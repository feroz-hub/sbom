"""Central account transitions, independent of routes and authentication.

Callers must authorize the operation and validate activation/password proofs.
This module never grants tenant authority. Legacy platform administration keeps
its existing last-administrator protections and uses the shared validator.
"""

from datetime import UTC, datetime

from sqlalchemy import select, update
from sqlalchemy.orm import Session

from ..core.identity_states import IdentityAuditEvent
from ..core.native_identity import AccountStatus
from ..models import AccountActionToken, IAMUser, NativeUserCredential
from . import audit_service

_TRANSITIONS = {
    AccountStatus.PENDING: {AccountStatus.ACTIVE},
    AccountStatus.PENDING_EMAIL_VERIFICATION: {AccountStatus.ACTIVE, AccountStatus.DISABLED},
    AccountStatus.ACTIVE: {AccountStatus.LOCKED, AccountStatus.DISABLED, AccountStatus.FORCE_PASSWORD_CHANGE},
    AccountStatus.LOCKED: {AccountStatus.ACTIVE, AccountStatus.DISABLED},
    AccountStatus.DISABLED: {AccountStatus.ACTIVE},
    AccountStatus.FORCE_PASSWORD_CHANGE: {AccountStatus.ACTIVE, AccountStatus.DISABLED},
}


class InvalidAccountTransition(ValueError):
    pass


def validate_transition(
    current: str,
    target: str,
    *,
    explicitly_authorized: bool = False,
    activation_completed: bool = False,
    password_updated: bool = False,
    legacy_approval: bool = False,
) -> None:
    try:
        before, after = AccountStatus(current), AccountStatus(target)
    except ValueError:
        raise InvalidAccountTransition("Unknown account status.") from None
    if after not in _TRANSITIONS[before]:
        raise InvalidAccountTransition(f"Transition from {before} to {after} is not allowed.")
    if before == AccountStatus.PENDING and not legacy_approval:
        raise InvalidAccountTransition("Legacy PENDING requires explicit administrator approval.")
    if after == AccountStatus.ACTIVE:
        if before == AccountStatus.PENDING_EMAIL_VERIFICATION and not activation_completed:
            raise InvalidAccountTransition("Account activation must complete before enabling the account.")
        if before == AccountStatus.FORCE_PASSWORD_CHANGE and not password_updated:
            raise InvalidAccountTransition("A successful password update is required.")
        if before in {AccountStatus.DISABLED, AccountStatus.LOCKED} and not explicitly_authorized:
            raise InvalidAccountTransition("Enabling or unlocking requires explicit authorization.")


def transition_account(
    db: Session,
    user_id: int,
    target: str,
    *,
    actor_user_id: int | None,
    explicitly_authorized: bool = False,
    activation_completed: bool = False,
    password_updated: bool = False,
) -> IAMUser:
    """Internal native lifecycle primitive; caller owns commit and permission checks.

    An audit failure rolls back this mutation even if the caller catches it.
    No HTTP endpoint exposes this foundation primitive in Phase 1.
    """
    with db.begin_nested():
        if target in {AccountStatus.DISABLED, AccountStatus.LOCKED, AccountStatus.FORCE_PASSWORD_CHANGE}:
            from .platform_service import update_user_status

            # Reuse the tenant->user->grant lock order and last-administrator
            # guards for every transition that removes effective access. The
            # temporary DISABLED value never leaves this transaction.
            mutation = update_user_status(db, user_id, "DISABLED")
            user, before = mutation.user, mutation.old_status
        else:
            user = db.scalar(
                select(IAMUser).where(IAMUser.id == user_id).with_for_update().execution_options(populate_existing=True)
            )
            if user is None:
                raise InvalidAccountTransition("Account does not exist.")
            before = user.status
        validate_transition(
            before,
            target,
            explicitly_authorized=explicitly_authorized,
            activation_completed=activation_completed,
            password_updated=password_updated,
        )
        if before == AccountStatus.PENDING_EMAIL_VERIFICATION and target == AccountStatus.ACTIVE:
            credential_exists = db.scalar(
                select(NativeUserCredential.id).where(NativeUserCredential.user_id == user_id)
            )
            if credential_exists is None or not user.email_verified or user.verification_required:
                raise InvalidAccountTransition(
                    "Activation requires a stored credential and completed email verification."
                )
        user.status = target
        now = datetime.now(UTC)
        user.updated_at = now
        credential = db.scalar(
            select(NativeUserCredential).where(NativeUserCredential.user_id == user_id).with_for_update()
        )
        if credential is not None:
            credential.security_version += 1
            credential.updated_at = now
            if target == AccountStatus.LOCKED:
                credential.locked_at = now
            elif before == AccountStatus.LOCKED:
                credential.locked_at = credential.locked_until = None
                credential.failed_login_count = 0
        if target in {AccountStatus.DISABLED, AccountStatus.LOCKED}:
            db.execute(
                update(AccountActionToken)
                .where(
                    AccountActionToken.user_id == user_id,
                    AccountActionToken.consumed_at.is_(None),
                    AccountActionToken.invalidated_at.is_(None),
                )
                .values(invalidated_at=now)
            )
        if target == AccountStatus.ACTIVE:
            action = {
                AccountStatus.PENDING_EMAIL_VERIFICATION: IdentityAuditEvent.ACCOUNT_ACTIVATED,
                AccountStatus.LOCKED: IdentityAuditEvent.USER_UNLOCKED,
                AccountStatus.FORCE_PASSWORD_CHANGE: IdentityAuditEvent.PASSWORD_CHANGED,
                AccountStatus.DISABLED: IdentityAuditEvent.USER_ENABLED,
            }[AccountStatus(before)]
        else:
            action = {
                AccountStatus.LOCKED: IdentityAuditEvent.USER_LOCKED,
                AccountStatus.DISABLED: IdentityAuditEvent.USER_DISABLED,
                AccountStatus.FORCE_PASSWORD_CHANGE: IdentityAuditEvent.FORCE_PASSWORD_CHANGE_SET,
            }[AccountStatus(target)]
        audit_service.write_authorization_audit(
            db,
            action=str(action),
            actor_user_id=actor_user_id,
            target_user_id=user_id,
            old_value={"status": before},
            new_value={"status": target},
        )
        db.flush()
    return user

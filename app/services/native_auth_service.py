"""Transactional native enrollment and credential authentication.

Lock order is user then credential. Security lockout intentionally does not use
administrative last-administrator guards. Callers own the outer transaction.
"""

import re
import secrets
from datetime import UTC, datetime, timedelta
from functools import lru_cache

from sqlalchemy import select
from sqlalchemy.orm import Session

from ..core.native_identity import AccountActionPurpose, canonicalize_email
from ..models import AccountActionToken, IAMUser, NativeUserCredential, UserIdentity
from ..settings import get_settings
from . import account_action_token_service as tokens
from . import audit_service, native_jwt_service, password_service
from .account_state_service import transition_account


def audit(db, action, user_id=None, **kwargs):
    audit_service.write_authorization_audit(db, action=action, target_user_id=user_id, **kwargs)


@lru_cache(maxsize=1)
def _dummy_hash() -> str:
    return password_service.hash_password(secrets.token_urlsafe(32))


def activate(db: Session, raw_token: str, password: str) -> IAMUser:
    if not get_settings().native_user_creation_enabled:
        raise tokens.InvalidAccountActionToken()
    if re.fullmatch(r"[A-Za-z0-9_-]{43}", raw_token) is None:
        raise tokens.InvalidAccountActionToken()
    password_service.validate_password(password)
    with db.begin_nested():
        row = db.scalar(
            select(AccountActionToken).where(AccountActionToken.token_hash == tokens.hash_action_token(raw_token))
        )
        if row is None:
            raise tokens.InvalidAccountActionToken()
        from .native_platform_bootstrap import finalize, lock_for_activation

        lock_for_activation(db, row.user_id)
        tokens.consume_action_token(db, raw_token, user_id=row.user_id, purpose=AccountActionPurpose.ACCOUNT_ACTIVATION)
        now = datetime.now(UTC)
        user = db.get(IAMUser, row.user_id)
        db.add(
            NativeUserCredential(
                user_id=user.id,
                password_hash=password_service.hash_password(password),
                password_changed_at=now,
                created_at=now,
                updated_at=now,
            )
        )
        user.email_verified = True
        user.email_verified_at = now
        user.verification_required = False
        db.flush()
        audit(db, "PASSWORD_SET", user.id)
        transition_account(db, user.id, "ACTIVE", actor_user_id=None, activation_completed=True)
        finalize(db, user)
        db.flush()
    return user


def verify_native_credential(db: Session, email: str, password: str, *, purpose="login"):
    """Locked credential proof only: no token, session or login timestamps.

    Callers commit failure accounting. Forced proofs retain FORCE_PASSWORD_CHANGE;
    only login may recover an expired LOCKED account with a valid credential.
    """
    if purpose not in {"login", "password_change", "forced_change"}:
        raise ValueError("Unsupported credential proof purpose")
    with db.begin_nested():
        identity = db.scalar(
            select(UserIdentity).where(
                UserIdentity.provider_type == "NATIVE", UserIdentity.provider_identifier == canonicalize_email(email)
            )
        )
        user = credential = None
        if identity:
            user = db.scalar(
                select(IAMUser)
                .where(IAMUser.id == identity.user_id)
                .with_for_update()
                .execution_options(populate_existing=True)
            )
            credential = db.scalar(
                select(NativeUserCredential)
                .where(NativeUserCredential.user_id == identity.user_id)
                .with_for_update()
                .execution_options(populate_existing=True)
            )
        now = datetime.now(UTC)
        forced = purpose == "forced_change"
        eligible = bool(
            user
            and credential
            and (purpose == "login" or identity.provider_identifier == canonicalize_email(user.email))
            and (
                (
                    user.status == "FORCE_PASSWORD_CHANGE"
                    and (not credential.locked_until or credential.locked_until <= now)
                )
                if forced
                else (
                    user.status == "ACTIVE"
                    or (
                        purpose == "login"
                        and user.status == "LOCKED"
                        and credential.locked_until
                        and credential.locked_until <= now
                    )
                )
            )
        )
        valid = password_service.verify_password(password, credential.password_hash if eligible else _dummy_hash())
        if not eligible or not valid:
            # Wrong proof never clears or extends an expired normal account lock.
            if eligible and (forced or user.status == "ACTIVE"):
                credential.failed_login_count += 1
                credential.updated_at = now
                if credential.failed_login_count >= get_settings().native_login_max_failed_attempts:
                    if not forced:
                        user.status = "LOCKED"
                        user.updated_at = now
                    credential.locked_at = now
                    credential.locked_until = now + timedelta(seconds=get_settings().native_login_lockout_seconds)
                    credential.security_version += 1
                    if not forced:
                        audit(db, "USER_LOCKED", user.id, new_value={"reason": "INVALID_CREDENTIALS"})
            audit(db, "LOGIN_FAILED", user.id if user else None, outcome="DENIED")
            db.flush()
            return None
        if purpose == "login":
            if user.status == "LOCKED":
                transition_account(db, user.id, "ACTIVE", actor_user_id=None, explicitly_authorized=True)
            credential.failed_login_count = 0
            credential.locked_at = credential.locked_until = None
            if password_service.needs_rehash(credential.password_hash):
                credential.password_hash = password_service.hash_password(password)
            credential.updated_at = now
        db.flush()
        return user, credential, identity


def login(db: Session, email: str, password: str) -> str | None:
    """Normal login owns successful-login activity and token issuance."""
    native_jwt_service.signing_key()  # Fail before credential mutations.
    with db.begin_nested():
        proved = verify_native_credential(db, email, password)
        if proved is None:
            return None
        user, credential, identity = proved
        now = datetime.now(UTC)
        user.last_login_at = now
        identity.last_authenticated_at = now
        audit(db, "LOGIN_SUCCESS", user.id)
        db.flush()
        return native_jwt_service.issue_token(user, credential)

"""Native password lifecycle. Account -> credential -> token lock order.

Callers commit failed credential attempts as well as successful mutations.
Reset is recovery for ACTIVE/LOCKED/FORCE_PASSWORD_CHANGE, never DISABLED.
"""

import re
import secrets
from datetime import UTC, datetime, timedelta

from fastapi import HTTPException
from sqlalchemy import func, select, update

from ..core.native_identity import canonicalize_email
from ..models import AccountActionToken, IAMUser, NativeUserCredential, UserIdentity
from ..settings import get_settings
from . import account_action_token_service as action_tokens
from . import audit_service, native_auth_service, password_service
from .account_state_service import transition_account

RESET_STATES = {"ACTIVE", "LOCKED", "FORCE_PASSWORD_CHANGE"}
GENERIC_RESET = "If an eligible account exists, password reset instructions will be sent."


def audit(db, action, uid, **kwargs):
    audit_service.write_authorization_audit(db, action=action, target_user_id=uid, **kwargs)


def lock_native(db, uid):
    user = db.scalar(
        select(IAMUser).where(IAMUser.id == uid).with_for_update().execution_options(populate_existing=True)
    )
    cred = db.scalar(
        select(NativeUserCredential)
        .where(NativeUserCredential.user_id == uid)
        .with_for_update()
        .execution_options(populate_existing=True)
    )
    identity = db.scalar(
        select(UserIdentity).where(UserIdentity.user_id == uid, UserIdentity.provider_type == "NATIVE")
    )
    if not user or not cred or not identity or identity.provider_identifier != canonicalize_email(user.email):
        raise HTTPException(401, "Native authentication required")
    return user, cred, identity


def forced_proof(db, email, password):
    """Credential proof grants no token/session; completion rechecks credentials.

    Forced accounts retain their forced state when throttled, so unlock cannot
    accidentally bypass password replacement. Temporary credential lock remains.
    """
    identity = db.scalar(
        select(UserIdentity).where(
            UserIdentity.provider_type == "NATIVE", UserIdentity.provider_identifier == canonicalize_email(email)
        )
    )
    if not identity:
        password_service.verify_password(password, native_auth_service._dummy_hash())
        return None
    user, cred, _ = lock_native(db, identity.user_id)
    now = datetime.now(UTC)
    eligible = user.status == "FORCE_PASSWORD_CHANGE" and (not cred.locked_until or cred.locked_until <= now)
    valid = password_service.verify_password(
        password, cred.password_hash if eligible else native_auth_service._dummy_hash()
    )
    if not eligible or not valid:
        if eligible:
            cred.failed_login_count += 1
            if cred.failed_login_count >= get_settings().native_login_max_failed_attempts:
                cred.locked_at = now
                cred.locked_until = now + timedelta(seconds=get_settings().native_login_lockout_seconds)
                cred.security_version += 1
        audit(db, "LOGIN_FAILED", user.id, outcome="DENIED")
        return None
    return user, cred


def replace_password(db, user, cred, password, *, reset=False):
    password_service.validate_password(password, cred.password_hash)
    with db.begin_nested():
        now = datetime.now(UTC)
        cred.password_hash = password_service.hash_password(password)
        cred.password_changed_at = cred.updated_at = now
        cred.failed_login_count = 0
        cred.locked_at = cred.locked_until = None
        before = user.status
        if before in {"LOCKED", "FORCE_PASSWORD_CHANGE"}:
            transition_account(
                db, user.id, "ACTIVE", actor_user_id=user.id, explicitly_authorized=True, password_updated=True
            )
            audit(
                db, "PASSWORD_ACCOUNT_ACTIVATED", user.id, old_value={"status": before}, new_value={"status": "ACTIVE"}
            )
        else:
            cred.security_version += 1
        db.execute(
            update(AccountActionToken)
            .where(
                AccountActionToken.user_id == user.id,
                AccountActionToken.consumed_at.is_(None),
                AccountActionToken.invalidated_at.is_(None),
            )
            .values(invalidated_at=now)
        )
        if reset or before != "FORCE_PASSWORD_CHANGE":
            audit(db, "PASSWORD_RESET" if reset else "PASSWORD_CHANGED", user.id)
        audit(db, "ALL_SESSIONS_REVOKED", user.id)
        db.flush()


def change_password(db, uid, version, current, new):
    user, cred, _ = lock_native(db, uid)
    if user.status != "ACTIVE" or cred.security_version != version:
        raise HTTPException(401, "Authentication required")
    # Reuse login's brute-force accounting, with the account lock still held.
    if native_auth_service.login(db, user.email, current) is None:
        return False
    replace_password(db, user, cred, new)
    return True


def complete_forced(db, email, current, new):
    proved = forced_proof(db, email, current)
    if not proved:
        return False
    replace_password(db, *proved, new)
    return True


def request_reset(db, email):
    # Same Argon2 cost for every account class. SMTP occurs after commit.
    password_service.verify_password("reset-request-dummy", native_auth_service._dummy_hash())
    identity = db.scalar(
        select(UserIdentity).where(
            UserIdentity.provider_type == "NATIVE", UserIdentity.provider_identifier == canonicalize_email(email)
        )
    )
    if not identity:
        return None
    try:
        user, cred, identity = lock_native(db, identity.user_id)
    except HTTPException:
        return None
    if user.status not in RESET_STATES or not user.email_verified or user.verification_required:
        return None
    with db.begin_nested():
        now = datetime.now(UTC)
        # Suppress mail floods without changing the public response.
        latest = db.scalar(
            select(AccountActionToken.created_at)
            .where(AccountActionToken.user_id == user.id, AccountActionToken.purpose == "PASSWORD_RESET")
            .order_by(AccountActionToken.created_at.desc())
            .limit(1)
        )
        if latest and latest + timedelta(seconds=60) > now:
            return None
        for duration, maximum in [
            (timedelta(hours=1), get_settings().email_verification_max_sends_per_hour),
            (timedelta(days=1), get_settings().email_verification_max_sends_per_day),
        ]:
            count = db.scalar(
                select(func.count(AccountActionToken.id)).where(
                    AccountActionToken.user_id == user.id,
                    AccountActionToken.purpose == "PASSWORD_RESET",
                    AccountActionToken.created_at >= now - duration,
                )
            )
            if count >= maximum:
                return None
        db.execute(
            update(AccountActionToken)
            .where(
                AccountActionToken.user_id == user.id,
                AccountActionToken.purpose == "PASSWORD_RESET",
                AccountActionToken.consumed_at.is_(None),
                AccountActionToken.invalidated_at.is_(None),
            )
            .values(invalidated_at=now)
        )
        raw = secrets.token_urlsafe(32)
        row = AccountActionToken(
            user_id=user.id,
            purpose="PASSWORD_RESET",
            token_hash=action_tokens.hash_action_token(raw),
            email_snapshot=identity.provider_identifier,
            created_at=now,
            expires_at=now + timedelta(seconds=get_settings().native_password_reset_ttl_seconds),
        )
        db.add(row)
        db.flush()
        audit(db, "PASSWORD_RESET_REQUESTED", user.id)
        audit(db, "PASSWORD_RESET_TOKEN_CREATED", user.id, new_value={"token_id": row.id})
        return user, action_tokens.IssuedAccountActionToken(row.id, raw, row.expires_at, row.email_snapshot)


def reset_password(db, raw, new):
    if re.fullmatch(r"[A-Za-z0-9_-]{43}", raw) is None:
        raise action_tokens.InvalidAccountActionToken()
    row = db.scalar(
        select(AccountActionToken).where(
            AccountActionToken.token_hash == action_tokens.hash_action_token(raw),
            AccountActionToken.purpose == "PASSWORD_RESET",
        )
    )
    if not row:
        raise action_tokens.InvalidAccountActionToken()
    with db.begin_nested():
        try:
            user, cred, identity = lock_native(db, row.user_id)
        except HTTPException:
            raise action_tokens.InvalidAccountActionToken() from None
        if user.status not in RESET_STATES or not user.email_verified or user.verification_required:
            raise action_tokens.InvalidAccountActionToken()
        now = datetime.now(UTC)
        consumed = db.scalar(
            update(AccountActionToken)
            .where(
                AccountActionToken.id == row.id,
                AccountActionToken.purpose == "PASSWORD_RESET",
                AccountActionToken.email_snapshot == identity.provider_identifier,
                AccountActionToken.expires_at > now,
                AccountActionToken.consumed_at.is_(None),
                AccountActionToken.invalidated_at.is_(None),
            )
            .values(consumed_at=now)
            .returning(AccountActionToken.id)
        )
        if consumed is None:
            raise action_tokens.InvalidAccountActionToken()
        replace_password(db, user, cred, new, reset=True)
        audit(db, "ACCOUNT_ACTION_TOKEN_CONSUMED", user.id, new_value={"token_id": row.id, "purpose": "PASSWORD_RESET"})
        return user

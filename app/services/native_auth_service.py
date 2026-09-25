"""Transactional native enrollment and credential authentication.

Lock order is user then credential. Security lockout intentionally does not use
administrative last-administrator guards. Callers own the outer transaction.
"""

import re
import secrets
from datetime import UTC, datetime, timedelta
from functools import lru_cache

from fastapi import HTTPException
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
    if len(password) < get_settings().native_password_min_length:
        raise HTTPException(422, "Password must contain at least 12 characters.")
    if len(password.encode("utf-8")) > password_service.MAX_PASSWORD_BYTES:
        raise HTTPException(422, "Password exceeds the maximum byte length.")
    with db.begin_nested():
        row = db.scalar(
            select(AccountActionToken).where(AccountActionToken.token_hash == tokens.hash_action_token(raw_token))
        )
        if row is None:
            raise tokens.InvalidAccountActionToken()
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
        db.flush()
    return user


def login(db: Session, email: str, password: str) -> str | None:
    """Return token or None. Failure counters/audit must be committed by caller."""
    native_jwt_service.signing_key()  # Fail before any credential mutation.
    with db.begin_nested():
        identity = db.scalar(
            select(UserIdentity).where(
                UserIdentity.provider_type == "NATIVE", UserIdentity.provider_identifier == canonicalize_email(email)
            )
        )
        user = None
        credential = None
        if identity:
            user = db.scalar(
                select(IAMUser)
                .where(IAMUser.id == identity.user_id)
                .with_for_update()
                .execution_options(populate_existing=True)
            )
            credential = db.scalar(
                select(NativeUserCredential)
                .where(NativeUserCredential.user_id == user.id)
                .with_for_update()
                .execution_options(populate_existing=True)
            )
        now = datetime.now(UTC)
        eligible = bool(
            user
            and credential
            and (
                user.status == "ACTIVE"
                or (user.status == "LOCKED" and credential.locked_until and credential.locked_until <= now)
            )
        )
        valid = password_service.verify_password(password, credential.password_hash if eligible else _dummy_hash())
        if not eligible:
            audit(db, "LOGIN_FAILED", user.id if user else None, outcome="DENIED")
            db.flush()
            return None
        if not valid:
            # An expired lock is cleared ONLY after a valid password. Wrong
            # attempts cannot extend or clear that lock or restore authority.
            if user.status == "ACTIVE":
                credential.failed_login_count += 1
                credential.updated_at = now
                if credential.failed_login_count >= get_settings().native_login_max_failed_attempts:
                    user.status = "LOCKED"
                    user.updated_at = now
                    credential.locked_at = now
                    credential.locked_until = now + timedelta(seconds=get_settings().native_login_lockout_seconds)
                    credential.security_version += 1
                    audit(db, "USER_LOCKED", user.id, new_value={"reason": "INVALID_CREDENTIALS"})
            audit(db, "LOGIN_FAILED", user.id, outcome="DENIED")
            db.flush()
            return None
        if user.status == "LOCKED":
            transition_account(db, user.id, "ACTIVE", actor_user_id=None, explicitly_authorized=True)
        credential.failed_login_count = 0
        credential.locked_at = credential.locked_until = None
        if password_service.needs_rehash(credential.password_hash):
            credential.password_hash = password_service.hash_password(password)
        credential.updated_at = now
        user.last_login_at = now
        identity.last_authenticated_at = now
        audit(db, "LOGIN_SUCCESS", user.id)
        db.flush()
        return native_jwt_service.issue_token(user, credential)

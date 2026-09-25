"""Internal, transactional account tokens. No public activation endpoint yet.

Identity records are global. Callers must authorize the selected user before
issuance/invalidation; possession is checked against BOTH user and purpose on
consumption. No token operation grants memberships, roles, or account access.
"""

import hashlib
import re
import secrets
from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta

from sqlalchemy import select, update
from sqlalchemy.orm import Session

from ..core.identity_states import IdentityAuditEvent
from ..core.native_identity import AccountActionPurpose, AccountStatus
from ..models import AccountActionToken, IAMUser, UserIdentity
from ..settings import get_settings
from . import audit_service


class InvalidAccountActionToken(ValueError):
    def __init__(self) -> None:
        super().__init__("Account action token is invalid or unavailable.")


@dataclass(frozen=True)
class IssuedAccountActionToken:
    id: int
    raw_token: str = field(repr=False)
    expires_at: datetime


def hash_action_token(raw_token: str) -> str:
    return hashlib.sha256(raw_token.encode("ascii")).hexdigest()


def _lock_native_user(db: Session, user_id: int) -> tuple[IAMUser, UserIdentity]:
    user = db.scalar(
        select(IAMUser).where(IAMUser.id == user_id).with_for_update().execution_options(populate_existing=True)
    )
    identity = db.scalar(
        select(UserIdentity).where(
            UserIdentity.user_id == user_id,
            UserIdentity.provider_type == "NATIVE",
        )
    )
    if user is None or identity is None or user.status != AccountStatus.PENDING_EMAIL_VERIFICATION:
        raise InvalidAccountActionToken()
    return user, identity


def issue_activation_token(db: Session, user_id: int, *, actor_user_id: int | None) -> IssuedAccountActionToken:
    if not get_settings().native_user_creation_enabled:
        raise ValueError("Native user creation is disabled.")
    with db.begin_nested():
        _user, identity = _lock_native_user(db, user_id)
        now = datetime.now(UTC)
        db.execute(
            update(AccountActionToken)
            .where(
                AccountActionToken.user_id == user_id,
                AccountActionToken.purpose == AccountActionPurpose.ACCOUNT_ACTIVATION,
                AccountActionToken.consumed_at.is_(None),
                AccountActionToken.invalidated_at.is_(None),
            )
            .values(invalidated_at=now)
        )
        raw = secrets.token_urlsafe(32)
        token = AccountActionToken(
            user_id=user_id,
            purpose=AccountActionPurpose.ACCOUNT_ACTIVATION,
            token_hash=hash_action_token(raw),
            email_snapshot=identity.provider_identifier,
            created_at=now,
            expires_at=now + timedelta(seconds=get_settings().native_account_activation_ttl_seconds),
        )
        db.add(token)
        db.flush()
        audit_service.write_authorization_audit(
            db,
            action=IdentityAuditEvent.ACCOUNT_ACTIVATION_TOKEN_CREATED,
            actor_user_id=actor_user_id,
            target_user_id=user_id,
            new_value={"token_id": token.id, "purpose": token.purpose},
        )
        db.flush()
        result = IssuedAccountActionToken(token.id, raw, token.expires_at)
    return result


def consume_action_token(
    db: Session,
    raw_token: str,
    *,
    user_id: int,
    purpose: AccountActionPurpose,
) -> AccountActionToken:
    # Future token types require their own lifecycle implementation. Reserving
    # enum values does not enable password reset or email change today.
    if purpose != AccountActionPurpose.ACCOUNT_ACTIVATION:
        raise InvalidAccountActionToken()
    if not isinstance(raw_token, str) or re.fullmatch(r"[A-Za-z0-9_-]{43}", raw_token) is None:
        raise InvalidAccountActionToken()
    if not get_settings().native_user_creation_enabled:
        raise InvalidAccountActionToken()
    with db.begin_nested():
        _user, identity = _lock_native_user(db, user_id)
        now = datetime.now(UTC)
        # A conditional UPDATE is atomic even when multiple workers consume
        # the same token. Every predicate remains in SQL, not a stale ORM check.
        token_id = db.scalar(
            update(AccountActionToken)
            .where(
                AccountActionToken.user_id == user_id,
                AccountActionToken.purpose == purpose,
                AccountActionToken.token_hash == hash_action_token(raw_token),
                AccountActionToken.email_snapshot == identity.provider_identifier,
                AccountActionToken.expires_at > now,
                AccountActionToken.consumed_at.is_(None),
                AccountActionToken.invalidated_at.is_(None),
            )
            .values(consumed_at=now)
            .returning(AccountActionToken.id)
        )
        if token_id is None:
            raise InvalidAccountActionToken()
        audit_service.write_authorization_audit(
            db,
            action=IdentityAuditEvent.ACCOUNT_ACTION_TOKEN_CONSUMED,
            target_user_id=user_id,
            new_value={"token_id": token_id, "purpose": str(purpose)},
        )
        db.flush()
        token = db.get(AccountActionToken, token_id, populate_existing=True)
    return token


def invalidate_action_tokens(db: Session, user_id: int, *, actor_user_id: int | None) -> None:
    with db.begin_nested():
        if db.scalar(select(IAMUser.id).where(IAMUser.id == user_id).with_for_update()) is None:
            raise InvalidAccountActionToken()
        db.execute(
            update(AccountActionToken)
            .where(
                AccountActionToken.user_id == user_id,
                AccountActionToken.consumed_at.is_(None),
                AccountActionToken.invalidated_at.is_(None),
            )
            .values(invalidated_at=datetime.now(UTC))
        )
        audit_service.write_authorization_audit(
            db,
            action=IdentityAuditEvent.ACCOUNT_ACTION_TOKEN_INVALIDATED,
            actor_user_id=actor_user_id,
            target_user_id=user_id,
        )
        db.flush()

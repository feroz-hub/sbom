from __future__ import annotations

from datetime import UTC, datetime, timedelta

import pytest
from app.models import (
    AuthorizationAuditLog,
    EmailVerificationToken,
    PlatformUserRole,
    TenantUser,
)
from app.services.email_sender import EmailDeliveryStatus
from app.services.email_verification_service import (
    VerificationRateLimited,
    VerificationTokenInvalid,
    cleanup_verification_tokens,
    confirm_verification_token,
    hash_verification_token,
    issue_verification_email,
)
from app.services.identity_service import provision_local_identity
from app.settings import reset_settings
from sqlalchemy import func, select

from tests.phase5_helpers import (
    FakeVerificationEmailSender,
    claims_for_user,
    seed_unverified_user,
)


def _issued(db, user):
    sender = FakeVerificationEmailSender()
    delivery = issue_verification_email(
        db,
        user.id,
        resend=False,
        sender=sender,
    )
    assert delivery.status == "SENT"
    return sender.raw_token


def test_raw_token_is_never_persisted_and_hash_is_unique():
    from app.db import SessionLocal

    with SessionLocal() as db:
        user = seed_unverified_user(db)
        raw = _issued(db, user)
        row = db.scalar(
            select(EmailVerificationToken).where(
                EmailVerificationToken.user_id == user.id
            )
        )
        assert row.token_hash == hash_verification_token(raw)
        assert raw not in repr(row.__dict__)
        assert len(row.token_hash) == 64


def test_valid_confirmation_is_atomic_and_single_use():
    from app.db import SessionLocal

    with SessionLocal() as db:
        user = seed_unverified_user(db)
        raw = _issued(db, user)
        verified = confirm_verification_token(db, raw)
        assert verified.email_verified is True
        assert verified.email_verified_at is not None
        assert verified.verification_required is False
        with pytest.raises(VerificationTokenInvalid):
            confirm_verification_token(db, raw)
        db.refresh(verified)
        assert db.scalar(
            select(func.count(AuthorizationAuditLog.id)).where(
                AuthorizationAuditLog.action == "IAM_EMAIL_VERIFICATION_SUCCEEDED",
                AuthorizationAuditLog.target_user_id == verified.id,
            )
        ) == 1


@pytest.mark.parametrize("mutation", ["modified", "malformed", "short"])
def test_invalid_or_modified_tokens_are_rejected_without_500(mutation):
    from app.db import SessionLocal

    with SessionLocal() as db:
        user = seed_unverified_user(db)
        raw = _issued(db, user)
        candidate = {
            "modified": raw[:-1] + ("A" if raw[-1] != "A" else "B"),
            "malformed": raw[:-1] + "!",
            "short": "abc",
        }[mutation]
        with pytest.raises(VerificationTokenInvalid):
            confirm_verification_token(db, candidate)
        db.refresh(user)
        assert user.email_verified is False


def test_expired_token_is_rejected_and_invalidated():
    from app.db import SessionLocal

    with SessionLocal() as db:
        user = seed_unverified_user(db)
        raw = _issued(db, user)
        token = db.scalar(
            select(EmailVerificationToken).where(
                EmailVerificationToken.user_id == user.id
            )
        )
        token.created_at = datetime.now(UTC) - timedelta(days=2)
        token.expires_at = datetime.now(UTC) - timedelta(seconds=1)
        db.commit()
        with pytest.raises(VerificationTokenInvalid):
            confirm_verification_token(db, raw)
        db.refresh(token)
        assert token.invalidated_at is not None
        assert token.invalidation_reason == "EXPIRED"


def test_resend_invalidates_old_token_and_only_new_token_succeeds():
    from app.db import SessionLocal

    with SessionLocal() as db:
        user = seed_unverified_user(db)
        first = _issued(db, user)
        first_row = db.scalar(
            select(EmailVerificationToken).where(
                EmailVerificationToken.user_id == user.id
            )
        )
        first_row.created_at = datetime.now(UTC) - timedelta(minutes=2)
        db.commit()
        sender = FakeVerificationEmailSender()
        issue_verification_email(
            db,
            user.id,
            resend=True,
            sender=sender,
        )
        second = sender.raw_token
        with pytest.raises(VerificationTokenInvalid):
            confirm_verification_token(db, first)
        assert confirm_verification_token(db, second).email_verified is True
        assert db.scalar(
            select(func.count(EmailVerificationToken.id)).where(
                EmailVerificationToken.user_id == user.id,
                EmailVerificationToken.consumed_at.is_(None),
                EmailVerificationToken.invalidated_at.is_(None),
            )
        ) == 0


@pytest.mark.parametrize(
    ("window", "env_name", "age"),
    [
        ("hour", "EMAIL_VERIFICATION_MAX_SENDS_PER_HOUR", timedelta(minutes=2)),
        ("day", "EMAIL_VERIFICATION_MAX_SENDS_PER_DAY", timedelta(hours=2)),
    ],
)
def test_hourly_and_daily_send_limits_are_enforced(
    monkeypatch,
    window,
    env_name,
    age,
):
    from app.db import SessionLocal

    monkeypatch.setenv(env_name, "1")
    if window == "day":
        monkeypatch.setenv("EMAIL_VERIFICATION_MAX_SENDS_PER_HOUR", "100")
    reset_settings()
    try:
        with SessionLocal() as db:
            user = seed_unverified_user(db)
            _issued(db, user)
            token = db.scalar(
                select(EmailVerificationToken).where(
                    EmailVerificationToken.user_id == user.id
                )
            )
            token.created_at = datetime.now(UTC) - age
            db.commit()
            with pytest.raises(VerificationRateLimited):
                issue_verification_email(
                    db,
                    user.id,
                    resend=True,
                    sender=FakeVerificationEmailSender(),
                )
    finally:
        monkeypatch.delenv(env_name, raising=False)
        if window == "day":
            monkeypatch.delenv("EMAIL_VERIFICATION_MAX_SENDS_PER_HOUR", raising=False)
        reset_settings()


def test_email_change_invalidates_old_token_and_preserves_authority():
    from app.db import SessionLocal

    with SessionLocal() as db:
        user = seed_unverified_user(db)
        raw = _issued(db, user)
        now = datetime.now(UTC)
        membership = TenantUser(
            tenant_id=1,
            user_id=user.id,
            role="VIEWER",
            status="ACTIVE",
            created_at=now,
            updated_at=now,
        )
        grant = PlatformUserRole(
            user_id=user.id,
            role="PLATFORM_ADMIN",
            status="ACTIVE",
            created_at=now,
            updated_at=now,
        )
        db.add_all([membership, grant])
        db.commit()
        membership_id, grant_id = membership.id, grant.id

        changed = claims_for_user(
            user,
            email=f"changed-{user.id}@example.test",
        )
        provision_local_identity(db, changed)
        db.commit()
        with pytest.raises(VerificationTokenInvalid):
            confirm_verification_token(db, raw)
        assert db.get(TenantUser, membership_id) is not None
        assert db.get(PlatformUserRole, grant_id) is not None
        new_sender = FakeVerificationEmailSender(EmailDeliveryStatus.SENT)
        issue_verification_email(
            db,
            user.id,
            resend=False,
            sender=new_sender,
        )
        newest = db.scalar(
            select(EmailVerificationToken)
            .where(EmailVerificationToken.user_id == user.id)
            .order_by(EmailVerificationToken.id.desc())
        )
        assert newest.email_snapshot == changed["email"]
        assert confirm_verification_token(db, new_sender.raw_token).email_verified is True


def test_email_snapshot_mismatch_is_rejected_and_audited():
    from app.db import SessionLocal

    with SessionLocal() as db:
        user = seed_unverified_user(db)
        raw = _issued(db, user)
        token = db.scalar(
            select(EmailVerificationToken).where(
                EmailVerificationToken.user_id == user.id
            )
        )
        token.email_snapshot = "different@example.test"
        db.commit()
        with pytest.raises(VerificationTokenInvalid):
            confirm_verification_token(db, raw)
        assert db.scalar(
            select(func.count(AuthorizationAuditLog.id)).where(
                AuthorizationAuditLog.action
                == "IAM_EMAIL_VERIFICATION_EMAIL_MISMATCH",
                AuthorizationAuditLog.target_user_id == user.id,
            )
        ) == 1


@pytest.mark.parametrize("status", ["DISABLED", "PENDING"])
def test_disabled_and_pending_users_cannot_confirm(status):
    from app.db import SessionLocal

    with SessionLocal() as db:
        user = seed_unverified_user(db)
        raw = _issued(db, user)
        user.status = status
        db.commit()
        with pytest.raises(VerificationTokenInvalid):
            confirm_verification_token(db, raw)
        db.refresh(user)
        assert user.status == status
        assert user.email_verified is False


def test_audit_and_persistence_contain_no_raw_token():
    from app.db import SessionLocal

    with SessionLocal() as db:
        user = seed_unverified_user(db)
        raw = _issued(db, user)
        serialized = " ".join(
            f"{row.action} {row.detail} {row.new_value}"
            for row in db.scalars(select(AuthorizationAuditLog)).all()
        )
        persisted = " ".join(
            str(value)
            for row in db.scalars(select(EmailVerificationToken)).all()
            for value in row.__dict__.values()
        )
        assert raw not in serialized
        assert raw not in persisted
        assert all(
            row.tenant_id is None
            for row in db.scalars(select(AuthorizationAuditLog)).all()
        )


def test_cleanup_deletes_only_old_inactive_security_records(monkeypatch):
    from app.db import SessionLocal

    monkeypatch.setenv("EMAIL_VERIFICATION_TOKEN_RETENTION_DAYS", "30")
    reset_settings()
    try:
        with SessionLocal() as db:
            user = seed_unverified_user(db)
            raw = _issued(db, user)
            confirm_verification_token(db, raw)
            token = db.scalar(
                select(EmailVerificationToken).where(
                    EmailVerificationToken.user_id == user.id
                )
            )
            token.created_at = datetime.now(UTC) - timedelta(days=45)
            db.commit()
            token_id = token.id
            assert cleanup_verification_tokens(db) == 1
            assert db.get(EmailVerificationToken, token_id) is None
    finally:
        monkeypatch.delenv("EMAIL_VERIFICATION_TOKEN_RETENTION_DAYS", raising=False)
        reset_settings()

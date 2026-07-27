from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor
from datetime import UTC, datetime, timedelta
from threading import Barrier

import pytest
from app.models import AuthorizationAuditLog, EmailVerificationToken, IAMUser
from app.services.email_verification_service import (
    VerificationRateLimited,
    VerificationTokenInvalid,
    confirm_verification_token,
    issue_verification_email,
)
from app.services.identity_service import provision_local_identity
from sqlalchemy import func, select

from tests.phase5_helpers import (
    FakeVerificationEmailSender,
    claims_for_user,
    seed_unverified_user,
)

pytestmark = pytest.mark.postgres


def test_concurrent_initial_delivery_creates_one_active_token_and_one_email():
    from app.db import SessionLocal

    with SessionLocal() as db:
        user_id = seed_unverified_user(db).id
    sender = FakeVerificationEmailSender()
    barrier = Barrier(2)

    def issue() -> str:
        with SessionLocal() as db:
            barrier.wait(timeout=10)
            return issue_verification_email(
                db,
                user_id,
                resend=False,
                sender=sender,
            ).status

    with ThreadPoolExecutor(max_workers=2) as executor:
        statuses = list(executor.map(lambda _index: issue(), range(2)))
    assert statuses == ["SENT", "SENT"]
    assert len(sender.messages) == 1
    with SessionLocal() as db:
        assert db.scalar(
            select(func.count(EmailVerificationToken.id)).where(
                EmailVerificationToken.user_id == user_id,
                EmailVerificationToken.consumed_at.is_(None),
                EmailVerificationToken.invalidated_at.is_(None),
            )
        ) == 1


def test_concurrent_resend_leaves_one_final_active_token():
    from app.db import SessionLocal

    sender = FakeVerificationEmailSender()
    with SessionLocal() as db:
        user = seed_unverified_user(db)
        user_id = user.id
        issue_verification_email(
            db,
            user_id,
            resend=False,
            sender=sender,
        )
        token = db.scalar(
            select(EmailVerificationToken).where(
                EmailVerificationToken.user_id == user_id
            )
        )
        token.created_at = datetime.now(UTC) - timedelta(minutes=2)
        db.commit()
    barrier = Barrier(2)

    def resend() -> str:
        with SessionLocal() as db:
            barrier.wait(timeout=10)
            try:
                return issue_verification_email(
                    db,
                    user_id,
                    resend=True,
                    sender=sender,
                ).status
            except VerificationRateLimited:
                return "RATE_LIMITED"

    with ThreadPoolExecutor(max_workers=2) as executor:
        results = list(executor.map(lambda _index: resend(), range(2)))
    assert sorted(results) == ["RATE_LIMITED", "SENT"]
    with SessionLocal() as db:
        assert db.scalar(
            select(func.count(EmailVerificationToken.id)).where(
                EmailVerificationToken.user_id == user_id,
                EmailVerificationToken.consumed_at.is_(None),
                EmailVerificationToken.invalidated_at.is_(None),
            )
        ) == 1


def test_concurrent_confirmation_has_exactly_one_success():
    from app.db import SessionLocal

    sender = FakeVerificationEmailSender()
    with SessionLocal() as db:
        user = seed_unverified_user(db)
        user_id = user.id
        issue_verification_email(
            db,
            user_id,
            resend=False,
            sender=sender,
        )
        raw = sender.raw_token
    barrier = Barrier(2)

    def confirm() -> str:
        with SessionLocal() as db:
            barrier.wait(timeout=10)
            try:
                confirm_verification_token(db, raw)
                return "VERIFIED"
            except VerificationTokenInvalid:
                return "REJECTED"

    with ThreadPoolExecutor(max_workers=2) as executor:
        results = list(executor.map(lambda _index: confirm(), range(2)))
    assert sorted(results) == ["REJECTED", "VERIFIED"]
    with SessionLocal() as db:
        user = db.get(IAMUser, user_id)
        assert user.email_verified is True
        token = db.scalar(
            select(EmailVerificationToken).where(
                EmailVerificationToken.user_id == user_id
            )
        )
        assert token.consumed_at is not None
        assert db.scalar(
            select(func.count(AuthorizationAuditLog.id)).where(
                AuthorizationAuditLog.action == "IAM_EMAIL_VERIFICATION_SUCCEEDED",
                AuthorizationAuditLog.target_user_id == user_id,
            )
        ) == 1


def test_confirmation_racing_email_change_cannot_verify_new_email():
    from app.db import SessionLocal

    sender = FakeVerificationEmailSender()
    with SessionLocal() as db:
        user = seed_unverified_user(db)
        user_id = user.id
        issue_verification_email(
            db,
            user_id,
            resend=False,
            sender=sender,
        )
        raw = sender.raw_token
        original_claims = claims_for_user(user)
    barrier = Barrier(2)

    def confirm() -> str:
        with SessionLocal() as db:
            barrier.wait(timeout=10)
            try:
                confirm_verification_token(db, raw)
                return "CONFIRMED_OLD_EMAIL"
            except VerificationTokenInvalid:
                return "REJECTED"

    def change_email() -> str:
        with SessionLocal() as db:
            barrier.wait(timeout=10)
            claims = dict(original_claims)
            claims["email"] = f"new-{user_id}@example.test"
            provision_local_identity(db, claims)
            db.commit()
            return "EMAIL_CHANGED"

    with ThreadPoolExecutor(max_workers=2) as executor:
        confirm_future = executor.submit(confirm)
        change_future = executor.submit(change_email)
        outcomes = {confirm_future.result(), change_future.result()}
    assert "EMAIL_CHANGED" in outcomes
    with SessionLocal() as db:
        user = db.get(IAMUser, user_id)
        assert user.email == f"new-{user_id}@example.test"
        assert user.email_verified is False
        assert user.verification_required is True

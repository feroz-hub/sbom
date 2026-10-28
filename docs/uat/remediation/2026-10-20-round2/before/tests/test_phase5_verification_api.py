from __future__ import annotations

from datetime import UTC, datetime, timedelta

import pytest
from app.core.security import get_current_user
from app.models import EmailVerificationToken, IAMUser, PlatformUserRole, Tenant, TenantUser
from app.services.auth_context_service import resolve_authorization_state
from app.services.email_sender import EmailDeliveryStatus
from app.services.email_verification_service import (
    confirm_verification_token,
    issue_verification_email,
)
from sqlalchemy import select

from tests.phase5_helpers import (
    FakeVerificationEmailSender,
    claims_for_user,
    seed_unverified_user,
)


def test_initial_context_dispatch_status_confirm_and_no_tenant_transition(
    client,
    app,
    monkeypatch,
):
    from app.db import SessionLocal

    sender = FakeVerificationEmailSender()
    monkeypatch.setattr(
        "app.services.email_verification_service.get_verification_email_sender",
        lambda: sender,
    )
    claims = {
        "iss": "https://hcl-cs.example.test",
        "sub": "phase5-api-initial",
        "email": "phase5-api-initial@example.test",
        "name": "Initial API User",
        "preferred_username": "phase5-api-initial@example.test",
        "employee_id": "P5-INITIAL",
    }
    app.dependency_overrides[get_current_user] = lambda: claims
    try:
        context = client.get("/api/auth/context")
        assert context.status_code == 200
        assert context.json()["status"] == "VERIFICATION_REQUIRED"
        assert context.json()["verification"]["delivery_status"] == "SENT"
        assert len(sender.messages) == 1

        status = client.get("/api/auth/verification/status")
        assert status.status_code == 200
        assert status.json()["delivery_status"] == "SENT"
        assert len(sender.messages) == 1

        confirmed = client.post(
            "/api/auth/verification/confirm",
            json={"token": sender.raw_token},
        )
        assert confirmed.status_code == 200
        assert confirmed.json()["next_action"] == "REFRESH_AUTH_CONTEXT"

        after = client.get("/api/auth/context")
        assert after.status_code == 200
        assert after.json()["status"] == "NO_TENANT"
        assert after.json()["verification"]["delivery_status"] is None
        with SessionLocal() as db:
            user = db.scalar(
                select(IAMUser).where(
                    IAMUser.external_issuer == claims["iss"],
                    IAMUser.external_subject == claims["sub"],
                )
            )
            assert user.email_verified is True
            assert db.scalar(
                select(TenantUser).where(TenantUser.user_id == user.id)
            ) is None
            assert db.scalar(
                select(PlatformUserRole).where(PlatformUserRole.user_id == user.id)
            ) is None
    finally:
        app.dependency_overrides.pop(get_current_user, None)


def test_resend_invalidates_old_link_and_enforces_cooldown(
    client,
    app,
    monkeypatch,
):
    from app.db import SessionLocal

    sender = FakeVerificationEmailSender()
    monkeypatch.setattr(
        "app.services.email_verification_service.get_verification_email_sender",
        lambda: sender,
    )
    with SessionLocal() as db:
        user = seed_unverified_user(db)
        claims = claims_for_user(user)
    app.dependency_overrides[get_current_user] = lambda: claims
    try:
        assert client.get("/api/auth/verification/status").status_code == 200
        old = sender.raw_token
        with SessionLocal() as db:
            token = db.scalar(
                select(EmailVerificationToken).where(
                    EmailVerificationToken.user_id == user.id
                )
            )
            token.created_at = datetime.now(UTC) - timedelta(minutes=2)
            db.commit()
        resent = client.post("/api/auth/verification/resend")
        assert resent.status_code == 200
        assert resent.json()["delivery_status"] == "SENT"
        new = sender.raw_token
        assert new != old
        limited = client.post("/api/auth/verification/resend")
        assert limited.status_code == 429
        assert limited.json()["detail"]["code"] == "IAM_VERIFICATION_RESEND_RATE_LIMITED"
        assert int(limited.headers["Retry-After"]) >= 1
        assert client.post(
            "/api/auth/verification/confirm",
            json={"token": old},
        ).status_code == 400
        assert client.post(
            "/api/auth/verification/confirm",
            json={"token": new},
        ).status_code == 200
    finally:
        app.dependency_overrides.pop(get_current_user, None)


def test_delivery_failure_is_safe_and_does_not_verify(client, app, monkeypatch):
    from app.db import SessionLocal

    sender = FakeVerificationEmailSender(
        EmailDeliveryStatus.FAILED,
        "SMTP_UNAVAILABLE",
    )
    monkeypatch.setattr(
        "app.services.email_verification_service.get_verification_email_sender",
        lambda: sender,
    )
    with SessionLocal() as db:
        user = seed_unverified_user(db)
        claims = claims_for_user(user)
    app.dependency_overrides[get_current_user] = lambda: claims
    try:
        response = client.get("/api/auth/verification/status")
        assert response.status_code == 200
        assert response.json()["delivery_status"] == "FAILED"
        with SessionLocal() as db:
            stored = db.get(IAMUser, user.id)
            assert stored.email_verified is False
            token = db.scalar(
                select(EmailVerificationToken).where(
                    EmailVerificationToken.user_id == user.id
                )
            )
            assert token.invalidated_at is not None
            assert token.delivery_error_code == "SMTP_UNAVAILABLE"
    finally:
        app.dependency_overrides.pop(get_current_user, None)


@pytest.mark.parametrize(
    ("status", "expected_code"),
    [
        ("DISABLED", "IAM_ACCOUNT_DISABLED"),
        ("PENDING", "IAM_ACCOUNT_PENDING_APPROVAL"),
    ],
)
def test_disabled_and_pending_users_cannot_resend(
    client,
    app,
    status,
    expected_code,
):
    from app.db import SessionLocal

    with SessionLocal() as db:
        user = seed_unverified_user(db, status=status)
        claims = claims_for_user(user)
    app.dependency_overrides[get_current_user] = lambda: claims
    try:
        response = client.post("/api/auth/verification/resend")
        assert response.status_code == 403
        assert response.json()["detail"]["code"] == expected_code
    finally:
        app.dependency_overrides.pop(get_current_user, None)


def test_already_verified_resend_is_safe_noop(client, app):
    from app.db import SessionLocal

    with SessionLocal() as db:
        user = seed_unverified_user(db)
        user.email_verified = True
        user.email_verified_at = datetime.now(UTC)
        user.verification_required = False
        db.commit()
        claims = claims_for_user(user)
    app.dependency_overrides[get_current_user] = lambda: claims
    try:
        response = client.post("/api/auth/verification/resend")
        assert response.status_code == 200
        assert response.json()["status"] == "VERIFIED"
        with SessionLocal() as db:
            assert db.scalar(
                select(EmailVerificationToken).where(
                    EmailVerificationToken.user_id == user.id
                )
            ) is None
    finally:
        app.dependency_overrides.pop(get_current_user, None)


def test_confirmation_is_post_only_and_failures_are_generic(client):
    assert client.get("/api/auth/verification/confirm").status_code == 405
    unknown = client.post(
        "/api/auth/verification/confirm",
        json={"token": "A" * 43},
    )
    assert unknown.status_code == 400
    assert unknown.json()["detail"] == {
        "code": "IAM_VERIFICATION_TOKEN_INVALID",
        "message": (
            "This verification link is invalid or has expired. "
            "Request a new verification email to continue."
        ),
    }


def test_after_verification_existing_authority_drives_state(client, app, monkeypatch):
    from app.db import SessionLocal

    sender = FakeVerificationEmailSender()
    monkeypatch.setattr(
        "app.services.email_verification_service.get_verification_email_sender",
        lambda: sender,
    )
    with SessionLocal() as db:
        user = seed_unverified_user(db)
        now = datetime.now(UTC)
        tenant = Tenant(
            name="Phase Five Tenant",
            slug=f"phase5-{user.id}",
            external_iam_tenant_id=f"phase5-external-{user.id}",
            status="ACTIVE",
            created_at=now,
            updated_at=now,
        )
        db.add(tenant)
        db.flush()
        db.add(
            TenantUser(
                tenant_id=tenant.id,
                user_id=user.id,
                role="VIEWER",
                status="ACTIVE",
                created_at=now,
                updated_at=now,
            )
        )
        db.commit()
        claims = claims_for_user(user)
    app.dependency_overrides[get_current_user] = lambda: claims
    try:
        assert client.get("/api/auth/context").json()["status"] == "VERIFICATION_REQUIRED"
        assert client.post(
            "/api/auth/verification/confirm",
            json={"token": sender.raw_token},
        ).status_code == 200
        context = client.get("/api/auth/context").json()
        assert context["status"] == "READY"
        assert context["next_action"] == "OPEN_DASHBOARD"
        assert context["tenant_context"]["active_tenant"]["current_role"] == "VIEWER"
    finally:
        app.dependency_overrides.pop(get_current_user, None)


def test_after_verification_multiple_tenants_require_selection():
    from app.db import SessionLocal

    sender = FakeVerificationEmailSender()
    with SessionLocal() as db:
        user = seed_unverified_user(db)
        now = datetime.now(UTC)
        for index in range(2):
            tenant = Tenant(
                name=f"Multiple {index}",
                slug=f"multiple-{user.id}-{index}",
                external_iam_tenant_id=f"multiple-external-{user.id}-{index}",
                status="ACTIVE",
                created_at=now,
                updated_at=now,
            )
            db.add(tenant)
            db.flush()
            db.add(
                TenantUser(
                    tenant_id=tenant.id,
                    user_id=user.id,
                    role="VIEWER",
                    status="ACTIVE",
                    created_at=now,
                    updated_at=now,
                )
            )
        db.commit()
        issue_verification_email(
            db,
            user.id,
            resend=False,
            sender=sender,
        )
        verified = confirm_verification_token(db, sender.raw_token)
        state = resolve_authorization_state(db, verified)
        assert str(state.status) == "TENANT_SELECTION_REQUIRED"
        assert str(state.next_action) == "SELECT_TENANT"


def test_after_verification_platform_admin_without_tenant_opens_platform():
    from app.db import SessionLocal

    sender = FakeVerificationEmailSender()
    with SessionLocal() as db:
        user = seed_unverified_user(db)
        now = datetime.now(UTC)
        db.add(
            PlatformUserRole(
                user_id=user.id,
                role="PLATFORM_ADMIN",
                status="ACTIVE",
                created_at=now,
                updated_at=now,
            )
        )
        db.commit()
        issue_verification_email(
            db,
            user.id,
            resend=False,
            sender=sender,
        )
        verified = confirm_verification_token(db, sender.raw_token)
        state = resolve_authorization_state(db, verified)
        assert str(state.status) == "READY"
        assert str(state.next_action) == "OPEN_PLATFORM_ADMIN"
        assert state.active_tenant is None

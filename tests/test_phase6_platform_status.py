from __future__ import annotations

from datetime import UTC, datetime, timedelta

import pytest
from app.core.security import _resolve_context
from app.db import SessionLocal
from app.models import (
    AuthorizationAuditLog,
    EmailVerificationToken,
    PlatformUserRole,
    TenantUser,
)
from fastapi import HTTPException
from sqlalchemy import func, select

from tests.phase6_helpers import (
    identity_claims,
    seed_dev_platform_admin,
    seed_membership,
    seed_platform_grant,
    seed_user,
)


def _seed_active_token(db, user) -> EmailVerificationToken:
    now = datetime.now(UTC)
    token = EmailVerificationToken(
        user_id=user.id,
        token_hash=("a" * 63) + str(user.id % 10),
        email_snapshot=user.email,
        expires_at=now + timedelta(hours=1),
        created_at=now,
        delivery_status="SENT",
    )
    db.add(token)
    db.flush()
    return token


def test_pending_activation_preserves_verification_and_creates_no_authority(client):
    with SessionLocal() as db:
        seed_dev_platform_admin(db)
        target = seed_user(db, status="PENDING", verified=False)
        target_id = target.id
        db.commit()

    response = client.patch(
        f"/api/platform/users/{target_id}/status",
        json={"status": "ACTIVE", "reason": "Legacy approval completed"},
    )
    assert response.status_code == 200, response.text
    body = response.json()
    assert body["old_status"] == "PENDING"
    assert body["status"] == "ACTIVE"
    assert body["email_verified"] is False
    assert body["verification_required"] is True

    with SessionLocal() as db:
        assert db.get(PlatformUserRole, target_id) is None
        assert db.scalar(
            select(func.count(TenantUser.id)).where(
                TenantUser.user_id == target_id
            )
        ) == 0
        actions = set(
            db.scalars(
                select(AuthorizationAuditLog.action).where(
                    AuthorizationAuditLog.target_user_id == target_id
                )
            )
        )
        assert {
            "PLATFORM_USER_ACTIVATED",
            "PLATFORM_USER_STATUS_CHANGED",
        } <= actions


def test_disable_immediately_blocks_access_and_invalidates_token(
    client, monkeypatch
):
    from app.settings import reset_settings

    with SessionLocal() as db:
        seed_dev_platform_admin(db)
        target = seed_user(db)
        membership = seed_membership(db, target)
        grant = seed_platform_grant(db, target)
        token = _seed_active_token(db, target)
        target_id = target.id
        membership_id = membership.id
        grant_id = grant.id
        token_id = token.id
        claims = identity_claims(target)
        db.commit()

    response = client.patch(
        f"/api/platform/users/{target_id}/status",
        json={"status": "DISABLED", "reason": "Security response"},
    )
    assert response.status_code == 200
    assert response.json()["status"] == "DISABLED"

    monkeypatch.setenv("AUTH_ENABLED", "true")
    monkeypatch.setenv("DEV_DEFAULT_TENANT", "false")
    reset_settings()
    with SessionLocal() as db:
        with pytest.raises(HTTPException) as exc_info:
            _resolve_context(db, claims, None)
        assert exc_info.value.detail["code"] == "IAM_ACCOUNT_DISABLED"
        assert db.get(TenantUser, membership_id).status == "ACTIVE"
        assert db.get(PlatformUserRole, grant_id).status == "ACTIVE"
        token = db.get(EmailVerificationToken, token_id)
        assert token.invalidated_at is not None
        assert token.invalidation_reason == "USER_DISABLED"


def test_reactivation_restores_only_local_status(client):
    with SessionLocal() as db:
        seed_dev_platform_admin(db)
        target = seed_user(db, status="DISABLED", verified=False)
        membership = seed_membership(
            db, target, role="SECURITY_ANALYST", status="DISABLED"
        )
        grant = seed_platform_grant(db, target, status="DISABLED")
        target_id = target.id
        membership_id = membership.id
        grant_id = grant.id
        db.commit()

    response = client.patch(
        f"/api/platform/users/{target_id}",
        json={"status": "ACTIVE"},
    )
    assert response.status_code == 200
    assert response.json()["verification_required"] is True
    with SessionLocal() as db:
        assert db.get(PlatformUserRole, grant_id).status == "DISABLED"
        assert db.get(TenantUser, membership_id).status == "DISABLED"
        from app.models import IAMUser

        user = db.get(IAMUser, target_id)
        assert user.status == "ACTIVE"
        assert user.email_verified is False


def test_final_effective_administrator_cannot_be_disabled(client):
    with SessionLocal() as db:
        dev, _ = seed_dev_platform_admin(db)
        dev_id = dev.id

    response = client.patch(
        f"/api/platform/users/{dev_id}/status",
        json={"status": "DISABLED"},
    )
    assert response.status_code == 409
    assert (
        response.json()["detail"]["code"]
        == "IAM_LAST_PLATFORM_ADMIN_PROTECTED"
    )
    with SessionLocal() as db:
        from app.models import IAMUser

        assert db.get(IAMUser, dev_id).status == "ACTIVE"
        audit = db.scalar(
            select(AuthorizationAuditLog).where(
                AuthorizationAuditLog.action
                == "PLATFORM_ADMIN_LAST_ADMIN_PROTECTED"
            )
        )
        assert audit is not None
        assert audit.tenant_id is None


def test_invalid_status_transition_is_rejected(client):
    with SessionLocal() as db:
        seed_dev_platform_admin(db)
        pending = seed_user(db, status="PENDING", verified=False)
        pending_id = pending.id
        db.commit()

    response = client.patch(
        f"/api/platform/users/{pending_id}/status",
        json={"status": "DISABLED"},
    )
    assert response.status_code == 409
    assert (
        response.json()["detail"]["code"]
        == "IAM_USER_STATUS_TRANSITION_NOT_ALLOWED"
    )
    assert client.patch(
        f"/api/platform/users/{pending_id}/status",
        json={"status": "PENDING"},
    ).status_code == 422


def test_noop_status_update_is_idempotent_and_not_audited(client):
    with SessionLocal() as db:
        seed_dev_platform_admin(db)
        target = seed_user(db)
        target_id = target.id
        db.commit()

    response = client.patch(
        f"/api/platform/users/{target_id}/status",
        json={"status": "ACTIVE"},
    )
    assert response.status_code == 200
    assert response.json()["changed"] is False
    with SessionLocal() as db:
        assert db.scalar(
            select(func.count(AuthorizationAuditLog.id)).where(
                AuthorizationAuditLog.target_user_id == target_id,
                AuthorizationAuditLog.action
                == "PLATFORM_USER_STATUS_CHANGED",
            )
        ) == 0


def test_platform_status_api_cannot_mark_email_verified(client):
    with SessionLocal() as db:
        seed_dev_platform_admin(db)
        target = seed_user(db, status="PENDING", verified=False)
        target_id = target.id
        db.commit()

    response = client.patch(
        f"/api/platform/users/{target_id}/status",
        json={"status": "ACTIVE", "email_verified": True},
    )
    assert response.status_code == 422
    with SessionLocal() as db:
        from app.models import IAMUser

        user = db.get(IAMUser, target_id)
        assert user.email_verified is False
        assert user.verification_required is True

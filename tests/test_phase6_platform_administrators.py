from __future__ import annotations

import pytest
from app.core.security import _resolve_context
from app.db import SessionLocal
from app.models import AuthorizationAuditLog, IAMUser, PlatformUserRole, TenantUser
from app.services import platform_service
from fastapi import HTTPException
from sqlalchemy import func, select

from tests.phase6_helpers import (
    identity_claims,
    seed_dev_platform_admin,
    seed_membership,
    seed_platform_grant,
    seed_user,
)


def test_grant_is_eligible_duplicate_rejected_audited_and_immediate(client, monkeypatch):
    from app.settings import reset_settings

    with SessionLocal() as db:
        admin, _ = seed_dev_platform_admin(db)
        admin_id = admin.id
        target = seed_user(db)
        target_id = target.id
        target_claims = identity_claims(target)
        db.commit()

    granted = client.post(
        "/api/platform/administrators",
        json={"user_id": target_id},
        headers={"X-Correlation-ID": "grant-phase6"},
    )
    assert granted.status_code == 201, granted.text
    assert granted.json()["action"] == "CREATED"
    assert granted.json()["is_effective"] is True

    repeated = client.post(
        "/api/platform/administrators",
        json={"user_id": target_id},
    )
    assert repeated.status_code == 409
    assert (
        repeated.json()["detail"]["code"]
        == "IAM_PLATFORM_ADMIN_ALREADY_GRANTED"
    )

    monkeypatch.setenv("AUTH_ENABLED", "true")
    monkeypatch.setenv("DEV_DEFAULT_TENANT", "false")
    reset_settings()
    with SessionLocal() as db:
        context = _resolve_context(
            db, target_claims, None, allow_platform_context=True
        )
        assert context.is_platform_admin is True
        assert context.has_permission("platform:administrator:revoke")
        assert db.scalar(
            select(func.count(PlatformUserRole.id)).where(
                PlatformUserRole.user_id == target_id
            )
        ) == 1
        audits = list(
            db.scalars(
                select(AuthorizationAuditLog).where(
                    AuthorizationAuditLog.action == "PLATFORM_ADMIN_GRANTED",
                    AuthorizationAuditLog.target_user_id == target_id,
                )
            )
        )
        assert len(audits) == 1
        assert audits[0].actor_user_id == admin_id
        assert audits[0].tenant_id is None
        assert audits[0].correlation_id == "grant-phase6"
        assert db.scalar(
            select(func.count(TenantUser.id)).where(TenantUser.user_id == target_id)
        ) == 0


def test_inactive_grant_is_reactivated_without_duplicate(client):
    with SessionLocal() as db:
        admin, _ = seed_dev_platform_admin(db)
        target = seed_user(db)
        grant = seed_platform_grant(
            db, target, status="DISABLED", creator_id=admin.id
        )
        original_created_at = grant.created_at
        grant_id = grant.id
        target_id = target.id
        db.commit()

    response = client.post(
        "/api/platform/administrators",
        json={"user_id": target_id},
    )
    assert response.status_code == 201
    assert response.json()["action"] == "REACTIVATED"
    assert response.json()["grant_id"] == grant_id
    with SessionLocal() as db:
        grant = db.get(PlatformUserRole, grant_id)
        assert grant.status == "ACTIVE"
        assert grant.created_at == original_created_at
        assert db.scalar(
            select(func.count(PlatformUserRole.id)).where(
                PlatformUserRole.user_id == target_id
            )
        ) == 1
        assert db.scalar(
            select(AuthorizationAuditLog).where(
                AuthorizationAuditLog.action
                == "PLATFORM_ADMIN_GRANT_REACTIVATED"
            )
        )


@pytest.mark.parametrize(
    ("status", "verified", "code"),
    [
        ("DISABLED", True, "IAM_ACCOUNT_DISABLED"),
        ("PENDING", True, "IAM_ACCOUNT_PENDING_APPROVAL"),
        ("ACTIVE", False, "IAM_EMAIL_VERIFICATION_REQUIRED"),
    ],
)
def test_ineligible_users_cannot_receive_platform_grant(
    client, status, verified, code
):
    with SessionLocal() as db:
        seed_dev_platform_admin(db)
        target = seed_user(db, status=status, verified=verified)
        target_id = target.id
        db.commit()

    response = client.post(
        "/api/platform/administrators",
        json={"user_id": target_id},
    )
    assert response.status_code == 409
    assert response.json()["detail"]["code"] == code
    with SessionLocal() as db:
        assert db.scalar(
            select(PlatformUserRole).where(
                PlatformUserRole.user_id == target_id
            )
        ) is None
        audit = db.scalar(
            select(AuthorizationAuditLog).where(
                AuthorizationAuditLog.action == "PLATFORM_ADMIN_GRANT_REJECTED"
            )
        )
        assert audit is not None
        assert audit.tenant_id is None


def test_unknown_user_and_invalid_selector_are_rejected(client):
    with SessionLocal() as db:
        seed_dev_platform_admin(db)

    unknown = client.post(
        "/api/platform/administrators",
        json={"user_id": 999999},
    )
    assert unknown.status_code == 404
    assert unknown.json()["detail"]["code"] == "IAM_USER_NOT_FOUND"
    assert client.post("/api/platform/administrators", json={}).status_code == 422
    assert client.post(
        "/api/platform/administrators",
        json={"user_id": 1, "external_user_id": "also-supplied"},
    ).status_code == 422


def test_administrator_listing_exposes_effectiveness_without_external_identity(client):
    with SessionLocal() as db:
        admin, _ = seed_dev_platform_admin(db)
        disabled = seed_user(db, status="DISABLED")
        unverified = seed_user(db, verified=False)
        inactive = seed_user(db)
        seed_platform_grant(db, disabled, creator_id=admin.id)
        seed_platform_grant(db, unverified, creator_id=admin.id)
        seed_platform_grant(
            db, inactive, status="DISABLED", creator_id=admin.id
        )
        db.commit()

    response = client.get("/api/platform/administrators?page_size=10")
    assert response.status_code == 200
    body = response.json()
    assert body["total"] == 4
    states = {item["user_id"]: item["is_effective"] for item in body["items"]}
    assert sum(states.values()) == 1
    assert "external_subject" not in response.text
    assert "external_iam_user_id" not in response.text


def test_revoke_is_soft_immediate_and_preserves_membership(client, monkeypatch):
    from app.settings import reset_settings

    with SessionLocal() as db:
        seed_dev_platform_admin(db)
        target = seed_user(db)
        membership = seed_membership(db, target, role="VIEWER")
        grant = seed_platform_grant(db, target)
        target_id = target.id
        grant_id = grant.id
        membership_id = membership.id
        claims = identity_claims(target)
        db.commit()

    assert client.delete(
        f"/api/platform/administrators/{grant_id}"
    ).status_code == 204

    monkeypatch.setenv("AUTH_ENABLED", "true")
    monkeypatch.setenv("DEV_DEFAULT_TENANT", "false")
    reset_settings()
    with SessionLocal() as db:
        grant = db.get(PlatformUserRole, grant_id)
        assert grant.status == "DISABLED"
        assert db.get(TenantUser, membership_id).role == "VIEWER"
        context = _resolve_context(db, claims, None)
        assert context.is_platform_admin is False
        assert not context.has_permission("platform:user:read")
        audit = db.scalar(
            select(AuthorizationAuditLog).where(
                AuthorizationAuditLog.action == "PLATFORM_ADMIN_REVOKED",
                AuthorizationAuditLog.target_user_id == target_id,
            )
        )
        assert audit is not None
        assert audit.tenant_id is None


def test_self_revocation_allowed_with_backup_and_final_admin_protected(client):
    with SessionLocal() as db:
        dev, dev_grant = seed_dev_platform_admin(db)
        backup = seed_user(db)
        backup_grant = seed_platform_grant(db, backup, creator_id=dev.id)
        dev_grant_id = dev_grant.id
        backup_grant_id = backup_grant.id
        db.commit()

    assert client.delete(
        f"/api/platform/administrators/{dev_grant_id}"
    ).status_code == 204

    # Test requests still resolve as the development identity, which now has
    # no platform grant. Exercise the service directly as the remaining admin.
    with SessionLocal() as db:
        with pytest.raises(HTTPException) as exc_info:
            from app.services import platform_service

            platform_service.revoke_platform_administrator(db, backup_grant_id)
        assert exc_info.value.status_code == 409
        assert (
            exc_info.value.detail["code"]
            == "IAM_LAST_PLATFORM_ADMIN_PROTECTED"
        )
        db.rollback()
        assert db.get(PlatformUserRole, backup_grant_id).status == "ACTIVE"


@pytest.mark.parametrize(
    ("backup_status", "backup_verified"),
    [
        ("DISABLED", True),
        ("PENDING", True),
        ("ACTIVE", False),
    ],
)
def test_ineffective_backup_does_not_defeat_last_admin_protection(
    backup_status, backup_verified
):
    from app.services import platform_service

    with SessionLocal() as db:
        dev = seed_user(db)
        target_grant = seed_platform_grant(db, dev)
        backup = seed_user(
            db, status=backup_status, verified=backup_verified
        )
        seed_platform_grant(db, backup)
        db.commit()
        target_grant_id = target_grant.id

    with SessionLocal() as db:
        with pytest.raises(HTTPException) as exc_info:
            platform_service.revoke_platform_administrator(
                db, target_grant_id
            )
        assert exc_info.value.detail["code"] == "IAM_LAST_PLATFORM_ADMIN_PROTECTED"


def test_jwt_role_tenant_role_and_profile_fields_do_not_grant_platform_authority(
    monkeypatch,
):
    from app.settings import reset_settings

    with SessionLocal() as db:
        user = seed_user(
            db,
            email="platform-admin@corporate.example",
            employee_id="PLATFORM-ADMIN",
            department="Administrators",
        )
        seed_membership(db, user, role="TENANT_ADMIN")
        claims = identity_claims(
            user,
            role="PLATFORM_ADMIN",
            tenant_id="local-default",
        )
        db.commit()

    monkeypatch.setenv("AUTH_ENABLED", "true")
    monkeypatch.setenv("DEV_DEFAULT_TENANT", "false")
    reset_settings()
    with SessionLocal() as db:
        context = _resolve_context(db, claims, None)
        assert context.is_platform_admin is False
        assert "PLATFORM_ADMIN" not in context.roles
        assert not context.has_permission("platform:administrator:grant")


def test_email_change_removes_effective_platform_access_immediately():
    from app.services.identity_service import provision_local_identity

    with SessionLocal() as db:
        target = seed_user(db)
        grant = seed_platform_grant(db, target)
        claims = identity_claims(target)
        claims["email"] = "changed.phase6@example.test"
        user_id = target.id
        grant_id = grant.id
        db.commit()

    with SessionLocal() as db:
        result = provision_local_identity(db, claims)
        db.commit()
        assert result.user.id == user_id
        assert result.user.email_verified is False
        assert result.user.verification_required is True
        assert db.get(PlatformUserRole, grant_id).status == "ACTIVE"
        assert (
            platform_service.get_effective_platform_grant(db, result.user)
            is None
        )


def test_token_verification_does_not_reactivate_inactive_platform_grant(
    monkeypatch,
):
    from app.services.email_verification_service import (
        confirm_verification_token,
        issue_verification_email,
    )

    from tests.phase5_helpers import FakeVerificationEmailSender

    sender = FakeVerificationEmailSender()
    monkeypatch.setattr(
        "app.services.email_verification_service.get_verification_email_sender",
        lambda: sender,
    )
    with SessionLocal() as db:
        target = seed_user(db, verified=False)
        grant = seed_platform_grant(db, target, status="DISABLED")
        user_id = target.id
        grant_id = grant.id
        db.commit()
        issue_verification_email(
            db,
            user_id,
            resend=False,
            sender=sender,
        )
        raw_token = sender.raw_token
        confirm_verification_token(db, raw_token)

    with SessionLocal() as db:
        target = db.get(IAMUser, user_id)
        assert target.email_verified is True
        assert target.verification_required is False
        assert db.get(PlatformUserRole, grant_id).status == "DISABLED"
        assert platform_service.get_effective_platform_grant(db, target) is None

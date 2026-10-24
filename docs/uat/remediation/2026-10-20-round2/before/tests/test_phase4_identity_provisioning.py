from __future__ import annotations

from datetime import UTC, datetime
from uuid import uuid4

import pytest
from app.core.identity_states import IdentityAuditEvent
from app.models import AuthorizationAuditLog, IAMUser, PlatformUserRole, TenantUser
from app.services.identity_service import provision_local_identity
from fastapi import HTTPException
from sqlalchemy import func, select


def _claims(suffix: str, **overrides):
    values = {
        "iss": "https://hcl-cs.example.test",
        "sub": f"phase4-{suffix}",
        "email": f"phase4-{suffix}@example.test",
        "name": "Phase Four User",
        "preferred_username": f"phase4-{suffix}@example.test",
        "employee_id": f"00{suffix[:6]}",
        "department": "Security",
    }
    values.update(overrides)
    return values


def test_first_login_creates_active_unverified_user_without_authority():
    from app.db import SessionLocal

    claims = _claims(uuid4().hex)
    with SessionLocal() as db:
        result = provision_local_identity(db, claims)
        db.commit()
        user_id = result.user.id
        assert result.created is True
        assert result.user.status == "ACTIVE"
        assert result.user.email_verified is False
        assert result.user.email_verified_at is None
        assert result.user.verification_required is True
        assert result.user.external_issuer == claims["iss"]
        assert result.user.external_subject == claims["sub"]
        assert result.user.external_iam_user_id == claims["sub"]
        assert db.scalar(select(func.count(TenantUser.id)).where(TenantUser.user_id == user_id)) == 0
        assert db.scalar(
            select(func.count(PlatformUserRole.id)).where(PlatformUserRole.user_id == user_id)
        ) == 0
        assert db.scalar(
            select(func.count(AuthorizationAuditLog.id)).where(
                AuthorizationAuditLog.action == str(IdentityAuditEvent.USER_PROVISIONED),
                AuthorizationAuditLog.target_user_id == user_id,
            )
        ) == 1


def test_repeat_login_is_idempotent_and_does_not_duplicate_provision_audit():
    from app.db import SessionLocal

    claims = _claims(uuid4().hex)
    with SessionLocal() as db:
        first = provision_local_identity(db, claims)
        db.commit()
        first_id = first.user.id
        second = provision_local_identity(db, claims)
        db.commit()
        assert second.user.id == first_id
        assert second.created is False
        assert db.scalar(
            select(func.count(IAMUser.id)).where(
                IAMUser.external_issuer == claims["iss"],
                IAMUser.external_subject == claims["sub"],
            )
        ) == 1
        assert db.scalar(
            select(func.count(AuthorizationAuditLog.id)).where(
                AuthorizationAuditLog.action == str(IdentityAuditEvent.USER_PROVISIONED),
                AuthorizationAuditLog.target_user_id == first_id,
            )
        ) == 1


def test_same_email_different_subjects_are_not_merged():
    from app.db import SessionLocal

    suffix = uuid4().hex
    shared_email = f"shared-{suffix}@example.test"
    with SessionLocal() as db:
        first = provision_local_identity(
            db,
            _claims(suffix, sub=f"subject-a-{suffix}", email=shared_email),
        )
        second = provision_local_identity(
            db,
            _claims(suffix, sub=f"subject-b-{suffix}", email=shared_email),
        )
        db.commit()
        assert first.user.id != second.user.id


def test_same_subject_under_different_issuers_creates_separate_composite_identities():
    from app.db import SessionLocal

    suffix = uuid4().hex
    subject = f"shared-subject-{suffix}"
    with SessionLocal() as db:
        first = provision_local_identity(
            db,
            _claims(suffix, iss="https://issuer-a.example.test", sub=subject),
        )
        second = provision_local_identity(
            db,
            _claims(suffix, iss="https://issuer-b.example.test", sub=subject),
        )
        db.commit()
        assert first.user.id != second.user.id
        assert first.user.external_subject == second.user.external_subject == subject
        assert first.user.external_iam_user_id == subject
        assert second.user.external_iam_user_id != subject


def test_legacy_identity_links_only_when_non_conflicting():
    from app.db import SessionLocal

    suffix = uuid4().hex
    claims = _claims(suffix)
    now = datetime.now(UTC)
    with SessionLocal() as db:
        legacy = IAMUser(
            external_iam_user_id=claims["sub"],
            email=claims["email"],
            display_name=claims["name"],
            status="PENDING",
            created_at=now,
            updated_at=now,
        )
        db.add(legacy)
        db.commit()
        original_id = legacy.id
        result = provision_local_identity(db, claims)
        db.commit()
        assert result.linked is True
        assert result.user.id == original_id
        assert result.user.status == "PENDING"
        assert result.user.external_issuer == claims["iss"]
        assert db.scalar(
            select(func.count(AuthorizationAuditLog.id)).where(
                AuthorizationAuditLog.action == str(IdentityAuditEvent.EXTERNAL_IDENTITY_LINKED)
            )
        ) == 1


def test_conflicting_legacy_identity_is_rejected_and_audited():
    from app.db import SessionLocal

    suffix = uuid4().hex
    claims = _claims(suffix)
    now = datetime.now(UTC)
    with SessionLocal() as db:
        db.add(
            IAMUser(
                external_iam_user_id=claims["sub"],
                external_issuer=claims["iss"],
                external_subject=f"different-{claims['sub']}",
                status="ACTIVE",
                created_at=now,
                updated_at=now,
            )
        )
        db.commit()
        with pytest.raises(HTTPException) as exc_info:
            provision_local_identity(db, claims)
        db.commit()
        assert exc_info.value.status_code == 403
        assert exc_info.value.detail["code"] == "IAM_IDENTITY_CONFLICT"
        assert db.scalar(
            select(func.count(AuthorizationAuditLog.id)).where(
                AuthorizationAuditLog.action == str(IdentityAuditEvent.IDENTITY_CONFLICT)
            )
        ) == 1


@pytest.mark.parametrize(
    "mutator",
    [
        lambda claims: claims.pop("iss"),
        lambda claims: claims.pop("sub"),
        lambda claims: claims.pop("email"),
        lambda claims: claims.pop("name"),
        lambda claims: claims.pop("preferred_username"),
        lambda claims: claims.pop("employee_id"),
        lambda claims: claims.update(email="not-an-email"),
        lambda claims: claims.update(email="user@@example.test"),
        lambda claims: claims.update(name=123),
        lambda claims: claims.update(sub="subject\ninjected"),
        lambda claims: claims.update(department="Security\nInjected"),
        lambda claims: claims.update(employee_id="00123\u007f"),
    ],
)
def test_invalid_identity_claims_never_create_a_user(mutator, monkeypatch):
    monkeypatch.setenv("HCL_IAM_REQUIRE_EMPLOYEE_ID", "true")
    from app.db import SessionLocal

    claims = _claims(uuid4().hex)
    mutator(claims)
    with SessionLocal() as db:
        before = db.scalar(select(func.count(IAMUser.id)))
        with pytest.raises(HTTPException) as exc_info:
            provision_local_identity(db, claims)
        assert exc_info.value.status_code == 401
        assert exc_info.value.detail["code"] == "IAM_REQUIRED_CLAIM_MISSING"
        assert db.scalar(select(func.count(IAMUser.id))) == before


def test_profile_sync_and_email_change_preserve_authority_but_reset_verification():
    from app.db import SessionLocal

    suffix = uuid4().hex
    claims = _claims(suffix)
    now = datetime.now(UTC)
    with SessionLocal() as db:
        user = IAMUser(
            external_iam_user_id=claims["sub"],
            external_issuer=claims["iss"],
            external_subject=claims["sub"],
            email=claims["email"],
            display_name=claims["name"],
            user_principal_name=claims["preferred_username"],
            employee_id=claims["employee_id"],
            department=claims["department"],
            status="ACTIVE",
            email_verified=True,
            email_verified_at=now,
            verification_required=False,
            created_at=now,
            updated_at=now,
        )
        db.add(user)
        db.flush()
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

        profile = provision_local_identity(
            db,
            _claims(
                suffix,
                name="Updated Name",
                preferred_username="updated@example.test",
                employee_id="000777",
                department="Engineering",
            ),
        )
        db.commit()
        assert profile.user.email_verified is True
        assert profile.user.verification_required is False

        changed = provision_local_identity(
            db,
            _claims(suffix, email=f"new-{suffix}@example.test"),
        )
        db.commit()
        assert changed.email_changed is True
        assert changed.user.email_verified is False
        assert changed.user.email_verified_at is None
        assert changed.user.verification_required is True
        assert db.get(TenantUser, membership_id) is not None
        assert db.get(PlatformUserRole, grant_id) is not None
        actions = set(db.scalars(select(AuthorizationAuditLog.action)))
        assert {
            str(IdentityAuditEvent.EMAIL_CHANGED),
            str(IdentityAuditEvent.REVERIFICATION_REQUIRED),
            str(IdentityAuditEvent.CLAIMS_SYNCHRONIZED),
        } <= actions

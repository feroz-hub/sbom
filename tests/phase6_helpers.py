"""Reusable PostgreSQL seeds for Phase 6 platform-administration tests."""

from __future__ import annotations

from datetime import UTC, datetime
from uuid import uuid4

from app.models import IAMUser, PlatformUserRole, TenantUser
from app.services.tenant_role_assignment_service import create_initial_assignment
from sqlalchemy import select


def now() -> datetime:
    return datetime.now(UTC)


def seed_user(
    db,
    *,
    status: str = "ACTIVE",
    verified: bool = True,
    email: str | None = None,
    display_name: str = "Phase Six User",
    employee_id: str | None = None,
    department: str | None = "Security",
) -> IAMUser:
    suffix = uuid4().hex
    timestamp = now()
    user = IAMUser(
        external_iam_user_id=f"phase6-{suffix}",
        external_issuer="https://hcl-cs.test",
        external_subject=f"phase6-subject-{suffix}",
        employee_id=employee_id or f"EMP-{suffix}",
        user_principal_name=f"phase6-{suffix}@example.test",
        department=department,
        email=email or f"phase6-{suffix}@example.test",
        display_name=display_name,
        status=status,
        email_verified=verified,
        email_verified_at=timestamp if verified else None,
        verification_required=not verified,
        last_claim_sync_at=timestamp,
        last_login_at=timestamp,
        created_at=timestamp,
        updated_at=timestamp,
    )
    db.add(user)
    db.flush()
    return user


def dev_user(db) -> IAMUser:
    return db.scalar(
        select(IAMUser).where(IAMUser.external_iam_user_id == "dev-user")
    )


def seed_platform_grant(
    db,
    user: IAMUser,
    *,
    status: str = "ACTIVE",
    creator_id: int | None = None,
) -> PlatformUserRole:
    timestamp = now()
    grant = PlatformUserRole(
        user_id=user.id,
        role="PLATFORM_ADMIN",
        status=status,
        created_by_user_id=creator_id,
        created_at=timestamp,
        updated_at=timestamp,
    )
    db.add(grant)
    db.flush()
    return grant


def seed_dev_platform_admin(db) -> tuple[IAMUser, PlatformUserRole]:
    user = dev_user(db)
    grant = seed_platform_grant(db, user)
    db.commit()
    return user, grant


def seed_membership(
    db,
    user: IAMUser,
    *,
    tenant_id: int = 1,
    role: str = "VIEWER",
    status: str = "ACTIVE",
) -> TenantUser:
    timestamp = now()
    membership = TenantUser(
        tenant_id=tenant_id,
        user_id=user.id,
        role=role,
        status=status,
        created_at=timestamp,
        updated_at=timestamp,
    )
    db.add(membership)
    db.flush()
    create_initial_assignment(
        db,
        membership,
        role_code=role,
        actor_user_id=user.id,
        source="SYSTEM",
    )
    return membership


def identity_claims(user: IAMUser, **overrides) -> dict:
    claims = {
        "iss": user.external_issuer,
        "sub": user.external_subject,
        "email": user.email,
        "name": user.display_name,
        "preferred_username": user.user_principal_name,
        "employee_id": user.employee_id,
    }
    claims.update(overrides)
    return claims

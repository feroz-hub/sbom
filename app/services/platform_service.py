"""Database-authoritative platform administrator grants."""

from __future__ import annotations

from datetime import UTC, datetime

from fastapi import HTTPException
from sqlalchemy import func, select
from sqlalchemy.orm import Session

from ..core.permissions import TENANT_STATUSES, USER_STATUSES
from ..models import IAMUser, PlatformUserRole, Tenant


def get_active_platform_grant(db: Session, user_id: int) -> PlatformUserRole | None:
    return db.execute(
        select(PlatformUserRole).where(
            PlatformUserRole.user_id == user_id,
            PlatformUserRole.role == "PLATFORM_ADMIN",
            PlatformUserRole.status == "ACTIVE",
        )
    ).scalar_one_or_none()


def list_platform_administrators(db: Session) -> list[tuple[PlatformUserRole, IAMUser]]:
    return list(
        db.execute(
            select(PlatformUserRole, IAMUser)
            .join(IAMUser, IAMUser.id == PlatformUserRole.user_id)
            .order_by(IAMUser.email, IAMUser.external_iam_user_id)
        ).all()
    )


def list_platform_tenants(db: Session) -> list[Tenant]:
    """Return every tenant, including disabled tenants, for platform administration."""
    return list(db.execute(select(Tenant).order_by(Tenant.name, Tenant.id)).scalars())


def grant_platform_administrator(
    db: Session,
    *,
    external_iam_user_id: str,
    created_by_user_id: int | None,
) -> tuple[PlatformUserRole, IAMUser, dict | None]:
    user = db.execute(
        select(IAMUser).where(IAMUser.external_iam_user_id == external_iam_user_id)
    ).scalar_one_or_none()
    if user is None:
        raise HTTPException(status_code=404, detail="IAM user not found")
    if user.status != "ACTIVE":
        raise HTTPException(status_code=422, detail="Only active IAM users may receive platform authority")
    now = datetime.now(UTC)
    grant = db.execute(
        select(PlatformUserRole).where(PlatformUserRole.user_id == user.id)
    ).scalar_one_or_none()
    old = None
    if grant is None:
        grant = PlatformUserRole(
            user_id=user.id,
            role="PLATFORM_ADMIN",
            status="ACTIVE",
            created_by_user_id=created_by_user_id,
            created_at=now,
            updated_at=now,
        )
        db.add(grant)
    else:
        old = {"role": grant.role, "status": grant.status}
        grant.role = "PLATFORM_ADMIN"
        grant.status = "ACTIVE"
        grant.created_by_user_id = created_by_user_id
        grant.updated_at = now
    db.flush()
    return grant, user, old


def revoke_platform_administrator(db: Session, grant_id: int) -> tuple[PlatformUserRole, IAMUser]:
    row = db.execute(
        select(PlatformUserRole, IAMUser)
        .join(IAMUser, IAMUser.id == PlatformUserRole.user_id)
        .where(PlatformUserRole.id == grant_id)
    ).one_or_none()
    if row is None:
        raise HTTPException(status_code=404, detail="Platform administrator grant not found")
    grant, user = row
    active_count = db.execute(
        select(func.count(PlatformUserRole.id))
        .join(IAMUser, IAMUser.id == PlatformUserRole.user_id)
        .where(PlatformUserRole.status == "ACTIVE", IAMUser.status == "ACTIVE")
    ).scalar_one()
    if grant.status == "ACTIVE" and active_count <= 1:
        raise HTTPException(status_code=409, detail="Cannot revoke the last active platform administrator")
    grant.status = "DISABLED"
    grant.updated_at = datetime.now(UTC)
    db.flush()
    return grant, user


def update_user_status(db: Session, user_id: int, status_value: str) -> tuple[IAMUser, str]:
    status_value = status_value.strip().upper()
    if status_value not in USER_STATUSES:
        raise HTTPException(status_code=422, detail="Invalid IAM user status")
    user = db.get(IAMUser, user_id)
    if user is None:
        raise HTTPException(status_code=404, detail="IAM user not found")
    if status_value != "ACTIVE" and get_active_platform_grant(db, user.id) is not None:
        active_count = db.execute(
            select(func.count(PlatformUserRole.id))
            .join(IAMUser, IAMUser.id == PlatformUserRole.user_id)
            .where(PlatformUserRole.status == "ACTIVE", IAMUser.status == "ACTIVE")
        ).scalar_one()
        if active_count <= 1:
            raise HTTPException(status_code=409, detail="Cannot disable the last active platform administrator")
    old_status = user.status
    user.status = status_value
    user.updated_at = datetime.now(UTC)
    db.flush()
    return user, old_status


def update_tenant_status(db: Session, tenant_id: int, status_value: str) -> tuple[Tenant, str]:
    status_value = status_value.strip().upper()
    if status_value not in TENANT_STATUSES:
        raise HTTPException(status_code=422, detail="Invalid tenant status")
    tenant = db.get(Tenant, tenant_id)
    if tenant is None:
        raise HTTPException(status_code=404, detail="Tenant not found")
    old_status = tenant.status
    tenant.status = status_value
    tenant.updated_at = datetime.now(UTC)
    db.flush()
    return tenant, old_status

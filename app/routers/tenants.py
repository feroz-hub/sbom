from __future__ import annotations

from datetime import UTC, datetime

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel, Field
from sqlalchemy import select
from sqlalchemy.orm import Session

from ..core.context import CurrentContext
from ..core.permissions import ROLE_PERMISSIONS, normalize_role
from ..core.security import get_current_tenant_context, require_permission
from ..db import get_db
from ..models import AuditLog, IAMUser, Tenant, TenantUser

router = APIRouter(prefix="/api", tags=["identity"])


class TenantCreate(BaseModel):
    name: str = Field(min_length=1, max_length=255)
    slug: str = Field(pattern=r"^[a-z0-9][a-z0-9-]{1,126}[a-z0-9]$")
    external_iam_tenant_id: str = Field(min_length=1, max_length=255)


class MembershipUpsert(BaseModel):
    external_iam_user_id: str = Field(min_length=1, max_length=255)
    email: str | None = Field(default=None, max_length=320)
    display_name: str | None = Field(default=None, max_length=255)
    role: str
    status: str = "ACTIVE"


class MembershipUpdate(BaseModel):
    role: str | None = None
    status: str | None = None


def _tenant_dict(tenant: Tenant, role: str | None = None) -> dict:
    return {
        "id": tenant.id,
        "name": tenant.name,
        "slug": tenant.slug,
        "external_iam_tenant_id": tenant.external_iam_tenant_id,
        "status": tenant.status,
        "role": role,
    }


@router.get("/auth/me")
def auth_me(context: CurrentContext = Depends(get_current_tenant_context)) -> dict:
    return {
        "user_id": context.user_id,
        "external_user_id": context.external_user_id,
        "email": context.email,
        "display_name": context.display_name,
        "tenant_id": context.tenant_id,
        "external_tenant_id": context.external_tenant_id,
        "roles": sorted(context.roles),
        "permissions": sorted(context.permissions),
        "is_platform_admin": context.is_platform_admin,
    }


@router.get("/tenants")
def list_my_tenants(
    context: CurrentContext = Depends(get_current_tenant_context),
    db: Session = Depends(get_db),
) -> list[dict]:
    if context.is_platform_admin:
        tenants = db.execute(select(Tenant).where(Tenant.status == "ACTIVE").order_by(Tenant.name)).scalars()
        return [_tenant_dict(tenant, "PLATFORM_ADMIN") for tenant in tenants]
    rows = db.execute(
        select(Tenant, TenantUser.role)
        .join(TenantUser, TenantUser.tenant_id == Tenant.id)
        .where(
            TenantUser.user_id == context.user_id,
            TenantUser.status == "ACTIVE",
            Tenant.status == "ACTIVE",
        )
        .order_by(Tenant.name)
    ).all()
    return [_tenant_dict(tenant, role) for tenant, role in rows]


@router.post("/tenants", status_code=201)
def create_tenant(
    payload: TenantCreate,
    context: CurrentContext = Depends(require_permission("platform:admin")),
    db: Session = Depends(get_db),
) -> dict:
    now = datetime.now(UTC)
    tenant = Tenant(
        name=payload.name.strip(),
        slug=payload.slug,
        external_iam_tenant_id=payload.external_iam_tenant_id,
        status="ACTIVE",
        created_at=now,
        updated_at=now,
    )
    db.add(tenant)
    db.commit()
    db.refresh(tenant)
    return _tenant_dict(tenant)


@router.get("/tenants/{tenant_id}/users")
def list_tenant_users(
    tenant_id: int,
    context: CurrentContext = Depends(require_permission("tenant:user:read")),
    db: Session = Depends(get_db),
) -> list[dict]:
    if tenant_id != context.tenant_id:
        raise HTTPException(status_code=403, detail="Tenant access denied")
    rows = db.execute(
        select(TenantUser, IAMUser)
        .join(IAMUser, IAMUser.id == TenantUser.user_id)
        .where(TenantUser.tenant_id == tenant_id)
        .order_by(IAMUser.email, IAMUser.external_iam_user_id)
    ).all()
    return [
        {
            "membership_id": membership.id,
            "user_id": user.id,
            "external_iam_user_id": user.external_iam_user_id,
            "email": user.email,
            "display_name": user.display_name,
            "role": membership.role,
            "status": membership.status,
        }
        for membership, user in rows
    ]


@router.post("/tenants/{tenant_id}/users", status_code=201)
def add_tenant_user(
    tenant_id: int,
    payload: MembershipUpsert,
    context: CurrentContext = Depends(require_permission("tenant:user:invite")),
    db: Session = Depends(get_db),
) -> dict:
    if tenant_id != context.tenant_id:
        raise HTTPException(status_code=403, detail="Tenant access denied")
    role = normalize_role(payload.role)
    if role not in ROLE_PERMISSIONS or role == "PLATFORM_ADMIN":
        raise HTTPException(status_code=422, detail="Invalid tenant role")
    now = datetime.now(UTC)
    user = db.execute(
        select(IAMUser).where(IAMUser.external_iam_user_id == payload.external_iam_user_id)
    ).scalar_one_or_none()
    if user is None:
        user = IAMUser(
            external_iam_user_id=payload.external_iam_user_id,
            email=str(payload.email) if payload.email else None,
            display_name=payload.display_name,
            status="ACTIVE",
            created_at=now,
            updated_at=now,
        )
        db.add(user)
        db.flush()
    membership = db.execute(
        select(TenantUser).where(TenantUser.tenant_id == tenant_id, TenantUser.user_id == user.id)
    ).scalar_one_or_none()
    if membership is None:
        membership = TenantUser(
            tenant_id=tenant_id,
            user_id=user.id,
            role=role,
            status=payload.status.upper(),
            created_at=now,
            updated_at=now,
        )
        db.add(membership)
    else:
        membership.role = role
        membership.status = payload.status.upper()
        membership.updated_at = now
    db.add(
        AuditLog(
            tenant_id=tenant_id,
            user_id=context.external_user_id,
            user_ref_id=context.user_id,
            action="tenant.user.upsert",
            target_kind="tenant_user",
            target_id=user.id,
            entity_type="tenant_user",
            entity_id=str(user.id),
            new_value={"role": role, "status": membership.status},
            created_at=now.isoformat(),
        )
    )
    db.commit()
    return {"membership_id": membership.id, "user_id": user.id, "role": role, "status": membership.status}


@router.patch("/tenants/{tenant_id}/users/{membership_id}")
def update_tenant_user(
    tenant_id: int,
    membership_id: int,
    payload: MembershipUpdate,
    context: CurrentContext = Depends(require_permission("tenant:user:update")),
    db: Session = Depends(get_db),
) -> dict:
    if tenant_id != context.tenant_id:
        raise HTTPException(status_code=403, detail="Tenant access denied")
    membership = db.execute(
        select(TenantUser).where(TenantUser.id == membership_id, TenantUser.tenant_id == tenant_id)
    ).scalar_one_or_none()
    if membership is None:
        raise HTTPException(status_code=404, detail="Membership not found")
    old = {"role": membership.role, "status": membership.status}
    if payload.role is not None:
        role = normalize_role(payload.role)
        if role not in ROLE_PERMISSIONS or role == "PLATFORM_ADMIN":
            raise HTTPException(status_code=422, detail="Invalid tenant role")
        membership.role = role
    if payload.status is not None:
        membership.status = payload.status.upper()
    membership.updated_at = datetime.now(UTC)
    db.add(
        AuditLog(
            tenant_id=tenant_id,
            user_id=context.external_user_id,
            user_ref_id=context.user_id,
            action="tenant.user.update",
            target_kind="tenant_user",
            target_id=membership.user_id,
            entity_type="tenant_user",
            entity_id=str(membership.user_id),
            old_value=old,
            new_value={"role": membership.role, "status": membership.status},
            created_at=membership.updated_at.isoformat(),
        )
    )
    db.commit()
    return {"membership_id": membership.id, "role": membership.role, "status": membership.status}

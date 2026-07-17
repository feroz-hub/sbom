from __future__ import annotations

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel, Field
from sqlalchemy.orm import Session

from ..core.context import CurrentContext
from ..core.permissions import ROLE_PERMISSIONS, normalize_role
from ..core.security import get_current_tenant_context, require_permission
from ..db import get_db
from ..models import Tenant
from ..services import audit_service
from ..services import tenant_service as ts

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
@router.get("/v1/auth/me")
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
        "authenticated": True,
        "role": sorted(context.roles)[0] if context.roles else None,
    }


@router.get("/tenants")
def list_my_tenants(
    context: CurrentContext = Depends(get_current_tenant_context),
    db: Session = Depends(get_db),
) -> list[dict]:
    rows = ts.get_available_tenants_for_user(db, context.user_id, context.is_platform_admin)
    return [_tenant_dict(tenant, role) for tenant, role in rows]


@router.post("/tenants", status_code=201)
def create_tenant(
    payload: TenantCreate,
    context: CurrentContext = Depends(require_permission("platform:admin")),
    db: Session = Depends(get_db),
) -> dict:
    tenant = ts.create_tenant(
        db,
        name=payload.name,
        slug=payload.slug,
        external_iam_tenant_id=payload.external_iam_tenant_id,
    )
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
    rows = ts.list_tenant_users(db, tenant_id)
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
    membership, user = ts.add_user_to_tenant(
        db,
        tenant_id,
        external_iam_user_id=payload.external_iam_user_id,
        email=str(payload.email) if payload.email else None,
        display_name=payload.display_name,
        role=role,
        status=payload.status,
    )
    audit_service.write_audit_log(
        db,
        context,
        "tenant.user.upsert",
        entity_type="tenant_user",
        entity_id=user.id,
        new_value={"role": role, "status": membership.status},
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
    if payload.role is not None:
        role = normalize_role(payload.role)
        if role not in ROLE_PERMISSIONS or role == "PLATFORM_ADMIN":
            raise HTTPException(status_code=422, detail="Invalid tenant role")
    membership, old, new = ts.update_user_role(
        db,
        tenant_id,
        membership_id,
        role=normalize_role(payload.role) if payload.role is not None else None,
        status=payload.status,
    )
    audit_service.write_audit_log(
        db,
        context,
        "tenant.user.update",
        entity_type="tenant_user",
        entity_id=membership.user_id,
        old_value=old,
        new_value=new,
    )
    db.commit()
    return {"membership_id": membership.id, "role": membership.role, "status": membership.status}

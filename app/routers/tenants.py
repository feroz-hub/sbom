from __future__ import annotations

from typing import Literal

from fastapi import APIRouter, Depends, HTTPException, Request
from pydantic import AliasChoices, BaseModel, Field, field_validator
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from ..core.context import CurrentContext
from ..core.permissions import TENANT_ROLES
from ..core.security import get_current_tenant_context, invalidate_user_contexts, require_permission
from ..db import get_db
from ..models import IAMUser, Tenant, TenantUser
from ..services import audit_service
from ..services import tenant_service as ts

router = APIRouter(prefix="/api", tags=["identity"])

TenantRole = Literal["TENANT_ADMIN", "SECURITY_ANALYST", "DEVELOPER", "VIEWER"]
MembershipStatus = Literal["ACTIVE", "PENDING", "DISABLED"]


class TenantCreate(BaseModel):
    name: str = Field(min_length=1, max_length=255)
    slug: str = Field(min_length=3, max_length=128, pattern=r"^[a-z0-9]+(?:-[a-z0-9]+)*$")
    external_iam_tenant_id: str = Field(min_length=1, max_length=255)

    @field_validator("name", "external_iam_tenant_id")
    @classmethod
    def strip_required_text(cls, value: str) -> str:
        stripped = value.strip()
        if not stripped:
            raise ValueError("Field must not be blank")
        return stripped


class MembershipUpsert(BaseModel):
    external_user_id: str = Field(
        min_length=1,
        max_length=255,
        validation_alias=AliasChoices("external_user_id", "external_iam_user_id"),
    )
    role: TenantRole
    status: MembershipStatus = "ACTIVE"


class MembershipUpdate(BaseModel):
    role: TenantRole | None = None
    status: MembershipStatus | None = None


def _tenant_dict(tenant: Tenant, role: str | None = None) -> dict:
    return {
        "id": tenant.id,
        "name": tenant.name,
        "slug": tenant.slug,
        "external_iam_tenant_id": tenant.external_iam_tenant_id,
        "status": tenant.status,
        "role": role,
        "created_at": tenant.created_at,
        "updated_at": tenant.updated_at,
    }


def _membership_dict(membership, user) -> dict:
    return {
        "membership_id": membership.id,
        "user_id": user.id,
        "external_iam_user_id": user.external_iam_user_id,
        "email": user.email,
        "display_name": user.display_name,
        "user_status": user.status,
        "role": membership.role,
        "status": membership.status,
    }


def _require_current_tenant(tenant_id: int, context: CurrentContext) -> None:
    if context.tenant_id is None or tenant_id != context.tenant_id:
        raise HTTPException(status_code=404, detail="Tenant membership not found")


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
        "identity_roles": sorted(context.identity_roles),
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
    request: Request,
    context: CurrentContext = Depends(require_permission("platform:tenant:create")),
    db: Session = Depends(get_db),
) -> dict:
    try:
        tenant = ts.create_tenant(
            db,
            name=payload.name,
            slug=payload.slug,
            external_iam_tenant_id=payload.external_iam_tenant_id,
        )
    except (HTTPException, IntegrityError) as exc:
        if isinstance(exc, IntegrityError):
            db.rollback()
            exc = HTTPException(status_code=409, detail="A tenant with this slug or external IAM tenant ID already exists.")
        audit_service.write_authorization_audit(
            db,
            action="tenant.create_denied",
            outcome="DENIED",
            context=context,
            request=request,
            new_value={"name": payload.name, "slug": payload.slug, "external_iam_tenant_id": payload.external_iam_tenant_id},
            detail=str(exc.detail),
        )
        db.commit()
        raise
    audit_service.write_authorization_audit(
        db,
        action="tenant.created",
        context=context,
        tenant_id=tenant.id,
        request=request,
        new_value={
            "name": tenant.name,
            "slug": tenant.slug,
            "external_iam_tenant_id": tenant.external_iam_tenant_id,
            "status": tenant.status,
        },
    )
    db.commit()
    db.refresh(tenant)
    return _tenant_dict(tenant)


@router.get("/tenant-roles")
def list_assignable_tenant_roles(
    _context: CurrentContext = Depends(require_permission("tenant:user:read")),
) -> dict:
    return {"roles": sorted(TENANT_ROLES)}


@router.get("/tenants/{tenant_id}/users")
def list_tenant_users(
    tenant_id: int,
    context: CurrentContext = Depends(require_permission("tenant:user:read")),
    db: Session = Depends(get_db),
) -> list[dict]:
    _require_current_tenant(tenant_id, context)
    return [_membership_dict(membership, user) for membership, user in ts.list_tenant_users(db, tenant_id)]


@router.get("/tenants/{tenant_id}/users/{membership_id}")
def get_tenant_user(
    tenant_id: int,
    membership_id: int,
    context: CurrentContext = Depends(require_permission("tenant:user:read")),
    db: Session = Depends(get_db),
) -> dict:
    _require_current_tenant(tenant_id, context)
    membership, user = ts.get_tenant_membership(db, tenant_id, membership_id)
    return _membership_dict(membership, user)


@router.post("/tenants/{tenant_id}/users", status_code=201)
def add_tenant_user(
    tenant_id: int,
    payload: MembershipUpsert,
    request: Request,
    context: CurrentContext = Depends(require_permission("tenant:user:invite")),
    db: Session = Depends(get_db),
) -> dict:
    _require_current_tenant(tenant_id, context)
    existing = None
    previous_user_status = None
    user_id = db.query(IAMUser.id).filter(IAMUser.external_iam_user_id == payload.external_user_id).scalar()
    if user_id is not None:
        previous_user_status = db.query(IAMUser.status).filter(IAMUser.id == user_id).scalar()
        existing = db.query(TenantUser).filter(
            TenantUser.tenant_id == tenant_id,
            TenantUser.user_id == user_id,
        ).one_or_none()
    membership, user = ts.add_user_to_tenant(
        db,
        tenant_id,
        external_iam_user_id=payload.external_user_id,
        role=payload.role,
        status=payload.status,
    )
    action = "membership.updated" if existing else "membership.created"
    audit_service.write_authorization_audit(
        db,
        action=action,
        context=context,
        target_user_id=user.id,
        target_membership_id=membership.id,
        tenant_id=tenant_id,
        request=request,
        new_value={"role": membership.role, "status": membership.status},
    )
    if previous_user_status is not None and previous_user_status != user.status:
        audit_service.write_authorization_audit(
            db,
            action="iam.user.status_changed",
            context=context,
            target_user_id=user.id,
            tenant_id=tenant_id,
            request=request,
            old_value={"status": previous_user_status},
            new_value={"status": user.status},
        )
    db.commit()
    invalidate_user_contexts(user.id)
    return _membership_dict(membership, user)


@router.patch("/tenants/{tenant_id}/users/{membership_id}")
def update_tenant_user(
    tenant_id: int,
    membership_id: int,
    payload: MembershipUpdate,
    request: Request,
    context: CurrentContext = Depends(require_permission("tenant:user:update")),
    db: Session = Depends(get_db),
) -> dict:
    _require_current_tenant(tenant_id, context)
    membership, user = ts.get_tenant_membership(db, tenant_id, membership_id)
    try:
        ts.ensure_not_last_active_tenant_admin(
            db,
            membership,
            next_role=payload.role,
            next_status=payload.status,
            platform_override=context.is_platform_admin,
        )
    except HTTPException as exc:
        audit_service.write_authorization_audit(
            db,
            action="membership.update_denied",
            outcome="DENIED",
            context=context,
            target_user_id=user.id,
            target_membership_id=membership.id,
            tenant_id=tenant_id,
            request=request,
            detail=str(exc.detail),
        )
        db.commit()
        raise
    membership, old, new = ts.update_user_role(
        db,
        tenant_id,
        membership_id,
        role=payload.role,
        status=payload.status,
    )
    action = "membership.role_changed" if old["role"] != new["role"] else "membership.status_changed"
    audit_service.write_authorization_audit(
        db,
        action=action,
        context=context,
        target_user_id=user.id,
        target_membership_id=membership.id,
        tenant_id=tenant_id,
        request=request,
        old_value=old,
        new_value=new,
    )
    db.commit()
    invalidate_user_contexts(user.id)
    return _membership_dict(membership, user)


def _set_membership_status(
    tenant_id: int,
    membership_id: int,
    status_value: MembershipStatus,
    request: Request,
    context: CurrentContext,
    db: Session,
) -> dict:
    _require_current_tenant(tenant_id, context)
    membership, user = ts.get_tenant_membership(db, tenant_id, membership_id)
    try:
        ts.ensure_not_last_active_tenant_admin(
            db,
            membership,
            next_status=status_value,
            platform_override=context.is_platform_admin,
        )
    except HTTPException as exc:
        audit_service.write_authorization_audit(
            db,
            action="membership.status_change_denied",
            outcome="DENIED",
            context=context,
            target_user_id=user.id,
            target_membership_id=membership.id,
            tenant_id=tenant_id,
            request=request,
            detail=str(exc.detail),
        )
        db.commit()
        raise
    membership, old, new = ts.set_membership_status(db, tenant_id, membership_id, status_value)
    action = "membership.activated" if status_value == "ACTIVE" else "membership.deactivated"
    audit_service.write_authorization_audit(
        db,
        action=action,
        context=context,
        target_user_id=user.id,
        target_membership_id=membership.id,
        tenant_id=tenant_id,
        request=request,
        old_value=old,
        new_value=new,
    )
    db.commit()
    invalidate_user_contexts(user.id)
    return _membership_dict(membership, user)


@router.post("/tenants/{tenant_id}/users/{membership_id}/activate")
def activate_tenant_user(
    tenant_id: int,
    membership_id: int,
    request: Request,
    context: CurrentContext = Depends(require_permission("tenant:user:update")),
    db: Session = Depends(get_db),
) -> dict:
    return _set_membership_status(tenant_id, membership_id, "ACTIVE", request, context, db)


@router.post("/tenants/{tenant_id}/users/{membership_id}/deactivate")
def deactivate_tenant_user(
    tenant_id: int,
    membership_id: int,
    request: Request,
    context: CurrentContext = Depends(require_permission("tenant:user:update")),
    db: Session = Depends(get_db),
) -> dict:
    return _set_membership_status(tenant_id, membership_id, "DISABLED", request, context, db)


@router.delete("/tenants/{tenant_id}/users/{membership_id}", status_code=204)
def delete_tenant_user(
    tenant_id: int,
    membership_id: int,
    request: Request,
    context: CurrentContext = Depends(require_permission("tenant:user:update")),
    db: Session = Depends(get_db),
) -> None:
    _require_current_tenant(tenant_id, context)
    membership, user = ts.get_tenant_membership(db, tenant_id, membership_id)
    try:
        ts.ensure_not_last_active_tenant_admin(
            db,
            membership,
            deleting=True,
            platform_override=context.is_platform_admin,
        )
    except HTTPException as exc:
        audit_service.write_authorization_audit(
            db,
            action="membership.remove_denied",
            outcome="DENIED",
            context=context,
            target_user_id=user.id,
            target_membership_id=membership.id,
            tenant_id=tenant_id,
            request=request,
            detail=str(exc.detail),
        )
        db.commit()
        raise
    old = {"role": membership.role, "status": membership.status}
    ts.remove_membership(db, tenant_id, membership_id)
    audit_service.write_authorization_audit(
        db,
        action="membership.removed",
        context=context,
        target_user_id=user.id,
        tenant_id=tenant_id,
        request=request,
        old_value=old,
    )
    db.commit()
    invalidate_user_contexts(user.id)

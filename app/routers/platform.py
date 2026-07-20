from __future__ import annotations

from typing import Literal

from fastapi import APIRouter, Depends, HTTPException, Request
from pydantic import BaseModel, Field
from sqlalchemy.orm import Session

from ..core.context import CurrentContext
from ..core.security import invalidate_user_contexts, require_permission
from ..db import get_db
from ..services import audit_service, platform_service

router = APIRouter(prefix="/api/platform", tags=["platform-identity"])


class PlatformAdministratorGrant(BaseModel):
    external_user_id: str = Field(min_length=1, max_length=255)


class UserStatusUpdate(BaseModel):
    status: Literal["ACTIVE", "PENDING", "DISABLED"]


class TenantStatusUpdate(BaseModel):
    status: Literal["ACTIVE", "PENDING", "DISABLED"]


def _grant_dict(grant, user) -> dict:
    return {
        "grant_id": grant.id,
        "user_id": user.id,
        "external_iam_user_id": user.external_iam_user_id,
        "email": user.email,
        "display_name": user.display_name,
        "user_status": user.status,
        "role": grant.role,
        "status": grant.status,
        "created_at": grant.created_at,
        "updated_at": grant.updated_at,
    }


def _tenant_dict(tenant) -> dict:
    return {
        "id": tenant.id,
        "name": tenant.name,
        "slug": tenant.slug,
        "external_iam_tenant_id": tenant.external_iam_tenant_id,
        "status": tenant.status,
        "created_at": tenant.created_at,
        "updated_at": tenant.updated_at,
    }


@router.get("/tenants")
def list_platform_tenants(
    _context: CurrentContext = Depends(require_permission("platform:tenant:create")),
    db: Session = Depends(get_db),
) -> list[dict]:
    return [_tenant_dict(tenant) for tenant in platform_service.list_platform_tenants(db)]


@router.get("/administrators")
def list_platform_administrators(
    _context: CurrentContext = Depends(require_permission("platform:user:read")),
    db: Session = Depends(get_db),
) -> list[dict]:
    return [_grant_dict(grant, user) for grant, user in platform_service.list_platform_administrators(db)]


@router.post("/administrators", status_code=201)
def grant_platform_administrator(
    payload: PlatformAdministratorGrant,
    request: Request,
    context: CurrentContext = Depends(require_permission("platform:user:write")),
    db: Session = Depends(get_db),
) -> dict:
    try:
        grant, user, old = platform_service.grant_platform_administrator(
            db,
            external_iam_user_id=payload.external_user_id,
            created_by_user_id=context.user_id,
        )
    except HTTPException as exc:
        audit_service.write_authorization_audit(
            db,
            action="platform_admin.grant_denied",
            outcome="DENIED",
            context=context,
            request=request,
            detail=str(exc.detail),
        )
        db.commit()
        raise
    audit_service.write_authorization_audit(
        db,
        action="platform_admin.granted",
        context=context,
        target_user_id=user.id,
        request=request,
        old_value=old,
        new_value={"role": grant.role, "status": grant.status},
    )
    db.commit()
    invalidate_user_contexts(user.id)
    return _grant_dict(grant, user)


@router.delete("/administrators/{grant_id}", status_code=204)
def revoke_platform_administrator(
    grant_id: int,
    request: Request,
    context: CurrentContext = Depends(require_permission("platform:user:write")),
    db: Session = Depends(get_db),
) -> None:
    try:
        grant, user = platform_service.revoke_platform_administrator(db, grant_id)
    except HTTPException as exc:
        audit_service.write_authorization_audit(
            db,
            action="platform_admin.revoke_denied",
            outcome="DENIED",
            context=context,
            request=request,
            new_value={"grant_id": grant_id},
            detail=str(exc.detail),
        )
        db.commit()
        raise
    audit_service.write_authorization_audit(
        db,
        action="platform_admin.revoked",
        context=context,
        target_user_id=user.id,
        request=request,
        old_value={"role": "PLATFORM_ADMIN", "status": "ACTIVE"},
        new_value={"role": grant.role, "status": grant.status},
    )
    db.commit()
    invalidate_user_contexts(user.id)


@router.patch("/users/{user_id}")
def update_iam_user_status(
    user_id: int,
    payload: UserStatusUpdate,
    request: Request,
    context: CurrentContext = Depends(require_permission("platform:user:write")),
    db: Session = Depends(get_db),
) -> dict:
    user, old_status = platform_service.update_user_status(db, user_id, payload.status)
    audit_service.write_authorization_audit(
        db,
        action="iam.user.status_changed",
        context=context,
        target_user_id=user.id,
        request=request,
        old_value={"status": old_status},
        new_value={"status": user.status},
    )
    db.commit()
    invalidate_user_contexts(user.id)
    return {"user_id": user.id, "status": user.status}


@router.patch("/tenants/{tenant_id}")
def update_tenant_status(
    tenant_id: int,
    payload: TenantStatusUpdate,
    request: Request,
    context: CurrentContext = Depends(require_permission("platform:admin")),
    db: Session = Depends(get_db),
) -> dict:
    tenant, old_status = platform_service.update_tenant_status(db, tenant_id, payload.status)
    audit_service.write_authorization_audit(
        db,
        action="tenant.status_changed",
        context=context,
        tenant_id=tenant.id,
        request=request,
        old_value={"status": old_status},
        new_value={"status": tenant.status},
    )
    db.commit()
    return {"tenant_id": tenant.id, "status": tenant.status}

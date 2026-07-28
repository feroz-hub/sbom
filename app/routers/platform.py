"""Centralized, database-authoritative platform administration APIs."""

from __future__ import annotations

from datetime import datetime
from typing import Literal

from fastapi import APIRouter, Depends, HTTPException, Query, Request
from pydantic import BaseModel
from sqlalchemy.orm import Session

from ..core.context import CurrentContext
from ..core.identity_states import IdentityAuditEvent, IdentityErrorCode
from ..core.security import invalidate_user_contexts, require_platform_permission
from ..db import get_db
from sqlalchemy import or_
from ..models import IAMUser, TenantUser
from ..schemas_platform import (
    PlatformAdministratorGrantRequest,
    PlatformAdministratorGrantResponse,
    PlatformAdministratorPage,
    PlatformGrantSummary,
    PlatformTenantMembershipSummary,
    PlatformUserDetail,
    PlatformUserPage,
    PlatformUserStatusResponse,
    PlatformUserStatusUpdate,
    PlatformUserSummary,
    TenantMembershipBrief,
    UserSearchResponse,
    UserSearchResult,
)
from ..services import audit_service, platform_service
from ..services.email_verification_service import ensure_initial_verification_delivery

router = APIRouter(prefix="/api/platform", tags=["platform-identity"])


class TenantStatusUpdate(BaseModel):
    status: Literal["ACTIVE", "PENDING", "DISABLED"]


def _error_code(exc: HTTPException) -> str:
    if isinstance(exc.detail, dict):
        return str(exc.detail.get("code") or "IAM_PLATFORM_OPERATION_REJECTED")
    return "IAM_PLATFORM_OPERATION_REJECTED"


def _audit_platform(
    db: Session,
    *,
    event: IdentityAuditEvent | str,
    context: CurrentContext | None,
    request: Request | None,
    outcome: str = "SUCCESS",
    target_user_id: int | None = None,
    old_value: dict | None = None,
    new_value: dict | None = None,
    detail: str | None = None,
) -> None:
    audit_service.write_authorization_audit(
        db,
        action=str(event),
        outcome=outcome,
        actor_user_id=context.user_id if context else None,
        target_user_id=target_user_id,
        tenant_id=None,
        request=request,
        old_value=old_value,
        new_value=new_value,
        detail=detail,
    )


def _grant_summary(grant, user) -> PlatformGrantSummary:
    return PlatformGrantSummary(
        grant_id=grant.id,
        user_id=user.id,
        email=user.email,
        display_name=user.display_name,
        local_status=user.status,
        email_verified=bool(user.email_verified),
        verification_required=bool(user.verification_required),
        role=grant.role,
        grant_status=grant.status,
        is_effective=platform_service.is_effective_platform_administrator(user, grant),
        created_at=grant.created_at,
        created_by_user_id=grant.created_by_user_id,
        updated_at=grant.updated_at,
    )


def _user_summary(user, grant, active_tenant_count: int) -> PlatformUserSummary:
    return PlatformUserSummary(
        id=user.id,
        email=user.email,
        display_name=user.display_name,
        user_principal_name=user.user_principal_name,
        employee_id=user.employee_id,
        department=user.department,
        local_status=user.status,
        email_verified=bool(user.email_verified),
        verification_required=bool(user.verification_required),
        is_platform_admin=platform_service.is_effective_platform_administrator(
            user, grant
        ),
        platform_grant_status=grant.status if grant else None,
        active_tenant_count=int(active_tenant_count),
        created_at=user.created_at,
        last_login_at=user.last_login_at,
    )


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


@router.get("/users/search", response_model=UserSearchResponse)
def search_platform_users(
    q: str = Query(..., min_length=1, max_length=200),
    tenant_id: int | None = Query(default=None, ge=1),
    context: CurrentContext = Depends(
        require_platform_permission("platform:user:read")
    ),
    db: Session = Depends(get_db),
) -> UserSearchResponse:
    pattern = f"%{platform_service._escape_search(q.strip())}%"
    users = (
        db.query(IAMUser)
        .filter(
            or_(
                IAMUser.email.ilike(pattern, escape="\\"),
                IAMUser.display_name.ilike(pattern, escape="\\"),
                IAMUser.user_principal_name.ilike(pattern, escape="\\"),
            )
        )
        .order_by(IAMUser.display_name.asc(), IAMUser.email.asc())
        .limit(20)
        .all()
    )

    items = []
    for user in users:
        grant = platform_service.get_platform_user_grant(db, user.id)
        is_admin = platform_service.is_effective_platform_administrator(user, grant)
        brief = None
        if tenant_id:
            membership = (
                db.query(TenantUser)
                .filter(TenantUser.tenant_id == tenant_id, TenantUser.user_id == user.id)
                .first()
            )
            if membership:
                brief = TenantMembershipBrief(
                    tenant_id=tenant_id,
                    status=membership.status,
                    role=membership.role,
                )
        items.append(
            UserSearchResult(
                id=user.id,
                email=user.email,
                display_name=user.display_name,
                username=user.user_principal_name,
                status=user.status,
                email_verified=bool(user.email_verified),
                verification_required=bool(user.verification_required),
                external_issuer=user.external_iam_issuer,
                external_subject=user.external_iam_user_id,
                is_platform_admin=is_admin,
                tenant_membership=brief,
            )
        )
    return UserSearchResponse(items=items)


@router.get("/users", response_model=PlatformUserPage)
def list_platform_users(
    request: Request,
    page: int = Query(default=1, ge=1),
    page_size: int = Query(default=50, ge=1, le=100),
    search: str | None = Query(default=None, min_length=1, max_length=200),
    local_status: Literal["ACTIVE", "PENDING", "DISABLED"] | None = None,
    email_verified: bool | None = None,
    verification_required: bool | None = None,
    is_platform_admin: bool | None = None,
    tenant_id: int | None = Query(default=None, ge=1),
    created_from: datetime | None = None,
    created_to: datetime | None = None,
    last_login_from: datetime | None = None,
    last_login_to: datetime | None = None,
    context: CurrentContext = Depends(
        require_platform_permission("platform:user:read")
    ),
    db: Session = Depends(get_db),
) -> PlatformUserPage:
    if created_from and created_to and created_from > created_to:
        raise HTTPException(
            status_code=422,
            detail="created_from must not be later than created_to",
        )
    if last_login_from and last_login_to and last_login_from > last_login_to:
        raise HTTPException(
            status_code=422,
            detail="last_login_from must not be later than last_login_to",
        )
    result = platform_service.list_platform_users(
        db,
        page=page,
        page_size=page_size,
        search=search,
        local_status=local_status,
        email_verified=email_verified,
        verification_required=verification_required,
        is_platform_admin=is_platform_admin,
        tenant_id=tenant_id,
        created_from=created_from,
        created_to=created_to,
        last_login_from=last_login_from,
        last_login_to=last_login_to,
    )
    _audit_platform(
        db,
        event=IdentityAuditEvent.PLATFORM_USER_LIST_VIEWED,
        context=context,
        request=request,
        new_value={
            "page": page,
            "page_size": page_size,
            "result_count": len(result.items),
            "search_applied": bool(search),
            "filters_applied": any(
                value is not None
                for value in (
                    local_status,
                    email_verified,
                    verification_required,
                    is_platform_admin,
                    tenant_id,
                    created_from,
                    created_to,
                    last_login_from,
                    last_login_to,
                )
            ),
        },
    )
    db.commit()
    return PlatformUserPage(
        items=[
            _user_summary(user, grant, active_count)
            for user, grant, active_count in result.items
        ],
        page=result.page,
        page_size=result.page_size,
        total=result.total,
        total_pages=result.total_pages,
    )


@router.get("/users/{user_id}", response_model=PlatformUserDetail)
def get_platform_user(
    user_id: int,
    request: Request,
    context: CurrentContext = Depends(
        require_platform_permission("platform:user:read")
    ),
    db: Session = Depends(get_db),
) -> PlatformUserDetail:
    user, grant, memberships, active_count = platform_service.get_platform_user(
        db, user_id
    )
    _audit_platform(
        db,
        event=IdentityAuditEvent.PLATFORM_USER_DETAIL_VIEWED,
        context=context,
        request=request,
        target_user_id=user.id,
    )
    db.commit()
    summary = _user_summary(user, grant, active_count)
    return PlatformUserDetail(
        **summary.model_dump(),
        platform_grant=_grant_summary(grant, user) if grant else None,
        tenant_memberships=[
            PlatformTenantMembershipSummary(
                tenant_id=tenant.id,
                tenant_name=tenant.name,
                tenant_slug=tenant.slug,
                membership_status=membership.status,
                current_role=membership.role,
                tenant_status=tenant.status,
            )
            for membership, tenant in memberships
        ],
    )


@router.get("/administrators", response_model=PlatformAdministratorPage)
def list_platform_administrators(
    request: Request,
    page: int = Query(default=1, ge=1),
    page_size: int = Query(default=50, ge=1, le=100),
    context: CurrentContext = Depends(
        require_platform_permission("platform:administrator:read")
    ),
    db: Session = Depends(get_db),
) -> PlatformAdministratorPage:
    result = platform_service.list_platform_administrators(
        db, page=page, page_size=page_size
    )
    _audit_platform(
        db,
        event=IdentityAuditEvent.PLATFORM_ADMIN_LIST_VIEWED,
        context=context,
        request=request,
        new_value={
            "page": page,
            "page_size": page_size,
            "result_count": len(result.items),
        },
    )
    db.commit()
    return PlatformAdministratorPage(
        items=[_grant_summary(grant, user) for grant, user in result.items],
        page=result.page,
        page_size=result.page_size,
        total=result.total,
        total_pages=result.total_pages,
    )


@router.post(
    "/administrators",
    status_code=201,
    response_model=PlatformAdministratorGrantResponse,
)
def grant_platform_administrator(
    payload: PlatformAdministratorGrantRequest,
    request: Request,
    context: CurrentContext = Depends(
        require_platform_permission("platform:administrator:grant")
    ),
    db: Session = Depends(get_db),
) -> PlatformAdministratorGrantResponse:
    try:
        mutation = platform_service.grant_platform_administrator(
            db,
            user_id=payload.user_id,
            external_iam_user_id=payload.external_user_id,
            created_by_user_id=context.user_id,
        )
    except HTTPException as exc:
        _audit_platform(
            db,
            event=IdentityAuditEvent.PLATFORM_ADMIN_GRANT_REJECTED,
            context=context,
            request=request,
            outcome="DENIED",
            detail=_error_code(exc),
        )
        db.commit()
        raise
    if mutation.action != "EXISTING":
        event = (
            IdentityAuditEvent.PLATFORM_ADMIN_GRANTED
            if mutation.action == "CREATED"
            else IdentityAuditEvent.PLATFORM_ADMIN_GRANT_REACTIVATED
        )
        _audit_platform(
            db,
            event=event,
            context=context,
            request=request,
            target_user_id=mutation.user.id,
            old_value=mutation.old_state,
            new_value={"role": mutation.grant.role, "status": mutation.grant.status},
        )
    db.commit()
    invalidate_user_contexts(mutation.user.id)
    summary = _grant_summary(mutation.grant, mutation.user)
    return PlatformAdministratorGrantResponse(
        **summary.model_dump(),
        action=mutation.action,
    )


@router.delete("/administrators/{grant_id}", status_code=204)
def revoke_platform_administrator(
    grant_id: int,
    request: Request,
    context: CurrentContext = Depends(
        require_platform_permission("platform:administrator:revoke")
    ),
    db: Session = Depends(get_db),
) -> None:
    try:
        mutation = platform_service.revoke_platform_administrator(db, grant_id)
    except HTTPException as exc:
        event = (
            IdentityAuditEvent.PLATFORM_ADMIN_LAST_ADMIN_PROTECTED
            if _error_code(exc)
            == str(IdentityErrorCode.LAST_PLATFORM_ADMIN_PROTECTED)
            else IdentityAuditEvent.PLATFORM_ADMIN_GRANT_REJECTED
        )
        _audit_platform(
            db,
            event=event,
            context=context,
            request=request,
            outcome="DENIED",
            new_value={"grant_id": grant_id},
            detail=_error_code(exc),
        )
        db.commit()
        raise
    if mutation.action == "REVOKED":
        _audit_platform(
            db,
            event=IdentityAuditEvent.PLATFORM_ADMIN_REVOKED,
            context=context,
            request=request,
            target_user_id=mutation.user.id,
            old_value=mutation.old_state,
            new_value={
                "role": mutation.grant.role,
                "status": mutation.grant.status,
            },
        )
    db.commit()
    invalidate_user_contexts(mutation.user.id)


def _change_user_status(
    user_id: int,
    payload: PlatformUserStatusUpdate,
    request: Request,
    context: CurrentContext,
    db: Session,
) -> PlatformUserStatusResponse:
    try:
        mutation = platform_service.update_user_status(db, user_id, payload.status)
    except HTTPException as exc:
        error_code = _error_code(exc)
        if error_code in {
            str(IdentityErrorCode.LAST_PLATFORM_ADMIN_PROTECTED),
            str(IdentityErrorCode.LAST_TENANT_ADMIN_PROTECTED),
        }:
            _audit_platform(
                db,
                event=(
                    IdentityAuditEvent.PLATFORM_ADMIN_LAST_ADMIN_PROTECTED
                    if error_code
                    == str(IdentityErrorCode.LAST_PLATFORM_ADMIN_PROTECTED)
                    else IdentityAuditEvent.TENANT_ROLE_LAST_ADMIN_PROTECTED
                ),
                context=context,
                request=request,
                outcome="DENIED",
                target_user_id=user_id,
                detail=error_code,
            )
            db.commit()
        raise
    if mutation.changed:
        event = {
            ("PENDING", "ACTIVE"): IdentityAuditEvent.PLATFORM_USER_ACTIVATED,
            ("ACTIVE", "DISABLED"): IdentityAuditEvent.PLATFORM_USER_DISABLED,
            ("DISABLED", "ACTIVE"): IdentityAuditEvent.PLATFORM_USER_REACTIVATED,
        }[(mutation.old_status, mutation.user.status)]
        _audit_platform(
            db,
            event=event,
            context=context,
            request=request,
            target_user_id=mutation.user.id,
            old_value={"status": mutation.old_status},
            new_value={"status": mutation.user.status},
            detail=payload.reason,
        )
        _audit_platform(
            db,
            event=IdentityAuditEvent.PLATFORM_USER_STATUS_CHANGED,
            context=context,
            request=request,
            target_user_id=mutation.user.id,
            old_value={"status": mutation.old_status},
            new_value={"status": mutation.user.status},
        )
    db.commit()
    invalidate_user_contexts(mutation.user.id)

    delivery_status = None
    if (
        mutation.changed
        and mutation.user.status == "ACTIVE"
        and (not mutation.user.email_verified or mutation.user.verification_required)
    ):
        delivery = ensure_initial_verification_delivery(
            db, mutation.user, request=request
        )
        delivery_status = delivery.status if delivery else None
        db.refresh(mutation.user)
    return PlatformUserStatusResponse(
        user_id=mutation.user.id,
        old_status=mutation.old_status,
        status=mutation.user.status,
        changed=mutation.changed,
        verification_required=bool(mutation.user.verification_required),
        email_verified=bool(mutation.user.email_verified),
        verification_delivery_status=delivery_status,
    )


@router.patch(
    "/users/{user_id}/status",
    response_model=PlatformUserStatusResponse,
)
def update_iam_user_status(
    user_id: int,
    payload: PlatformUserStatusUpdate,
    request: Request,
    context: CurrentContext = Depends(
        require_platform_permission("platform:user:manage_status")
    ),
    db: Session = Depends(get_db),
) -> PlatformUserStatusResponse:
    return _change_user_status(user_id, payload, request, context, db)


@router.patch(
    "/users/{user_id}",
    response_model=PlatformUserStatusResponse,
    deprecated=True,
)
def update_iam_user_status_compatibility(
    user_id: int,
    payload: PlatformUserStatusUpdate,
    request: Request,
    context: CurrentContext = Depends(
        require_platform_permission("platform:user:manage_status")
    ),
    db: Session = Depends(get_db),
) -> PlatformUserStatusResponse:
    """Compatibility alias retained for existing API clients."""
    return _change_user_status(user_id, payload, request, context, db)


@router.get("/tenants")
def list_platform_tenants(
    _context: CurrentContext = Depends(
        require_platform_permission("platform:tenant:create")
    ),
    db: Session = Depends(get_db),
) -> list[dict]:
    return [
        _tenant_dict(tenant)
        for tenant in platform_service.list_platform_tenants(db)
    ]


@router.patch("/tenants/{tenant_id}")
def update_tenant_status(
    tenant_id: int,
    payload: TenantStatusUpdate,
    request: Request,
    context: CurrentContext = Depends(
        require_platform_permission("platform:admin")
    ),
    db: Session = Depends(get_db),
) -> dict:
    tenant, old_status = platform_service.update_tenant_status(
        db, tenant_id, payload.status
    )
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

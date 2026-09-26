"""Centralized, database-authoritative platform administration APIs."""

from __future__ import annotations

from datetime import datetime
from typing import Literal

from fastapi import APIRouter, Depends, HTTPException, Query, Request
from pydantic import BaseModel
from sqlalchemy import func, or_
from sqlalchemy.orm import Session

from ..core.context import CurrentContext
from ..core.identity_states import (
    IdentityAuditEvent,
    IdentityErrorCode,
)
from ..core.native_identity import AccountStatus
from ..core.security import invalidate_user_contexts, require_platform_permission
from ..db import get_db
from ..models import AuthorizationAuditLog, IAMUser, Tenant, TenantUser
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
from ..schemas_user_management import ProfileUpdate
from ..services import audit_service, platform_service
from ..services import tenant_role_assignment_service as tras
from ..services import user_management_service as ums
from ..services.email_verification_service import ensure_initial_verification_delivery

router = APIRouter(prefix="/api/platform", tags=["platform-identity"])


class TenantStatusUpdate(BaseModel):
    status: Literal["ACTIVE", "DISABLED"]


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


def _user_summary(db, user, grant, active_tenant_count: int) -> PlatformUserSummary:
    return PlatformUserSummary(
        id=user.id,
        first_name=user.first_name, last_name=user.last_name, phone=user.phone,
        providers=ums.providers(db, user), updated_at=user.updated_at, account_status=user.status,
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


from ..services.identity_mapping_service import build_identity_mapping


def _tenant_dict(tenant) -> dict:
    return {
        "id": tenant.id,
        "name": tenant.name,
        "slug": tenant.slug,
        "external_iam_tenant_id": tenant.external_iam_tenant_id,
        "identity_mapping": build_identity_mapping(
            tenant.external_iam_tenant_id,
            is_legacy=getattr(tenant, "is_legacy", False),
        ),
        "status": tenant.status,
        "created_at": tenant.created_at,
        "updated_at": tenant.updated_at,
    }


def _platform_tenant_dict(db: Session, tenant: Tenant) -> dict:
    item = _tenant_dict(tenant)
    item["member_count"] = int(
        db.query(func.count(TenantUser.id))
        .filter(TenantUser.tenant_id == tenant.id)
        .scalar()
        or 0
    )
    assignment_audit = (
        db.query(AuthorizationAuditLog)
        .filter(
            AuthorizationAuditLog.tenant_id == tenant.id,
            AuthorizationAuditLog.action
            == str(IdentityAuditEvent.TENANT_INITIAL_ADMIN_ASSIGNED),
            AuthorizationAuditLog.outcome == "SUCCESS",
        )
        .order_by(AuthorizationAuditLog.id)
        .first()
    )
    initial_admin = (
        db.get(IAMUser, assignment_audit.target_user_id)
        if assignment_audit and assignment_audit.target_user_id
        else None
    )
    item["initial_administrator"] = (
        {
            "user_id": initial_admin.id,
            "display_name": initial_admin.display_name,
            "email": initial_admin.email,
        }
        if initial_admin is not None
        else None
    )
    current_administrators = []
    membership_rows = (
        db.query(TenantUser, IAMUser)
        .join(IAMUser, IAMUser.id == TenantUser.user_id)
        .filter(
            TenantUser.tenant_id == tenant.id,
            TenantUser.status == "ACTIVE",
            IAMUser.status == "ACTIVE",
            IAMUser.email_verified.is_(True),
            IAMUser.verification_required.is_(False),
        )
        .order_by(IAMUser.display_name, IAMUser.email)
        .all()
    )
    for membership, user in membership_rows:
        if "TENANT_ADMIN" in tras.effective_role_codes(db, membership):
            current_administrators.append(
                {
                    "user_id": user.id,
                    "display_name": user.display_name,
                    "email": user.email,
                }
            )
    item["current_administrators"] = current_administrators
    return item


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
        grant = platform_service.get_active_platform_grant(db, user.id)
        is_admin = platform_service.is_effective_platform_administrator(user, grant)
        brief = None
        membership_rows = (
            db.query(TenantUser, Tenant)
            .join(Tenant, Tenant.id == TenantUser.tenant_id)
            .filter(TenantUser.user_id == user.id)
            .order_by(Tenant.name)
            .all()
        )
        membership_briefs = [
            TenantMembershipBrief(
                tenant_id=membership.tenant_id,
                tenant_name=tenant.name,
                status=membership.status,
                role=membership.role,
                roles=sorted(
                    tras.effective_role_codes(db, membership)
                ),
            )
            for membership, tenant in membership_rows
        ]
        if tenant_id:
            membership = (
                db.query(TenantUser)
                .filter(TenantUser.tenant_id == tenant_id, TenantUser.user_id == user.id)
                .first()
            )
            if membership:
                brief = TenantMembershipBrief(
                    tenant_id=tenant_id,
                    tenant_name=next(
                        (
                            tenant.name
                            for row, tenant in membership_rows
                            if row.id == membership.id
                        ),
                        None,
                    ),
                    status=membership.status,
                    role=membership.role,
                    roles=sorted(
                        tras.effective_role_codes(db, membership)
                    ),
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
                external_issuer=user.external_issuer,
                external_subject=user.effective_external_subject,
                is_platform_admin=is_admin,
                tenant_membership=brief,
                tenant_memberships=membership_briefs,
            )
        )
    return UserSearchResponse(items=items)


@router.get("/users", response_model=PlatformUserPage)
def list_platform_users(
    request: Request,
    page: int = Query(default=1, ge=1),
    page_size: int = Query(default=50, ge=1, le=100),
    search: str | None = Query(default=None, min_length=1, max_length=200),
    local_status: AccountStatus | None = None,
    role: str | None = Query(default=None, max_length=64),
    provider: Literal["NATIVE", "HCL_CS"] | None = None,
    sort_by: Literal["name", "email", "created_at", "last_login_at"] = "created_at",
    sort_order: Literal["asc", "desc"] = "desc",
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
        search=search, role=role, provider=provider, sort_by=sort_by, sort_order=sort_order,
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
            _user_summary(db, user, grant, active_count)
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
    summary = _user_summary(db, user, grant, active_count)
    return PlatformUserDetail(
        **summary.model_dump(),
        security=ums.security_summary(db, user.id),
        activity=ums.audit_history(db, user.id, page_size=50),
        platform_grant=_grant_summary(grant, user) if grant else None,
        tenant_memberships=[
            PlatformTenantMembershipSummary(**ums.membership_summary(db, membership, tenant))
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
        from ..services.account_state_service import InvalidAccountTransition, transition_account
        with db.begin_nested():
            # Preserve legacy approval/idempotence, but centralize actual account
            # lifecycle transitions and required audit/token invalidation.
            initial = platform_service.lock_account_for_administration(db, user_id, removing_access=payload.status == "DISABLED")
            if initial is None:
                raise HTTPException(404, "User not found")
            if initial.status == "PENDING" or initial.status == payload.status:
                mutation = platform_service.update_user_status(db, user_id, payload.status)
            else:
                old_status = initial.status
                try:
                    changed_user = transition_account(db, user_id, payload.status,
                        actor_user_id=context.user_id, explicitly_authorized=True)
                except InvalidAccountTransition as exc:
                    raise HTTPException(409, str(exc)) from None
                mutation = platform_service.StatusMutation(changed_user, old_status, True)
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
        }.get((mutation.old_status, mutation.user.status), IdentityAuditEvent.PLATFORM_USER_STATUS_CHANGED)
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
        _platform_tenant_dict(db, tenant)
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
    audit_service.write_authorization_audit(
        db,
        action=str(
            IdentityAuditEvent.TENANT_ENABLED
            if tenant.status == "ACTIVE"
            else IdentityAuditEvent.TENANT_DISABLED
        ),
        context=context,
        tenant_id=tenant.id,
        request=request,
        old_value={"status": old_status},
        new_value={"status": tenant.status},
    )
    db.commit()
    return {"tenant_id": tenant.id, "status": tenant.status}


@router.patch('/users/{user_id}/profile')
def edit_user_profile(user_id: int, payload: ProfileUpdate,
                      context: CurrentContext = Depends(require_platform_permission('platform:user:write')),
                      db: Session = Depends(get_db)):
    user = ums.update_profile(db, user_id, payload.model_dump(exclude_unset=True), actor_user_id=context.user_id)
    db.commit()
    return ums.profile(db, user)


@router.get('/users/{user_id}/audit')
def user_audit(user_id: int, page: int = Query(default=1, ge=1), page_size: int = Query(default=50, ge=1, le=100),
               context: CurrentContext = Depends(require_platform_permission('platform:user:read')),
               db: Session = Depends(get_db)):
    platform_service.get_platform_user(db, user_id)
    return ums.audit_history(db, user_id, page=page, page_size=page_size)


@router.post('/users/{user_id}/unlock')
def unlock_user(user_id: int,
                context: CurrentContext = Depends(require_platform_permission('platform:user:manage_status')),
                db: Session = Depends(get_db)):
    return _security_action(db, context, user_id, 'unlock')


@router.post('/users/{user_id}/force-password-change')
def force_password_change(user_id: int,
                          context: CurrentContext = Depends(require_platform_permission('platform:user:manage_status')),
                          db: Session = Depends(get_db)):
    return _security_action(db, context, user_id, 'force-password-change')


def _security_action(db, context, user_id, action):
    from sqlalchemy import select

    from ..models import NativeUserCredential
    from ..services.account_state_service import InvalidAccountTransition, transition_account
    try:
        # Force-change locks follow the central tenant->user order. Eligibility
        # is checked again by the lifecycle service while holding the user lock.
        if action == 'unlock':
            user = db.scalar(select(IAMUser).where(IAMUser.id == user_id).with_for_update()
                             .execution_options(populate_existing=True))
            if not user or user.status != 'LOCKED':
                raise HTTPException(409, 'Only locked accounts may be unlocked')
            target = 'ACTIVE'
        else:
            if not db.scalar(select(NativeUserCredential.id).where(NativeUserCredential.user_id == user_id)):
                raise HTTPException(409, 'An enrolled native account is required')
            target = 'FORCE_PASSWORD_CHANGE'
        user = transition_account(db, user_id, target, actor_user_id=context.user_id, explicitly_authorized=True)
        db.commit()
        return {'user_id': user.id, 'status': user.status}
    except InvalidAccountTransition as exc:
        db.rollback()
        raise HTTPException(409, str(exc)) from None

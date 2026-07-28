from __future__ import annotations

from typing import Literal

from fastapi import APIRouter, Body, Depends, Header, HTTPException, Query, Request
from pydantic import AliasChoices, BaseModel, Field
from sqlalchemy.orm import Session

from ..core.context import CurrentContext
from ..core.identity_states import (
    IdentityAuditEvent,
    IdentityErrorCode,
    identity_http_error,
)
from ..core.security import (
    _claim,
    _roles,
    get_current_tenant_context,
    get_current_user,
    invalidate_user_contexts,
    require_permission,
    require_platform_permission,
)
from sqlalchemy import or_
from ..db import get_db
from ..schemas_platform import (
    TenantMembershipBrief,
    UserSearchResponse,
    UserSearchResult,
)
from ..models import AuthorizationRole, IAMUser, Tenant, TenantUser
from ..schemas_identity import AuthContextResponse
from ..schemas_tenants import (
    CreatedTenantResponse,
    InitialTenantAdministratorResponse,
    TenantCreateRequest,
    TenantCreationResponse,
)
from ..services import audit_service
from ..services import tenant_role_assignment_service as tras
from ..services import tenant_service as ts
from ..services.auth_context_service import (
    build_auth_context_response,
    resolve_authorization_state,
)
from ..services.email_verification_service import ensure_initial_verification_delivery
from ..services.identity_service import provision_local_identity
from ..settings import get_settings

router = APIRouter(prefix="/api", tags=["identity"])

TenantRole = Literal["TENANT_ADMIN", "SECURITY_ANALYST", "DEVELOPER", "VIEWER"]
MembershipStatus = Literal["ACTIVE", "PENDING", "DISABLED"]


class MembershipUpsert(BaseModel):
    user_id: int | None = Field(default=None, ge=1)
    external_user_id: str | None = Field(
        default=None,
        min_length=1,
        max_length=255,
        validation_alias=AliasChoices("external_user_id", "external_iam_user_id"),
    )
    role: str = Field(min_length=1, max_length=64)
    status: MembershipStatus = "ACTIVE"


class MembershipUpdate(BaseModel):
    role: str | None = Field(default=None, min_length=1, max_length=64)
    status: MembershipStatus | None = None
    replace_all_roles: bool = False


class TenantRoleGrantRequest(BaseModel):
    role_code: str = Field(min_length=1, max_length=64)
    expected_version: int = Field(ge=1)
    make_primary: bool = False
    reason: str | None = Field(default=None, max_length=512)


class TenantRoleSetRequest(BaseModel):
    role_codes: list[str]
    primary_role_code: str | None = Field(default=None, max_length=64)
    expected_version: int = Field(ge=1)
    reason: str | None = Field(default=None, max_length=512)


class TenantRoleRevokeRequest(BaseModel):
    expected_version: int = Field(ge=1)
    replacement_primary_role_code: str | None = Field(default=None, max_length=64)
    reason: str | None = Field(default=None, max_length=512)


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


def _membership_dict(membership, user, roles: list[str] | None = None) -> dict:
    return {
        "membership_id": membership.id,
        "user_id": user.id,
        "external_iam_user_id": user.external_iam_user_id,
        "email": user.email,
        "display_name": user.display_name,
        "user_status": user.status,
        "role": membership.role,
        "roles": roles or [membership.role],
        "role_assignment_version": membership.role_assignment_version,
        "status": membership.status,
    }


def _assignment_http_error(exc: tras.AssignmentProblem) -> HTTPException:
    detail = {"code": str(exc.code), "message": exc.message}
    if exc.current_version is not None:
        detail["current_version"] = exc.current_version
    return HTTPException(status_code=exc.status_code, detail=detail)


def _audit_assignment_rejection(
    db: Session,
    *,
    exc: tras.AssignmentProblem,
    context: CurrentContext,
    tenant_id: int,
    user_id: int,
    request: Request,
) -> None:
    audit_service.write_authorization_audit(
        db,
        action=str(IdentityAuditEvent.TENANT_ROLE_ASSIGNMENT_REJECTED),
        outcome="DENIED",
        context=context,
        target_user_id=user_id,
        tenant_id=tenant_id,
        request=request,
        new_value={
            "reason_code": str(exc.code),
            "current_version": exc.current_version,
        },
        detail=str(exc.code),
    )
    db.commit()


def _role_state(db: Session, tenant_id: int, user_id: int) -> dict:
    membership, rows = tras.list_assignments(db, tenant_id, user_id)
    roles = [
        {
            "assignment_id": assignment.id,
            "role_id": role.id,
            "role_code": role.code,
            "role_name": role.name,
            "role_status": role.status,
            "assignment_status": assignment.status,
            "is_primary": assignment.is_primary,
            "assignment_source": assignment.assignment_source,
            "assigned_at": assignment.assigned_at,
            "assigned_by_user_id": assignment.assigned_by_user_id,
            "revoked_at": assignment.revoked_at,
            "version": assignment.version,
        }
        for assignment, role in rows
    ]
    return {
        "membership_id": membership.id,
        "user_id": membership.user_id,
        "membership_status": membership.status,
        "role_assignment_version": membership.role_assignment_version,
        "primary_role": membership.role,
        "roles": roles,
        "effective_permissions": sorted(
            tras.effective_permissions(db, membership, actor_user_id=membership.user_id)
        ),
    }


def _require_current_tenant(tenant_id: int, context: CurrentContext) -> None:
    if context.tenant_id is None or tenant_id != context.tenant_id:
        raise HTTPException(status_code=404, detail="Tenant membership not found")


@router.get("/auth/me")
@router.get("/v1/auth/me")
def auth_me(
    request: Request,
    claims: dict = Depends(get_current_user),
    x_tenant_id: str | None = Header(default=None, alias="X-Tenant-ID"),
    db: Session = Depends(get_db),
) -> dict:
    try:
        provisioned = provision_local_identity(db, claims, request=request)
        db.commit()
        ensure_initial_verification_delivery(db, provisioned.user, request=request)
        db.refresh(provisioned.user)
        state = resolve_authorization_state(
            db,
            provisioned.user,
            selected_tenant=x_tenant_id,
            allow_platform_context=True,
            request=request,
            audit_resolution=True,
        )
    except HTTPException:
        db.commit()
        raise
    auth_context = build_auth_context_response(state, db=db)
    membership = state.active_membership
    roles = (
        set(
            tras.effective_role_codes(
                db,
                membership,
                actor_user_id=provisioned.user.id,
                request=request,
            )
        )
        if membership
        else set()
    )
    if state.is_platform_admin:
        roles.add("PLATFORM_ADMIN")
    permissions = (
        auth_context.tenant_context.active_tenant.effective_permissions
        if auth_context.tenant_context.active_tenant
        else auth_context.platform.permissions
    )
    response = {
        "user_id": provisioned.user.id,
        "external_user_id": provisioned.user.external_iam_user_id,
        "email": provisioned.user.email,
        "display_name": provisioned.user.display_name,
        "tenant_id": state.active_tenant.id if state.active_tenant else None,
        "external_tenant_id": (
            state.active_tenant.external_iam_tenant_id if state.active_tenant else None
        ),
        "roles": sorted(roles),
        "identity_roles": sorted(_roles(_claim(claims, get_settings().hcl_iam_role_claim))),
        "permissions": permissions,
        "is_platform_admin": state.is_platform_admin,
        "authenticated": True,
        "role": (
            membership.role
            if membership is not None
            else "PLATFORM_ADMIN"
            if state.is_platform_admin
            else None
        ),
        "auth_context": auth_context.model_dump(mode="json"),
    }
    db.commit()
    return response


@router.get("/auth/context", response_model=AuthContextResponse)
def auth_context(
    request: Request,
    claims: dict = Depends(get_current_user),
    x_tenant_id: str | None = Header(default=None, alias="X-Tenant-ID"),
    db: Session = Depends(get_db),
) -> AuthContextResponse:
    try:
        provisioned = provision_local_identity(db, claims, request=request)
        db.commit()
        ensure_initial_verification_delivery(db, provisioned.user, request=request)
        db.refresh(provisioned.user)
        state = resolve_authorization_state(
            db,
            provisioned.user,
            selected_tenant=x_tenant_id,
            allow_platform_context=True,
            request=request,
            audit_resolution=True,
        )
        response = build_auth_context_response(state, db=db)
    except HTTPException:
        db.commit()
        raise
    db.commit()
    return response


@router.get("/tenants")
def list_my_tenants(
    context: CurrentContext = Depends(get_current_tenant_context),
    db: Session = Depends(get_db),
) -> list[dict]:
    rows = ts.get_available_tenants_for_user(db, context.user_id, context.is_platform_admin)
    return [_tenant_dict(tenant, role) for tenant, role in rows]


@router.post("/tenants", status_code=201, response_model=TenantCreationResponse)
def create_tenant(
    payload: TenantCreateRequest,
    request: Request,
    context: CurrentContext = Depends(
        require_platform_permission("platform:tenant:create")
    ),
    db: Session = Depends(get_db),
) -> TenantCreationResponse:
    if (
        payload.initial_admin_user_id is None
        or payload.initial_admin_user_id < 1
    ):
        failure_value = {
            "name": payload.name[:255],
            "slug": payload.slug[:128],
            "reason_code": str(
                IdentityErrorCode.INITIAL_TENANT_ADMIN_REQUIRED
            ),
        }
        for action in (
            IdentityAuditEvent.PLATFORM_TENANT_CREATE_FAILED,
            IdentityAuditEvent.TENANT_CREATION_ROLLED_BACK,
        ):
            audit_service.write_authorization_audit(
                db,
                action=str(action),
                outcome="FAILED",
                actor_user_id=context.user_id,
                tenant_id=None,
                request=request,
                new_value=failure_value,
                detail=str(IdentityErrorCode.INITIAL_TENANT_ADMIN_REQUIRED),
            )
        db.commit()
        raise identity_http_error(
            IdentityErrorCode.INITIAL_TENANT_ADMIN_REQUIRED,
            "An initial Tenant Administrator is required.",
            status_code=422,
        )
    try:
        result = ts.create_tenant_with_initial_admin(
            db,
            actor_user_id=context.user_id,
            name=payload.name,
            slug=payload.slug,
            external_iam_tenant_id=payload.external_iam_tenant_id,
            initial_admin_user_id=payload.initial_admin_user_id,
            request=request,
        )
    except ts.TenantCreationError as exc:
        raise identity_http_error(
            exc.code,
            exc.message,
            status_code=exc.status_code,
        ) from exc
    return TenantCreationResponse(
        tenant=CreatedTenantResponse.model_validate(
            {
                "id": result.tenant.id,
                "name": result.tenant.name,
                "slug": result.tenant.slug,
                "external_iam_tenant_id": result.tenant.external_iam_tenant_id,
                "status": result.tenant.status,
                "created_at": result.tenant.created_at,
                "updated_at": result.tenant.updated_at,
            }
        ),
        initial_administrator=InitialTenantAdministratorResponse(
            user_id=result.initial_admin.id,
            email=result.initial_admin.email,
            display_name=result.initial_admin.display_name,
            membership_status=result.membership.status,
            role=result.membership.role,
        ),
    )


@router.get("/tenant-roles")
def list_assignable_tenant_roles(
    _context: CurrentContext = Depends(require_permission("tenant:user:read")),
    db: Session = Depends(get_db),
) -> dict:
    roles = db.query(AuthorizationRole).filter(
        AuthorizationRole.scope == "TENANT",
        AuthorizationRole.status == "ACTIVE",
        AuthorizationRole.is_assignable.is_(True),
    ).order_by(AuthorizationRole.code).all()
    return {
        "roles": [
            {"id": role.id, "code": role.code, "name": role.name}
            for role in roles
        ]
    }


@router.get("/tenants/{tenant_id}/users/{user_id}/roles")
def list_tenant_user_roles(
    tenant_id: int,
    user_id: int,
    context: CurrentContext = Depends(require_permission("tenant:user:read")),
    db: Session = Depends(get_db),
) -> dict:
    _require_current_tenant(tenant_id, context)
    try:
        return _role_state(db, tenant_id, user_id)
    except tras.AssignmentProblem as exc:
        raise _assignment_http_error(exc) from exc


@router.post("/tenants/{tenant_id}/users/{user_id}/roles")
def grant_tenant_user_role(
    tenant_id: int,
    user_id: int,
    payload: TenantRoleGrantRequest,
    request: Request,
    context: CurrentContext = Depends(require_permission("tenant:user:update")),
    db: Session = Depends(get_db),
) -> dict:
    _require_current_tenant(tenant_id, context)
    try:
        tras.grant_role(
            db,
            tenant_id,
            user_id,
            role_code=payload.role_code,
            expected_version=payload.expected_version,
            make_primary=payload.make_primary,
            reason=payload.reason,
            actor_user_id=context.user_id,
            is_platform_admin=context.is_platform_admin,
            request=request,
        )
        result = _role_state(db, tenant_id, user_id)
    except tras.AssignmentProblem as exc:
        _audit_assignment_rejection(
            db,
            exc=exc,
            context=context,
            tenant_id=tenant_id,
            user_id=user_id,
            request=request,
        )
        raise _assignment_http_error(exc) from exc
    invalidate_user_contexts(user_id)
    return result


@router.put("/tenants/{tenant_id}/users/{user_id}/roles")
def replace_tenant_user_roles(
    tenant_id: int,
    user_id: int,
    payload: TenantRoleSetRequest,
    request: Request,
    context: CurrentContext = Depends(require_permission("tenant:user:update")),
    db: Session = Depends(get_db),
) -> dict:
    _require_current_tenant(tenant_id, context)
    try:
        tras.replace_roles(
            db,
            tenant_id,
            user_id,
            role_codes=payload.role_codes,
            primary_role_code=payload.primary_role_code,
            expected_version=payload.expected_version,
            reason=payload.reason,
            actor_user_id=context.user_id,
            is_platform_admin=context.is_platform_admin,
            request=request,
        )
        result = _role_state(db, tenant_id, user_id)
    except tras.AssignmentProblem as exc:
        _audit_assignment_rejection(
            db,
            exc=exc,
            context=context,
            tenant_id=tenant_id,
            user_id=user_id,
            request=request,
        )
        raise _assignment_http_error(exc) from exc
    invalidate_user_contexts(user_id)
    return result


@router.delete("/tenants/{tenant_id}/users/{user_id}/roles/{role_code}")
def revoke_tenant_user_role(
    tenant_id: int,
    user_id: int,
    role_code: str,
    request: Request,
    payload: TenantRoleRevokeRequest = Body(...),
    context: CurrentContext = Depends(require_permission("tenant:user:update")),
    db: Session = Depends(get_db),
) -> dict:
    _require_current_tenant(tenant_id, context)
    try:
        tras.revoke_role(
            db,
            tenant_id,
            user_id,
            role_code=role_code,
            expected_version=payload.expected_version,
            replacement_primary_role_code=payload.replacement_primary_role_code,
            reason=payload.reason,
            actor_user_id=context.user_id,
            is_platform_admin=context.is_platform_admin,
            request=request,
        )
        result = _role_state(db, tenant_id, user_id)
    except tras.AssignmentProblem as exc:
        _audit_assignment_rejection(
            db,
            exc=exc,
            context=context,
            tenant_id=tenant_id,
            user_id=user_id,
            request=request,
        )
        raise _assignment_http_error(exc) from exc
    invalidate_user_contexts(user_id)
    return result


@router.get("/tenants/{tenant_id}/users/{user_id}/roles/history")
def tenant_user_role_history(
    tenant_id: int,
    user_id: int,
    request: Request,
    offset: int = Query(default=0, ge=0),
    limit: int = Query(default=100, ge=1, le=200),
    context: CurrentContext = Depends(require_permission("tenant:user:read")),
    db: Session = Depends(get_db),
) -> dict:
    _require_current_tenant(tenant_id, context)
    try:
        membership, rows = tras.get_history(
            db, tenant_id, user_id, offset=offset, limit=limit
        )
    except tras.AssignmentProblem as exc:
        raise _assignment_http_error(exc) from exc
    audit_service.write_authorization_audit(
        db,
        action=str(IdentityAuditEvent.TENANT_ROLE_HISTORY_VIEWED),
        context=context,
        target_user_id=user_id,
        target_membership_id=membership.id,
        tenant_id=tenant_id,
        request=request,
        new_value={"offset": offset, "limit": limit},
    )
    db.commit()
    return {
        "membership_id": membership.id,
        "role_assignment_version": membership.role_assignment_version,
        "history": [
            {
                "id": row.id,
                "assignment_id": row.assignment_id,
                "role_id": row.role_id,
                "role_code": row.role_code_snapshot,
                "event_type": row.event_type,
                "previous_status": row.previous_status,
                "new_status": row.new_status,
                "previous_primary": row.previous_primary,
                "new_primary": row.new_primary,
                "actor_user_id": row.actor_user_id,
                "assignment_source": row.assignment_source,
                "reason": row.reason,
                "before_membership_version": row.before_membership_version,
                "after_membership_version": row.after_membership_version,
                "correlation_id": row.correlation_id,
                "occurred_at": row.occurred_at,
                "metadata": row.metadata_json,
            }
            for row in rows
        ],
    }


@router.get("/tenants/{tenant_id}/user-candidates", response_model=UserSearchResponse)
def search_tenant_user_candidates(
    tenant_id: int,
    q: str = Query(..., min_length=1, max_length=200),
    context: CurrentContext = Depends(require_permission("tenant:user:read")),
    db: Session = Depends(get_db),
) -> UserSearchResponse:
    _require_current_tenant(tenant_id, context)
    from ..services.platform_service import _escape_search
    pattern = f"%{_escape_search(q.strip())}%"
    users = (
        db.query(IAMUser)
        .filter(
            IAMUser.status != "DISABLED",
            or_(
                IAMUser.email.ilike(pattern, escape="\\"),
                IAMUser.display_name.ilike(pattern, escape="\\"),
                IAMUser.user_principal_name.ilike(pattern, escape="\\"),
            ),
        )
        .order_by(IAMUser.display_name.asc(), IAMUser.email.asc())
        .limit(20)
        .all()
    )

    items = []
    for user in users:
        membership = (
            db.query(TenantUser)
            .filter(TenantUser.tenant_id == tenant_id, TenantUser.user_id == user.id)
            .first()
        )
        brief = None
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
                tenant_membership=brief,
            )
        )
    return UserSearchResponse(items=items)


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
    ext_user_id = payload.external_user_id
    if ext_user_id is None and payload.user_id is not None:
        user_row = db.query(IAMUser).filter(IAMUser.id == payload.user_id).one_or_none()
        if user_row:
            ext_user_id = user_row.external_iam_user_id
    if not ext_user_id:
        raise HTTPException(status_code=422, detail="Provide user_id or external_user_id")

    existing = None
    previous_user_status = None
    user_id = db.query(IAMUser.id).filter(IAMUser.external_iam_user_id == ext_user_id).scalar()
    if user_id is not None:
        previous_user_status = db.query(IAMUser.status).filter(IAMUser.id == user_id).scalar()
        existing = db.query(TenantUser).filter(
            TenantUser.tenant_id == tenant_id,
            TenantUser.user_id == user_id,
        ).one_or_none()
    membership, user = ts.add_user_to_tenant(
        db,
        tenant_id,
        external_iam_user_id=ext_user_id,
        role=payload.role,
        status=payload.status,
        actor_user_id=context.user_id,
        assignment_source=(
            "PLATFORM_ADMIN" if context.is_platform_admin else "TENANT_ADMIN"
        ),
        request=request,
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
    compatibility_old = {"role": membership.role, "status": membership.status}
    compatibility_role_changed = False
    if payload.role is not None:
        active_assignments = tras.active_assignment_count(db, membership.id)
        if active_assignments > 1 and not payload.replace_all_roles:
            raise identity_http_error(
                IdentityErrorCode.MULTI_ROLE_COMPATIBILITY_CONFLICT,
                "This membership has multiple roles; confirm complete replacement.",
                status_code=409,
            )
        try:
            tras.replace_roles(
                db,
                tenant_id,
                user.id,
                role_codes=[payload.role],
                primary_role_code=payload.role,
                expected_version=membership.role_assignment_version,
                reason="Legacy membership role update",
                actor_user_id=context.user_id,
                is_platform_admin=context.is_platform_admin,
                request=request,
            )
        except tras.AssignmentProblem as exc:
            audit_service.write_authorization_audit(
                db,
                action="membership.update_denied",
                outcome="DENIED",
                context=context,
                target_user_id=user.id,
                target_membership_id=membership.id,
                tenant_id=tenant_id,
                request=request,
                detail=str(exc.code),
            )
            db.commit()
            raise _assignment_http_error(exc) from exc
        membership, user = ts.get_tenant_membership(db, tenant_id, membership_id)
        compatibility_role_changed = membership.role != compatibility_old["role"]
    try:
        ts.ensure_not_last_active_tenant_admin(
            db,
            membership,
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
        status=payload.status,
    )
    if compatibility_role_changed:
        old = compatibility_old
        new = {"role": membership.role, "status": membership.status}
    action = (
        "membership.role_changed"
        if compatibility_role_changed or old["role"] != new["role"]
        else "membership.status_changed"
    )
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
    if (
        status_value == "ACTIVE"
        and tras.active_assignment_count(db, membership.id) == 0
    ):
        raise identity_http_error(
            IdentityErrorCode.TENANT_ROLE_ASSIGNMENT_DATA_INCOMPLETE,
            "The membership has no active tenant role assignment.",
            status_code=409,
        )
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

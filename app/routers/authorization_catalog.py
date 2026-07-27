"""Platform-administrator APIs for the global authorization catalogue."""

from __future__ import annotations

from fastapi import APIRouter, Depends, Query, Request
from sqlalchemy import func, select
from sqlalchemy.orm import Session, selectinload

from ..core.context import CurrentContext
from ..core.security import require_platform_permission
from ..db import get_db
from ..models import (
    AuthorizationPermission,
    AuthorizationRole,
    AuthorizationRolePermission,
)
from ..schemas_authorization import (
    AuthorizationMatrixResponse,
    AuthorizationPermissionPage,
    AuthorizationPermissionResponse,
    AuthorizationRoleDetail,
    AuthorizationRoleMetadataUpdate,
    AuthorizationRolePage,
    AuthorizationRolePermissionsUpdate,
    AuthorizationRoleSummary,
)
from ..services import audit_service
from ..services import authorization_catalog_service as catalog

router = APIRouter(
    prefix="/api/platform/authorization",
    tags=["platform-authorization-catalog"],
)


def _permission_response(
    permission: AuthorizationPermission,
    *,
    protected: bool = False,
) -> AuthorizationPermissionResponse:
    return AuthorizationPermissionResponse(
        id=permission.id,
        code=permission.code,
        name=permission.name,
        description=permission.description,
        scope=permission.scope,
        resource=permission.resource,
        action=permission.action,
        status=permission.status,
        is_system=permission.is_system,
        is_protected=protected,
    )


def _role_summary(role: AuthorizationRole) -> AuthorizationRoleSummary:
    return AuthorizationRoleSummary(
        id=role.id,
        code=role.code,
        name=role.name,
        description=role.description,
        scope=role.scope,
        status=role.status,
        is_system=role.is_system,
        is_assignable=role.is_assignable,
        version=role.version,
        permission_count=len(role.permissions),
        created_at=role.created_at,
        updated_at=role.updated_at,
    )


def _role_detail(role: AuthorizationRole) -> AuthorizationRoleDetail:
    protected = {mapping.permission_id for mapping in role.permissions if mapping.is_protected}
    return AuthorizationRoleDetail(
        **_role_summary(role).model_dump(),
        permissions=[
            _permission_response(
                mapping.permission,
                protected=mapping.permission_id in protected,
            )
            for mapping in sorted(role.permissions, key=lambda row: row.permission.code)
        ],
    )


def _problem(exc: catalog.CatalogProblem):
    from fastapi import HTTPException

    return HTTPException(
        status_code=exc.status_code,
        detail={"code": exc.code, "message": exc.message},
    )


def _audit_rejection(
    db: Session,
    *,
    context: CurrentContext,
    request: Request,
    role_id: int,
    exc: catalog.CatalogProblem,
    mapping_update: bool,
) -> None:
    if exc.code == "IAM_PROTECTED_PERMISSION_MAPPING":
        action = "AUTHORIZATION_PROTECTED_PERMISSION_REMOVAL_REJECTED"
    elif exc.code == "IAM_ROLE_PERMISSION_SCOPE_MISMATCH":
        action = "AUTHORIZATION_SCOPE_MISMATCH_REJECTED"
    elif exc.code == "IAM_ROLE_VERSION_CONFLICT":
        action = "AUTHORIZATION_VERSION_CONFLICT"
    else:
        action = (
            "AUTHORIZATION_ROLE_PERMISSIONS_UPDATE_REJECTED"
            if mapping_update
            else "AUTHORIZATION_ROLE_UPDATE_REJECTED"
        )
    audit_service.write_authorization_audit(
        db,
        action=action,
        outcome="DENIED",
        context=context,
        tenant_id=None,
        request=request,
        new_value={"role_id": role_id, "reason_code": exc.code},
        detail=exc.code,
        platform_global=True,
    )
    db.commit()


@router.get("/roles", response_model=AuthorizationRolePage)
def list_roles(
    request: Request,
    scope: str | None = Query(default=None, pattern="^(PLATFORM|TENANT)$"),
    status: str | None = Query(default=None, pattern="^(ACTIVE|DISABLED|DRAFT)$"),
    is_system: bool | None = Query(default=None),
    is_assignable: bool | None = Query(default=None),
    search: str | None = Query(default=None, max_length=128),
    limit: int = Query(default=100, ge=1, le=200),
    offset: int = Query(default=0, ge=0),
    context: CurrentContext = Depends(require_platform_permission("platform:authorization:read")),
    db: Session = Depends(get_db),
) -> AuthorizationRolePage:
    filters = []
    if scope:
        filters.append(AuthorizationRole.scope == scope)
    if status:
        filters.append(AuthorizationRole.status == status)
    if is_system is not None:
        filters.append(AuthorizationRole.is_system == is_system)
    if is_assignable is not None:
        filters.append(AuthorizationRole.is_assignable == is_assignable)
    if search and search.strip():
        term = f"%{search.strip()}%"
        filters.append(
            AuthorizationRole.code.ilike(term) | AuthorizationRole.name.ilike(term)
        )
    total = db.scalar(select(func.count()).select_from(AuthorizationRole).where(*filters)) or 0
    roles = list(
        db.execute(
            select(AuthorizationRole)
            .options(selectinload(AuthorizationRole.permissions))
            .where(*filters)
            .order_by(AuthorizationRole.scope, AuthorizationRole.code)
            .offset(offset)
            .limit(limit)
        ).scalars()
    )
    audit_service.write_authorization_audit(
        db,
        action="AUTHORIZATION_CATALOG_VIEWED",
        context=context,
        request=request,
        new_value={"scope": scope, "status": status, "result_count": len(roles)},
        platform_global=True,
    )
    db.commit()
    return AuthorizationRolePage(
        items=[_role_summary(role) for role in roles],
        total=total,
        limit=limit,
        offset=offset,
    )


@router.get("/roles/{role_id}", response_model=AuthorizationRoleDetail)
def get_role(
    role_id: int,
    request: Request,
    context: CurrentContext = Depends(require_platform_permission("platform:authorization:read")),
    db: Session = Depends(get_db),
) -> AuthorizationRoleDetail:
    try:
        role = catalog.get_role(db, role_id)
    except catalog.CatalogProblem as exc:
        raise _problem(exc) from exc
    response = _role_detail(role)
    audit_service.write_authorization_audit(
        db,
        action="AUTHORIZATION_ROLE_VIEWED",
        context=context,
        request=request,
        new_value={"role_id": role.id, "version": role.version},
        platform_global=True,
    )
    db.commit()
    return response


@router.get("/permissions", response_model=AuthorizationPermissionPage)
def list_permissions(
    request: Request,
    scope: str | None = Query(default=None, pattern="^(PLATFORM|TENANT)$"),
    status: str | None = Query(default=None, pattern="^(ACTIVE|DISABLED)$"),
    resource: str | None = Query(default=None, max_length=128),
    action: str | None = Query(default=None, max_length=64),
    search: str | None = Query(default=None, max_length=128),
    limit: int = Query(default=200, ge=1, le=500),
    offset: int = Query(default=0, ge=0),
    context: CurrentContext = Depends(require_platform_permission("platform:authorization:read")),
    db: Session = Depends(get_db),
) -> AuthorizationPermissionPage:
    filters = []
    if scope:
        filters.append(AuthorizationPermission.scope == scope)
    if status:
        filters.append(AuthorizationPermission.status == status)
    if resource:
        filters.append(AuthorizationPermission.resource == resource.strip())
    if action:
        filters.append(AuthorizationPermission.action == action.strip())
    if search and search.strip():
        term = f"%{search.strip()}%"
        filters.append(
            AuthorizationPermission.code.ilike(term)
            | AuthorizationPermission.name.ilike(term)
        )
    total = db.scalar(select(func.count()).select_from(AuthorizationPermission).where(*filters)) or 0
    permissions = list(
        db.execute(
            select(AuthorizationPermission)
            .where(*filters)
            .order_by(AuthorizationPermission.scope, AuthorizationPermission.code)
            .offset(offset)
            .limit(limit)
        ).scalars()
    )
    audit_service.write_authorization_audit(
        db,
        action="AUTHORIZATION_PERMISSION_VIEWED",
        context=context,
        request=request,
        new_value={"scope": scope, "status": status, "result_count": len(permissions)},
        platform_global=True,
    )
    db.commit()
    return AuthorizationPermissionPage(
        items=[_permission_response(permission) for permission in permissions],
        total=total,
        limit=limit,
        offset=offset,
    )


@router.get("/matrix", response_model=AuthorizationMatrixResponse)
def get_matrix(
    request: Request,
    context: CurrentContext = Depends(require_platform_permission("platform:authorization:read")),
    db: Session = Depends(get_db),
) -> AuthorizationMatrixResponse:
    roles = list(
        db.execute(
            select(AuthorizationRole)
            .options(selectinload(AuthorizationRole.permissions).selectinload(AuthorizationRolePermission.permission))
            .order_by(AuthorizationRole.scope, AuthorizationRole.code)
        ).scalars()
    )
    response = AuthorizationMatrixResponse(roles=[_role_detail(role) for role in roles])
    audit_service.write_authorization_audit(
        db,
        action="AUTHORIZATION_MATRIX_VIEWED",
        context=context,
        request=request,
        new_value={"role_count": len(roles)},
        platform_global=True,
    )
    db.commit()
    return response


@router.patch("/roles/{role_id}", response_model=AuthorizationRoleDetail)
def patch_role(
    role_id: int,
    payload: AuthorizationRoleMetadataUpdate,
    request: Request,
    context: CurrentContext = Depends(require_platform_permission("platform:authorization:manage")),
    db: Session = Depends(get_db),
) -> AuthorizationRoleDetail:
    try:
        role = catalog.update_role_metadata(
            db,
            role_id,
            name=payload.name,
            description=payload.description,
            status=payload.status,
            expected_version=payload.expected_version,
            context=context,
            request=request,
        )
        response = _role_detail(role)
        db.commit()
        return response
    except catalog.CatalogProblem as exc:
        db.rollback()
        _audit_rejection(
            db,
            context=context,
            request=request,
            role_id=role_id,
            exc=exc,
            mapping_update=False,
        )
        raise _problem(exc) from exc


@router.put("/roles/{role_id}/permissions", response_model=AuthorizationRoleDetail)
def put_role_permissions(
    role_id: int,
    payload: AuthorizationRolePermissionsUpdate,
    request: Request,
    context: CurrentContext = Depends(require_platform_permission("platform:authorization:manage")),
    db: Session = Depends(get_db),
) -> AuthorizationRoleDetail:
    try:
        role = catalog.replace_role_permissions(
            db,
            role_id,
            permission_codes=payload.permission_codes,
            expected_version=payload.expected_version,
            reason=payload.change_reason,
            context=context,
            request=request,
        )
        response = _role_detail(role)
        db.commit()
        return response
    except catalog.CatalogProblem as exc:
        db.rollback()
        _audit_rejection(
            db,
            context=context,
            request=request,
            role_id=role_id,
            exc=exc,
            mapping_update=True,
        )
        raise _problem(exc) from exc

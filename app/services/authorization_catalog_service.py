"""Database-authoritative role and permission catalogue.

The hard-coded matrix remains only as an explicitly configured migration and
comparison fallback. DATABASE mode fails closed and never grants permissions
from that fallback when the catalogue cannot be resolved.
"""

from __future__ import annotations

import logging
from collections.abc import Iterable
from dataclasses import dataclass
from datetime import UTC, datetime

from fastapi import Request
from sqlalchemy import or_, select
from sqlalchemy.exc import SQLAlchemyError
from sqlalchemy.orm import Session, selectinload

from ..core.context import CurrentContext
from ..core.identity_states import IdentityErrorCode
from ..core.permissions import (
    PERMISSION_SCOPES,
    PROTECTED_ROLE_PERMISSIONS,
    ROLE_PERMISSIONS,
    normalize_role,
)
from ..core.permissions import (
    permissions_for_roles as legacy_permissions_for_roles,
)
from ..models import (
    AuthorizationPermission,
    AuthorizationRole,
    AuthorizationRolePermission,
)
from ..settings import get_settings
from . import audit_service

log = logging.getLogger("sbom.authorization.catalog")


@dataclass(frozen=True, slots=True)
class CatalogProblem(Exception):
    code: str
    message: str
    status_code: int = 400

    def __str__(self) -> str:
        return self.message


def _audit_resolution(
    db: Session,
    *,
    action: str,
    outcome: str,
    actor_user_id: int | None,
    roles: Iterable[str],
    detail: str,
    request: Request | None = None,
) -> None:
    """Best-effort operational audit without exposing claims or SQL details."""
    try:
        audit_service.write_authorization_audit(
            db,
            action=action,
            outcome=outcome,
            actor_user_id=actor_user_id,
            tenant_id=None,
            request=request,
            new_value={"roles": sorted({normalize_role(role) for role in roles})},
            detail=detail,
            platform_global=True,
        )
    except Exception:  # noqa: BLE001 - authorization must still fail closed
        log.exception("authorization_catalog.audit_failed action=%s", action)


def database_permissions_for_roles(
    db: Session,
    roles: Iterable[str],
) -> frozenset[str]:
    """Resolve active roles, mappings, and permissions from the database."""
    normalized = sorted({normalize_role(role) for role in roles if role})
    if not normalized:
        return frozenset()
    rows = db.execute(
        select(AuthorizationPermission.code)
        .join(
            AuthorizationRolePermission,
            AuthorizationRolePermission.permission_id == AuthorizationPermission.id,
        )
        .join(
            AuthorizationRole,
            AuthorizationRole.id == AuthorizationRolePermission.role_id,
        )
        .where(
            AuthorizationRole.code.in_(normalized),
            AuthorizationRole.status == "ACTIVE",
            AuthorizationPermission.status == "ACTIVE",
            or_(
                AuthorizationRole.scope == AuthorizationPermission.scope,
                AuthorizationRole.code == "PLATFORM_ADMIN",
            ),
        )
        .distinct()
    ).scalars()
    return frozenset(rows)


def resolve_permissions_for_roles(
    db: Session,
    roles: Iterable[str],
    *,
    actor_user_id: int | None = None,
    request: Request | None = None,
) -> frozenset[str]:
    """Resolve permissions according to the configured transition mode."""
    normalized = frozenset(normalize_role(role) for role in roles if role)
    settings = get_settings()
    legacy = legacy_permissions_for_roles(normalized)
    if settings.authorization_catalog_mode == "LEGACY":
        return legacy
    try:
        database = database_permissions_for_roles(db, normalized)
        found_roles = set(
            db.execute(
                select(AuthorizationRole.code).where(
                    AuthorizationRole.code.in_(normalized),
                    AuthorizationRole.status == "ACTIVE",
                )
            ).scalars()
        )
        missing = sorted(normalized - found_roles)
        if missing:
            _audit_resolution(
                db,
                action="AUTHORIZATION_CATALOG_MISSING_ROLE",
                outcome="DENIED",
                actor_user_id=actor_user_id,
                roles=missing,
                detail="CATALOG_ROLE_MISSING",
                request=request,
            )
        if settings.authorization_catalog_mode == "COMPARE":
            if database != legacy:
                _audit_resolution(
                    db,
                    action="AUTHORIZATION_CATALOG_MISMATCH_DETECTED",
                    outcome="FAILED",
                    actor_user_id=actor_user_id,
                    roles=normalized,
                    detail="CATALOG_COMPARISON_MISMATCH",
                    request=request,
                )
                log.warning(
                    "authorization_catalog.comparison_mismatch roles=%s legacy_count=%d database_count=%d",
                    sorted(normalized),
                    len(legacy),
                    len(database),
                )
            return legacy
        return database
    except SQLAlchemyError:
        log.exception("authorization_catalog.resolution_failed mode=%s", settings.authorization_catalog_mode)
        _audit_resolution(
            db,
            action="AUTHORIZATION_CATALOG_UNAVAILABLE",
            outcome="DENIED" if settings.authorization_catalog_fail_closed else "FAILED",
            actor_user_id=actor_user_id,
            roles=normalized,
            detail="CATALOG_RESOLUTION_FAILED",
            request=request,
        )
        if settings.authorization_catalog_fail_closed:
            return frozenset()
        return legacy


def catalog_equivalence() -> dict[str, dict[str, list[str]]]:
    """Return deterministic legacy definitions for operational comparison."""
    return {
        role: {
            "permissions": sorted(permissions),
            "protected_permissions": sorted(PROTECTED_ROLE_PERMISSIONS.get(role, ())),
        }
        for role, permissions in sorted(ROLE_PERMISSIONS.items())
    }


def get_role(db: Session, role_id: int, *, for_update: bool = False) -> AuthorizationRole:
    statement = (
        select(AuthorizationRole)
        .options(selectinload(AuthorizationRole.permissions).selectinload(AuthorizationRolePermission.permission))
        .where(AuthorizationRole.id == role_id)
    )
    if for_update:
        statement = statement.with_for_update()
    role = db.execute(statement).scalar_one_or_none()
    if role is None:
        raise CatalogProblem(
            str(IdentityErrorCode.ROLE_NOT_FOUND),
            "Authorization role was not found.",
            404,
        )
    return role


def update_role_metadata(
    db: Session,
    role_id: int,
    *,
    name: str | None,
    description: str | None,
    status: str | None,
    expected_version: int,
    context: CurrentContext,
    request: Request | None,
) -> AuthorizationRole:
    role = get_role(db, role_id, for_update=True)
    if role.version != expected_version:
        raise CatalogProblem(
            str(IdentityErrorCode.ROLE_VERSION_CONFLICT),
            "The role changed since it was loaded.",
            409,
        )
    if role.is_system and status is not None and status != role.status:
        raise CatalogProblem(
            str(IdentityErrorCode.ROLE_SYSTEM_IMMUTABLE),
            "System roles cannot be disabled.",
            409,
        )
    before = {
        "name": role.name,
        "description": role.description,
        "status": role.status,
        "is_assignable": role.is_assignable,
        "before_version": role.version,
    }
    if name is not None:
        normalized_name = name.strip()
        if not normalized_name:
            raise CatalogProblem("AUTHORIZATION_ROLE_NAME_INVALID", "Role name cannot be blank.")
        role.name = normalized_name
    if description is not None:
        role.description = description.strip() or None
    if status is not None:
        role.status = status
    role.version += 1
    role.updated_by_user_id = context.user_id
    role.updated_at = datetime.now(UTC)
    audit_service.write_authorization_audit(
        db,
        action="AUTHORIZATION_ROLE_UPDATED",
        context=context,
        tenant_id=None,
        request=request,
        old_value=before,
        new_value={
            "role_id": role.id,
            "role_code": role.code,
            "scope": role.scope,
            "name": role.name,
            "description": role.description,
            "status": role.status,
            "is_assignable": role.is_assignable,
            "after_version": role.version,
        },
        platform_global=True,
    )
    db.flush()
    return role


def replace_role_permissions(
    db: Session,
    role_id: int,
    *,
    permission_codes: list[str],
    expected_version: int,
    reason: str | None,
    context: CurrentContext,
    request: Request | None,
) -> AuthorizationRole:
    normalized = [code.strip() for code in permission_codes]
    if len(normalized) != len(set(normalized)):
        raise CatalogProblem(
            str(IdentityErrorCode.PERMISSION_CODE_INVALID),
            "Permission codes must be unique.",
        )
    role = get_role(db, role_id, for_update=True)
    if role.version != expected_version:
        raise CatalogProblem(
            str(IdentityErrorCode.ROLE_VERSION_CONFLICT),
            "The role changed since it was loaded.",
            409,
        )
    permissions = list(
        db.execute(select(AuthorizationPermission).where(AuthorizationPermission.code.in_(normalized))).scalars()
    )
    by_code = {permission.code: permission for permission in permissions}
    missing = sorted(set(normalized) - set(by_code))
    if missing:
        raise CatalogProblem(
            str(IdentityErrorCode.PERMISSION_NOT_FOUND),
            f"Unknown permission codes: {', '.join(missing)}",
            404,
        )
    disabled = sorted(code for code, value in by_code.items() if value.status != "ACTIVE")
    if disabled:
        raise CatalogProblem(
            str(IdentityErrorCode.PERMISSION_STATUS_INVALID),
            f"Disabled permission codes cannot be assigned: {', '.join(disabled)}",
            409,
        )
    cross_scope = sorted(code for code, permission in by_code.items() if permission.scope != role.scope)
    # The legacy PLATFORM_ADMIN role intentionally contains tenant permissions
    # to support its separately audited cross-tenant administrative override.
    if cross_scope and role.code != "PLATFORM_ADMIN":
        raise CatalogProblem(
            str(IdentityErrorCode.ROLE_PERMISSION_SCOPE_MISMATCH),
            f"Permissions outside the role scope: {', '.join(cross_scope)}",
            409,
        )
    protected = PROTECTED_ROLE_PERMISSIONS.get(role.code, frozenset())
    removed_protected = sorted(set(protected) - set(normalized))
    if removed_protected:
        raise CatalogProblem(
            str(IdentityErrorCode.PROTECTED_PERMISSION_MAPPING),
            f"Protected mappings cannot be removed: {', '.join(removed_protected)}",
            409,
        )
    previous = sorted(mapping.permission.code for mapping in role.permissions)
    added = sorted(set(normalized) - set(previous))
    removed = sorted(set(previous) - set(normalized))
    db.query(AuthorizationRolePermission).filter(AuthorizationRolePermission.role_id == role.id).delete(
        synchronize_session=False
    )
    now = datetime.now(UTC)
    for code in sorted(normalized):
        db.add(
            AuthorizationRolePermission(
                role_id=role.id,
                permission_id=by_code[code].id,
                is_protected=code in protected,
                created_by_user_id=context.user_id,
                created_at=now,
                updated_at=now,
            )
        )
    role.version += 1
    role.updated_by_user_id = context.user_id
    role.updated_at = now
    audit_service.write_authorization_audit(
        db,
        action="AUTHORIZATION_ROLE_PERMISSIONS_UPDATED",
        context=context,
        tenant_id=None,
        request=request,
        old_value={
            "permission_codes": previous,
            "before_version": expected_version,
        },
        new_value={
            "role_id": role.id,
            "role_code": role.code,
            "scope": role.scope,
            "permission_codes": sorted(normalized),
            "added_permission_codes": added,
            "removed_permission_codes": removed,
            "after_version": role.version,
            "change_reason": (reason or "").strip()[:240] or None,
        },
        platform_global=True,
    )
    db.flush()
    db.expire(role, ["permissions"])
    return get_role(db, role.id)


def permission_definition(code: str) -> tuple[str, str]:
    """Return the resource and action represented by a permission code."""
    parts = code.split(":")
    return ":".join(parts[:-1]), parts[-1]


def permission_scope(code: str) -> str:
    return PERMISSION_SCOPES[code]

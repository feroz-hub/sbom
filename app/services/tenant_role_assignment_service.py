"""Tenant role-assignment lifecycle and database-authoritative resolution."""

from __future__ import annotations

import logging
from collections.abc import Iterable
from dataclasses import dataclass
from datetime import UTC, datetime

from fastapi import Request
from sqlalchemy import select
from sqlalchemy.exc import SQLAlchemyError
from sqlalchemy.orm import Session

from ..core.context import bind_context, minimal_background_context, reset_context
from ..core.identity_states import IdentityAuditEvent, IdentityErrorCode
from ..core.permissions import normalize_role
from ..models import (
    AuthorizationPermission,
    AuthorizationRole,
    AuthorizationRolePermission,
    IAMUser,
    Tenant,
    TenantUser,
    TenantUserRoleAssignment,
    TenantUserRoleAssignmentHistory,
)
from ..settings import get_settings
from . import audit_service, authorization_catalog_service

log = logging.getLogger("sbom.tenant.roles")


@dataclass(frozen=True, slots=True)
class AssignmentProblem(Exception):
    code: IdentityErrorCode
    message: str
    status_code: int = 400
    current_version: int | None = None

    def __str__(self) -> str:
        return self.message


def _problem(
    code: IdentityErrorCode,
    message: str,
    status_code: int = 400,
    current_version: int | None = None,
) -> AssignmentProblem:
    return AssignmentProblem(code, message, status_code, current_version)


def _source(*, is_platform_admin: bool) -> str:
    return "PLATFORM_ADMIN" if is_platform_admin else "TENANT_ADMIN"


def _correlation_id(request: Request | None) -> str | None:
    if request is None:
        return None
    return (
        request.headers.get("x-request-id")
        or request.headers.get("x-correlation-id")
        or ""
    )[:128] or None


def _bounded_reason(reason: str | None) -> str | None:
    value = (reason or "").strip()
    if len(value) > 512:
        raise _problem(
            IdentityErrorCode.TENANT_ROLE_ASSIGNMENT_FAILED,
            "The assignment reason is too long.",
            422,
        )
    return value or None


def _require_database_mutation_mode() -> None:
    if get_settings().tenant_role_assignment_mode != "DATABASE":
        raise _problem(
            IdentityErrorCode.TENANT_ROLE_ASSIGNMENT_FAILED,
            "Tenant role mutations require DATABASE assignment mode.",
            409,
        )


def _membership(
    db: Session,
    tenant_id: int,
    user_id: int,
    *,
    for_update: bool = False,
) -> TenantUser:
    statement = select(TenantUser).where(
        TenantUser.tenant_id == tenant_id,
        TenantUser.user_id == user_id,
    )
    if for_update:
        statement = statement.with_for_update()
    membership = db.scalar(statement)
    if membership is None:
        raise _problem(
            IdentityErrorCode.TENANT_MEMBERSHIP_NOT_FOUND,
            "Tenant membership was not found.",
            404,
        )
    return membership


def _eligible_user(db: Session, user_id: int, *, for_update: bool = False) -> IAMUser:
    statement = select(IAMUser).where(IAMUser.id == user_id)
    if for_update:
        statement = statement.with_for_update()
    user = db.scalar(statement)
    if (
        user is None
        or user.status != "ACTIVE"
        or not user.email_verified
        or user.verification_required
    ):
        raise _problem(
            IdentityErrorCode.USER_STATUS_INVALID,
            "The user is not eligible for a tenant role.",
            422,
        )
    return user


def _catalog_roles(
    db: Session,
    role_codes: Iterable[str],
    *,
    for_update: bool = False,
) -> dict[str, AuthorizationRole]:
    codes = sorted({normalize_role(code) for code in role_codes if code})
    statement = select(AuthorizationRole).where(AuthorizationRole.code.in_(codes))
    if for_update:
        statement = statement.order_by(AuthorizationRole.id).with_for_update()
    found = {role.code: role for role in db.scalars(statement)}
    for code in codes:
        role = found.get(code)
        if role is None:
            raise _problem(
                IdentityErrorCode.TENANT_ROLE_NOT_ASSIGNABLE,
                "The requested tenant role is not assignable.",
                422,
            )
        if role.scope != "TENANT":
            raise _problem(
                IdentityErrorCode.TENANT_ROLE_SCOPE_MISMATCH,
                "The requested role is not tenant scoped.",
                422,
            )
        if role.status != "ACTIVE":
            raise _problem(
                IdentityErrorCode.TENANT_ROLE_DISABLED,
                "The requested tenant role is disabled.",
                422,
            )
        if not role.is_assignable:
            raise _problem(
                IdentityErrorCode.TENANT_ROLE_NOT_ASSIGNABLE,
                "The requested tenant role is not assignable.",
                422,
            )
    return found


def _assignments(
    db: Session,
    membership_id: int,
    *,
    for_update: bool = False,
) -> list[TenantUserRoleAssignment]:
    statement = (
        select(TenantUserRoleAssignment)
        .where(TenantUserRoleAssignment.tenant_user_id == membership_id)
        .order_by(TenantUserRoleAssignment.id)
    )
    if for_update:
        statement = statement.with_for_update()
    return list(db.scalars(statement))


def _active(assignments: Iterable[TenantUserRoleAssignment]) -> list[TenantUserRoleAssignment]:
    return [item for item in assignments if item.status == "ACTIVE"]


def _check_version(membership: TenantUser, expected_version: int) -> None:
    if expected_version != membership.role_assignment_version:
        raise _problem(
            IdentityErrorCode.TENANT_ROLE_VERSION_CONFLICT,
            "Tenant roles changed since they were loaded.",
            409,
            membership.role_assignment_version,
        )


def _history(
    db: Session,
    *,
    membership: TenantUser,
    assignment: TenantUserRoleAssignment | None,
    role: AuthorizationRole | None,
    role_code: str,
    event_type: str,
    source: str,
    actor_user_id: int | None,
    before_version: int,
    after_version: int,
    request: Request | None,
    reason: str | None = None,
    previous_status: str | None = None,
    new_status: str | None = None,
    previous_primary: bool | None = None,
    new_primary: bool | None = None,
    metadata: dict | None = None,
) -> None:
    db.add(
        TenantUserRoleAssignmentHistory(
            tenant_id=membership.tenant_id,
            tenant_user_id=membership.id,
            assignment_id=assignment.id if assignment else None,
            role_id=role.id if role else None,
            role_code_snapshot=role_code,
            event_type=event_type,
            previous_status=previous_status,
            new_status=new_status,
            previous_primary=previous_primary,
            new_primary=new_primary,
            actor_user_id=actor_user_id,
            assignment_source=source,
            reason=reason,
            before_membership_version=before_version,
            after_membership_version=after_version,
            correlation_id=_correlation_id(request),
            occurred_at=datetime.now(UTC),
            metadata_json=metadata,
        )
    )


def create_initial_assignment(
    db: Session,
    membership: TenantUser,
    *,
    role_code: str,
    actor_user_id: int | None,
    source: str,
    request: Request | None = None,
) -> TenantUserRoleAssignment:
    """Create the first assignment inside an existing caller-owned transaction."""
    return create_initial_assignments(
        db,
        membership,
        role_codes=[role_code],
        primary_role_code=role_code,
        actor_user_id=actor_user_id,
        source=source,
        request=request,
    )[0]


def create_initial_assignments(
    db: Session,
    membership: TenantUser,
    *,
    role_codes: Iterable[str],
    primary_role_code: str,
    actor_user_id: int | None,
    source: str,
    request: Request | None = None,
) -> list[TenantUserRoleAssignment]:
    """Create a membership's initial role set in the caller-owned transaction."""
    normalized = [normalize_role(code) for code in role_codes if code]
    if not normalized:
        raise _problem(
            IdentityErrorCode.TENANT_ROLE_SET_EMPTY,
            "Assign at least one tenant role.",
            422,
        )
    if len(normalized) != len(set(normalized)):
        raise _problem(
            IdentityErrorCode.TENANT_ROLE_ALREADY_ASSIGNED,
            "Tenant roles must be unique.",
            409,
        )
    primary = normalize_role(primary_role_code)
    if primary not in normalized:
        raise _problem(
            IdentityErrorCode.PRIMARY_TENANT_ROLE_REQUIRED,
            "The primary tenant role must be included in the role set.",
            422,
        )
    token = bind_context(minimal_background_context(membership.tenant_id))
    try:
        catalog = _catalog_roles(db, normalized)
        now = datetime.now(UTC)
        assignments: list[TenantUserRoleAssignment] = []
        membership.role = primary
        membership.role_assignment_version = max(
            membership.role_assignment_version or 1, 1
        )
        for code in normalized:
            role = catalog[code]
            assignment = TenantUserRoleAssignment(
                tenant_id=membership.tenant_id,
                tenant_user_id=membership.id,
                role_id=role.id,
                status="ACTIVE",
                is_primary=code == primary,
                assignment_source=source,
                assigned_by_user_id=actor_user_id,
                assigned_at=now,
                version=1,
                created_at=now,
                updated_at=now,
            )
            db.add(assignment)
            db.flush()
            assignments.append(assignment)
            _history(
                db,
                membership=membership,
                assignment=assignment,
                role=role,
                role_code=role.code,
                event_type="GRANTED",
                source=source,
                actor_user_id=actor_user_id,
                before_version=membership.role_assignment_version,
                after_version=membership.role_assignment_version,
                request=request,
                previous_status=None,
                new_status="ACTIVE",
                previous_primary=None,
                new_primary=assignment.is_primary,
            )
        db.flush()
        return assignments
    finally:
        reset_context(token)


def list_assignments(
    db: Session,
    tenant_id: int,
    user_id: int,
) -> tuple[TenantUser, list[tuple[TenantUserRoleAssignment, AuthorizationRole]]]:
    membership = _membership(db, tenant_id, user_id)
    rows = list(
        db.execute(
            select(TenantUserRoleAssignment, AuthorizationRole)
            .join(AuthorizationRole, AuthorizationRole.id == TenantUserRoleAssignment.role_id)
            .where(
                TenantUserRoleAssignment.tenant_id == tenant_id,
                TenantUserRoleAssignment.tenant_user_id == membership.id,
            )
            .order_by(
                TenantUserRoleAssignment.is_primary.desc(),
                AuthorizationRole.code,
            )
        ).all()
    )
    return membership, rows


def database_role_codes(
    db: Session,
    membership: TenantUser,
) -> frozenset[str]:
    if membership.status != "ACTIVE":
        return frozenset()
    token = bind_context(minimal_background_context(membership.tenant_id))
    try:
        return frozenset(
            db.scalars(
                select(AuthorizationRole.code)
                .join(
                    TenantUserRoleAssignment,
                    TenantUserRoleAssignment.role_id == AuthorizationRole.id,
                )
                .where(
                    TenantUserRoleAssignment.tenant_id == membership.tenant_id,
                    TenantUserRoleAssignment.tenant_user_id == membership.id,
                    TenantUserRoleAssignment.status == "ACTIVE",
                    AuthorizationRole.scope == "TENANT",
                    AuthorizationRole.status == "ACTIVE",
                )
            )
        )
    finally:
        reset_context(token)


def effective_role_codes(
    db: Session,
    membership: TenantUser,
    *,
    actor_user_id: int | None = None,
    request: Request | None = None,
) -> frozenset[str]:
    settings = get_settings()
    legacy = frozenset({normalize_role(membership.role)}) if membership.status == "ACTIVE" else frozenset()
    if settings.tenant_role_assignment_mode == "LEGACY":
        return legacy
    try:
        database = database_role_codes(db, membership)
        if settings.tenant_role_assignment_mode == "COMPARE":
            if database != legacy:
                audit_service.write_authorization_audit(
                    db,
                    action="TENANT_ROLE_ASSIGNMENT_MISMATCH",
                    outcome="FAILED",
                    actor_user_id=actor_user_id,
                    target_user_id=membership.user_id,
                    target_membership_id=membership.id,
                    tenant_id=membership.tenant_id,
                    request=request,
                    old_value={"legacy_roles": sorted(legacy)},
                    new_value={"database_roles": sorted(database)},
                    detail="TENANT_ROLE_ASSIGNMENT_COMPARISON_MISMATCH",
                )
            return legacy
        if not database and membership.status == "ACTIVE":
            audit_service.write_authorization_audit(
                db,
                action="TENANT_ROLE_ASSIGNMENT_DATA_INCOMPLETE",
                outcome="DENIED",
                actor_user_id=actor_user_id,
                target_user_id=membership.user_id,
                target_membership_id=membership.id,
                tenant_id=membership.tenant_id,
                request=request,
                detail=str(IdentityErrorCode.TENANT_ROLE_ASSIGNMENT_DATA_INCOMPLETE),
            )
        return database
    except SQLAlchemyError:
        log.exception("tenant_role_assignment.resolution_failed")
        if settings.tenant_role_assignment_fail_closed:
            return frozenset()
        return legacy


def effective_permissions(
    db: Session,
    membership: TenantUser,
    *,
    actor_user_id: int | None = None,
    request: Request | None = None,
) -> frozenset[str]:
    settings = get_settings()
    roles = effective_role_codes(
        db,
        membership,
        actor_user_id=actor_user_id,
        request=request,
    )
    if settings.tenant_role_assignment_mode != "DATABASE":
        return authorization_catalog_service.resolve_permissions_for_roles(
            db, roles, actor_user_id=actor_user_id, request=request
        )
    if not roles:
        return frozenset()
    token = bind_context(minimal_background_context(membership.tenant_id))
    try:
        return frozenset(
            db.scalars(
                select(AuthorizationPermission.code)
                .join(
                    AuthorizationRolePermission,
                    AuthorizationRolePermission.permission_id
                    == AuthorizationPermission.id,
                )
                .join(
                    AuthorizationRole,
                    AuthorizationRole.id == AuthorizationRolePermission.role_id,
                )
                .join(
                    TenantUserRoleAssignment,
                    TenantUserRoleAssignment.role_id == AuthorizationRole.id,
                )
                .where(
                    TenantUserRoleAssignment.tenant_id == membership.tenant_id,
                    TenantUserRoleAssignment.tenant_user_id == membership.id,
                    TenantUserRoleAssignment.status == "ACTIVE",
                    AuthorizationRole.scope == "TENANT",
                    AuthorizationRole.status == "ACTIVE",
                    AuthorizationPermission.scope == "TENANT",
                    AuthorizationPermission.status == "ACTIVE",
                )
                .distinct()
            )
        )
    finally:
        reset_context(token)


def _locks_for_mutation(
    db: Session,
    tenant_id: int,
    user_id: int,
) -> tuple[TenantUser, IAMUser, list[TenantUserRoleAssignment]]:
    tenant = db.scalar(select(Tenant).where(Tenant.id == tenant_id).with_for_update())
    if tenant is None or tenant.status != "ACTIVE":
        raise _problem(
            IdentityErrorCode.UNAUTHORIZED_TENANT,
            "The tenant is not active.",
            404,
        )
    user = _eligible_user(db, user_id, for_update=True)
    membership = _membership(db, tenant_id, user_id, for_update=True)
    return membership, user, _assignments(db, membership.id, for_update=True)


def _protect_last_admin(
    db: Session,
    membership: TenantUser,
    assignments: Iterable[TenantUserRoleAssignment],
    roles_by_id: dict[int, AuthorizationRole],
) -> None:
    removes_admin = any(
        item.status == "ACTIVE"
        and roles_by_id.get(item.role_id)
        and roles_by_id[item.role_id].code == "TENANT_ADMIN"
        for item in assignments
    )
    if not removes_admin or membership.status != "ACTIVE":
        return
    # The tenant row is already locked. Lock candidate memberships in a stable
    # order so competing last-admin changes serialize.
    candidates = list(
        db.scalars(
            select(TenantUser)
            .where(
                TenantUser.tenant_id == membership.tenant_id,
                TenantUser.status == "ACTIVE",
            )
            .order_by(TenantUser.id)
            .with_for_update()
        )
    )
    effective_admin_ids = set(
        db.scalars(
            select(TenantUser.id)
            .join(IAMUser, IAMUser.id == TenantUser.user_id)
            .join(
                TenantUserRoleAssignment,
                TenantUserRoleAssignment.tenant_user_id == TenantUser.id,
            )
            .join(AuthorizationRole, AuthorizationRole.id == TenantUserRoleAssignment.role_id)
            .where(
                TenantUser.tenant_id == membership.tenant_id,
                TenantUser.status == "ACTIVE",
                IAMUser.status == "ACTIVE",
                IAMUser.email_verified.is_(True),
                IAMUser.verification_required.is_(False),
                TenantUserRoleAssignment.status == "ACTIVE",
                AuthorizationRole.code == "TENANT_ADMIN",
                AuthorizationRole.scope == "TENANT",
                AuthorizationRole.status == "ACTIVE",
            )
            .distinct()
        )
    )
    _ = candidates
    if membership.id in effective_admin_ids and len(effective_admin_ids) <= 1:
        raise _problem(
            IdentityErrorCode.LAST_TENANT_ADMIN_PROTECTED,
            "The last effective Tenant Administrator cannot be removed.",
            409,
        )


def _audit_mutation(
    db: Session,
    *,
    action: IdentityAuditEvent,
    membership: TenantUser,
    actor_user_id: int,
    request: Request | None,
    old_roles: Iterable[str],
    new_roles: Iterable[str],
    reason: str | None,
) -> None:
    audit_service.write_authorization_audit(
        db,
        action=str(action),
        actor_user_id=actor_user_id,
        target_user_id=membership.user_id,
        target_membership_id=membership.id,
        tenant_id=membership.tenant_id,
        request=request,
        old_value={"roles": sorted(old_roles)},
        new_value={
            "roles": sorted(new_roles),
            "primary_role": membership.role,
            "role_assignment_version": membership.role_assignment_version,
        },
        detail=reason,
    )


def grant_role(
    db: Session,
    tenant_id: int,
    user_id: int,
    *,
    role_code: str,
    expected_version: int,
    make_primary: bool,
    reason: str | None,
    actor_user_id: int,
    is_platform_admin: bool,
    request: Request | None = None,
) -> TenantUser:
    _require_database_mutation_mode()
    reason = _bounded_reason(reason)
    if db.in_transaction():
        db.rollback()
    with db.begin():
        membership, _user, assignments = _locks_for_mutation(db, tenant_id, user_id)
        _check_version(membership, expected_version)
        role = _catalog_roles(db, [role_code], for_update=True)[normalize_role(role_code)]
        roles_by_id = {
            item.id: item
            for item in db.scalars(
                select(AuthorizationRole).where(
                    AuthorizationRole.id.in_([a.role_id for a in assignments] or [-1])
                )
            )
        }
        old_codes = {
            roles_by_id[a.role_id].code
            for a in _active(assignments)
            if a.role_id in roles_by_id
        }
        old_primary = next(
            (item for item in _active(assignments) if item.is_primary),
            None,
        )
        existing = next((a for a in assignments if a.role_id == role.id), None)
        if existing is not None and existing.status == "ACTIVE" and (
            not make_primary or existing.is_primary
        ):
            return membership
        before = membership.role_assignment_version
        after = before + 1
        now = datetime.now(UTC)
        event = IdentityAuditEvent.TENANT_ROLE_ASSIGNMENT_GRANTED
        source = _source(is_platform_admin=is_platform_admin)
        if existing is None:
            existing = TenantUserRoleAssignment(
                tenant_id=tenant_id,
                tenant_user_id=membership.id,
                role_id=role.id,
                status="ACTIVE",
                is_primary=not _active(assignments),
                assignment_source=source,
                assigned_by_user_id=actor_user_id,
                assigned_at=now,
                version=1,
                created_at=now,
                updated_at=now,
            )
            db.add(existing)
            db.flush()
            event_type = "GRANTED"
            previous_status = None
        elif existing.status == "REVOKED":
            existing.status = "ACTIVE"
            existing.revoked_at = None
            existing.revoked_by_user_id = None
            existing.revocation_reason = None
            existing.assignment_source = source
            existing.assigned_by_user_id = actor_user_id
            existing.assigned_at = now
            existing.updated_at = now
            existing.version += 1
            event = IdentityAuditEvent.TENANT_ROLE_ASSIGNMENT_REACTIVATED
            event_type = "REACTIVATED"
            previous_status = "REVOKED"
        else:
            existing.version += 1
            existing.updated_at = now
            event = IdentityAuditEvent.TENANT_ROLE_PRIMARY_CHANGED
            event_type = "PRIMARY_CHANGED"
            previous_status = "ACTIVE"
        active = [*(_active(assignments)), existing]
        if make_primary or len(active) == 1:
            for item in active:
                item.is_primary = False
            db.flush()
            existing.is_primary = True
        primary = next(item for item in active if item.is_primary)
        primary_role = role if primary.role_id == role.id else roles_by_id[primary.role_id]
        membership.role = primary_role.code
        membership.role_assignment_version = after
        membership.updated_at = now
        _history(
            db,
            membership=membership,
            assignment=existing,
            role=role,
            role_code=role.code,
            event_type=event_type,
            source=source,
            actor_user_id=actor_user_id,
            before_version=before,
            after_version=after,
            request=request,
            reason=reason,
            previous_status=previous_status,
            new_status="ACTIVE",
            previous_primary=False if previous_status else None,
            new_primary=existing.is_primary,
        )
        if (
            existing.is_primary
            and old_primary is not None
            and old_primary.id != existing.id
            and event_type != "PRIMARY_CHANGED"
        ):
            _history(
                db,
                membership=membership,
                assignment=existing,
                role=role,
                role_code=role.code,
                event_type="PRIMARY_CHANGED",
                source=source,
                actor_user_id=actor_user_id,
                before_version=before,
                after_version=after,
                request=request,
                reason=reason,
                previous_primary=False,
                new_primary=True,
                metadata={"previous_assignment_id": old_primary.id},
            )
            audit_service.write_authorization_audit(
                db,
                action=str(IdentityAuditEvent.TENANT_ROLE_PRIMARY_CHANGED),
                actor_user_id=actor_user_id,
                target_user_id=membership.user_id,
                target_membership_id=membership.id,
                tenant_id=membership.tenant_id,
                request=request,
                old_value={"primary_assignment_id": old_primary.id},
                new_value={
                    "primary_assignment_id": existing.id,
                    "primary_role": role.code,
                    "role_assignment_version": after,
                },
                detail=reason,
            )
        new_codes = old_codes | {role.code}
        _audit_mutation(
            db,
            action=event,
            membership=membership,
            actor_user_id=actor_user_id,
            request=request,
            old_roles=old_codes,
            new_roles=new_codes,
            reason=reason,
        )
    return membership


def replace_roles(
    db: Session,
    tenant_id: int,
    user_id: int,
    *,
    role_codes: Iterable[str],
    primary_role_code: str | None,
    expected_version: int,
    reason: str | None,
    actor_user_id: int,
    is_platform_admin: bool,
    request: Request | None = None,
) -> TenantUser:
    _require_database_mutation_mode()
    reason = _bounded_reason(reason)
    requested_codes = [normalize_role(code) for code in role_codes if code]
    if len(requested_codes) != len(set(requested_codes)):
        raise _problem(
            IdentityErrorCode.TENANT_ROLE_ALREADY_ASSIGNED,
            "Tenant roles must be unique.",
            409,
        )
    codes = sorted(requested_codes)
    if db.in_transaction():
        db.rollback()
    with db.begin():
        membership, _user, assignments = _locks_for_mutation(db, tenant_id, user_id)
        _check_version(membership, expected_version)
        if not codes and membership.status == "ACTIVE":
            raise _problem(
                IdentityErrorCode.ACTIVE_MEMBERSHIP_REQUIRES_ROLE,
                "An active membership requires at least one tenant role.",
                409,
            )
        catalog = _catalog_roles(db, codes, for_update=True)
        existing_roles = {
            role.id: role
            for role in db.scalars(
                select(AuthorizationRole).where(
                    AuthorizationRole.id.in_([a.role_id for a in assignments] or [-1])
                )
            )
        }
        old_codes = {
            existing_roles[a.role_id].code
            for a in _active(assignments)
            if a.role_id in existing_roles
        }
        requested_primary = normalize_role(primary_role_code) if primary_role_code else None
        if requested_primary and requested_primary not in codes:
            raise _problem(
                IdentityErrorCode.PRIMARY_TENANT_ROLE_REQUIRED,
                "Primary role must be present in the replacement role set.",
                422,
            )
        if len(codes) > 1 and requested_primary is None:
            requested_primary = membership.role if membership.role in codes else None
            if requested_primary is None:
                raise _problem(
                    IdentityErrorCode.PRIMARY_TENANT_ROLE_REQUIRED,
                    "A primary role is required when assigning multiple roles.",
                    422,
                )
        if len(codes) == 1:
            requested_primary = codes[0]

        removed_admin = "TENANT_ADMIN" in old_codes and "TENANT_ADMIN" not in codes
        if removed_admin:
            _protect_last_admin(db, membership, assignments, existing_roles)

        before = membership.role_assignment_version
        after = before + 1
        source = _source(is_platform_admin=is_platform_admin)
        now = datetime.now(UTC)
        by_role_id = {item.role_id: item for item in assignments}
        for code in codes:
            role = catalog[code]
            assignment = by_role_id.get(role.id)
            if assignment is None:
                assignment = TenantUserRoleAssignment(
                    tenant_id=tenant_id,
                    tenant_user_id=membership.id,
                    role_id=role.id,
                    status="ACTIVE",
                    is_primary=False,
                    assignment_source=source,
                    assigned_by_user_id=actor_user_id,
                    assigned_at=now,
                    version=1,
                    created_at=now,
                    updated_at=now,
                )
                db.add(assignment)
                db.flush()
                event_type, previous_status = "GRANTED", None
            elif assignment.status == "REVOKED":
                previous_status = "REVOKED"
                assignment.status = "ACTIVE"
                assignment.revoked_at = None
                assignment.revoked_by_user_id = None
                assignment.revocation_reason = None
                assignment.assigned_by_user_id = actor_user_id
                assignment.assigned_at = now
                assignment.assignment_source = source
                assignment.updated_at = now
                assignment.version += 1
                event_type = "REACTIVATED"
            else:
                continue
            _history(
                db,
                membership=membership,
                assignment=assignment,
                role=role,
                role_code=code,
                event_type=event_type,
                source=source,
                actor_user_id=actor_user_id,
                before_version=before,
                after_version=after,
                request=request,
                reason=reason,
                previous_status=previous_status,
                new_status="ACTIVE",
                previous_primary=False if previous_status else None,
                new_primary=code == requested_primary,
            )
        all_assignments = _assignments(db, membership.id, for_update=True)
        for assignment in all_assignments:
            role = existing_roles.get(assignment.role_id) or next(
                (item for item in catalog.values() if item.id == assignment.role_id),
                None,
            )
            if (
                assignment.status == "ACTIVE"
                and role is not None
                and role.code not in codes
            ):
                previous_primary = assignment.is_primary
                assignment.status = "REVOKED"
                assignment.is_primary = False
                assignment.revoked_by_user_id = actor_user_id
                assignment.revoked_at = now
                assignment.revocation_reason = reason
                assignment.updated_at = now
                assignment.version += 1
                _history(
                    db,
                    membership=membership,
                    assignment=assignment,
                    role=role,
                    role_code=role.code,
                    event_type="REVOKED",
                    source=source,
                    actor_user_id=actor_user_id,
                    before_version=before,
                    after_version=after,
                    request=request,
                    reason=reason,
                    previous_status="ACTIVE",
                    new_status="REVOKED",
                    previous_primary=previous_primary,
                    new_primary=False,
                )
        active_now = [
            assignment
            for assignment in all_assignments
            if assignment.status == "ACTIVE"
        ]
        for assignment in active_now:
            assignment.is_primary = False
        db.flush()
        primary_role = catalog.get(requested_primary) if requested_primary else None
        primary_assignment = next(
            (item for item in active_now if primary_role and item.role_id == primary_role.id),
            None,
        )
        if primary_assignment and primary_role is not None:
            primary_assignment.is_primary = True
            membership.role = primary_role.code
        membership.role_assignment_version = after
        membership.updated_at = now
        _history(
            db,
            membership=membership,
            assignment=None,
            role=primary_role,
            role_code=primary_role.code if primary_role else "NONE",
            event_type="ROLE_SET_REPLACED",
            source=source,
            actor_user_id=actor_user_id,
            before_version=before,
            after_version=after,
            request=request,
            reason=reason,
            metadata={"roles": codes},
        )
        _audit_mutation(
            db,
            action=IdentityAuditEvent.TENANT_ROLE_SET_REPLACED,
            membership=membership,
            actor_user_id=actor_user_id,
            request=request,
            old_roles=old_codes,
            new_roles=codes,
            reason=reason,
        )
    return membership


def revoke_role(
    db: Session,
    tenant_id: int,
    user_id: int,
    *,
    role_code: str,
    expected_version: int,
    replacement_primary_role_code: str | None,
    reason: str | None,
    actor_user_id: int,
    is_platform_admin: bool,
    request: Request | None = None,
) -> TenantUser:
    _require_database_mutation_mode()
    reason = _bounded_reason(reason)
    code = normalize_role(role_code)
    if db.in_transaction():
        db.rollback()
    with db.begin():
        membership, _user, assignments = _locks_for_mutation(db, tenant_id, user_id)
        _check_version(membership, expected_version)
        roles = {
            role.id: role
            for role in db.scalars(
                select(AuthorizationRole)
                .where(AuthorizationRole.id.in_([a.role_id for a in assignments] or [-1]))
                .order_by(AuthorizationRole.id)
                .with_for_update()
            )
        }
        target = next(
            (item for item in assignments if roles.get(item.role_id) and roles[item.role_id].code == code),
            None,
        )
        if target is None:
            raise _problem(
                IdentityErrorCode.TENANT_ROLE_ASSIGNMENT_NOT_FOUND,
                "Tenant role assignment was not found.",
                404,
            )
        if target.status == "REVOKED":
            return membership
        active = _active(assignments)
        remaining = [item for item in active if item.id != target.id]
        if not remaining and membership.status == "ACTIVE":
            raise _problem(
                IdentityErrorCode.ACTIVE_MEMBERSHIP_REQUIRES_ROLE,
                "The final role cannot be revoked from an active membership.",
                409,
            )
        replacement = None
        if target.is_primary and remaining:
            if not replacement_primary_role_code:
                raise _problem(
                    IdentityErrorCode.PRIMARY_TENANT_ROLE_REPLACEMENT_REQUIRED,
                    "A replacement primary role is required.",
                    409,
                )
            replacement_code = normalize_role(replacement_primary_role_code)
            replacement = next(
                (
                    item
                    for item in remaining
                    if roles.get(item.role_id)
                    and roles[item.role_id].code == replacement_code
                ),
                None,
            )
            if replacement is None:
                raise _problem(
                    IdentityErrorCode.PRIMARY_TENANT_ROLE_REPLACEMENT_REQUIRED,
                    "The replacement primary role is not active.",
                    409,
                )
        if code == "TENANT_ADMIN":
            _protect_last_admin(db, membership, [target], roles)
        before = membership.role_assignment_version
        after = before + 1
        source = _source(is_platform_admin=is_platform_admin)
        now = datetime.now(UTC)
        was_primary = target.is_primary
        target.status = "REVOKED"
        target.is_primary = False
        target.revoked_by_user_id = actor_user_id
        target.revoked_at = now
        target.revocation_reason = reason
        target.version += 1
        target.updated_at = now
        if replacement is not None:
            replacement.is_primary = True
            membership.role = roles[replacement.role_id].code
        membership.role_assignment_version = after
        membership.updated_at = now
        _history(
            db,
            membership=membership,
            assignment=target,
            role=roles[target.role_id],
            role_code=code,
            event_type="REVOKED",
            source=source,
            actor_user_id=actor_user_id,
            before_version=before,
            after_version=after,
            request=request,
            reason=reason,
            previous_status="ACTIVE",
            new_status="REVOKED",
            previous_primary=was_primary,
            new_primary=False,
        )
        if replacement is not None:
            replacement_role = roles[replacement.role_id]
            _history(
                db,
                membership=membership,
                assignment=replacement,
                role=replacement_role,
                role_code=replacement_role.code,
                event_type="PRIMARY_CHANGED",
                source=source,
                actor_user_id=actor_user_id,
                before_version=before,
                after_version=after,
                request=request,
                reason=reason,
                previous_primary=False,
                new_primary=True,
                metadata={"previous_assignment_id": target.id},
            )
            audit_service.write_authorization_audit(
                db,
                action=str(IdentityAuditEvent.TENANT_ROLE_PRIMARY_CHANGED),
                actor_user_id=actor_user_id,
                target_user_id=membership.user_id,
                target_membership_id=membership.id,
                tenant_id=membership.tenant_id,
                request=request,
                old_value={"primary_assignment_id": target.id},
                new_value={
                    "primary_assignment_id": replacement.id,
                    "primary_role": replacement_role.code,
                    "role_assignment_version": after,
                },
                detail=reason,
            )
        new_codes = {
            roles[item.role_id].code
            for item in remaining
            if item.role_id in roles
        }
        _audit_mutation(
            db,
            action=IdentityAuditEvent.TENANT_ROLE_ASSIGNMENT_REVOKED,
            membership=membership,
            actor_user_id=actor_user_id,
            request=request,
            old_roles=new_codes | {code},
            new_roles=new_codes,
            reason=reason,
        )
    return membership


def get_history(
    db: Session,
    tenant_id: int,
    user_id: int,
    *,
    offset: int = 0,
    limit: int = 100,
) -> tuple[TenantUser, list[TenantUserRoleAssignmentHistory]]:
    membership = _membership(db, tenant_id, user_id)
    rows = list(
        db.scalars(
            select(TenantUserRoleAssignmentHistory)
            .where(
                TenantUserRoleAssignmentHistory.tenant_id == tenant_id,
                TenantUserRoleAssignmentHistory.tenant_user_id == membership.id,
            )
            .order_by(
                TenantUserRoleAssignmentHistory.occurred_at.desc(),
                TenantUserRoleAssignmentHistory.id.desc(),
            )
            .offset(max(offset, 0))
            .limit(min(max(limit, 1), 200))
        )
    )
    return membership, rows


def active_assignment_count(db: Session, membership_id: int) -> int:
    return len(
        list(
            db.scalars(
                select(TenantUserRoleAssignment.id).where(
                    TenantUserRoleAssignment.tenant_user_id == membership_id,
                    TenantUserRoleAssignment.status == "ACTIVE",
                )
            )
        )
    )

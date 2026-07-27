"""Tenant and IAM user business logic."""

from __future__ import annotations

import logging
import re
from collections.abc import Callable
from dataclasses import dataclass
from datetime import UTC, datetime
from typing import Any

from fastapi import HTTPException
from sqlalchemy import or_, select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from ..core.identity_states import (
    IdentityAuditEvent,
    IdentityErrorCode,
    identity_http_error,
)
from ..core.permissions import (
    MEMBERSHIP_STATUSES,
    TENANT_ROLES,
    normalize_role,
)
from ..models import (
    AuthorizationRole,
    IAMUser,
    PlatformUserRole,
    Tenant,
    TenantUser,
    TenantUserRoleAssignment,
)
from ..settings import get_settings
from . import (
    audit_service,
    authorization_catalog_service,
    tenant_role_assignment_service,
)
from .identity_service import provision_local_identity

_TENANT_SLUG_PATTERN = re.compile(r"^[a-z0-9]+(?:-[a-z0-9]+)*$")
_CONTROL_CHAR_PATTERN = re.compile(r"[\x00-\x1f\x7f]")
log = logging.getLogger("sbom.tenant")


@dataclass(frozen=True, slots=True)
class TenantCreationResult:
    tenant: Tenant
    membership: TenantUser
    initial_admin: IAMUser
    outcome: str = "CREATED"


class TenantCreationError(Exception):
    """Safe domain error translated by the API boundary."""

    def __init__(
        self,
        code: IdentityErrorCode,
        message: str,
        *,
        status_code: int,
        audit_event: IdentityAuditEvent | None = None,
    ) -> None:
        super().__init__(message)
        self.code = code
        self.message = message
        self.status_code = status_code
        self.audit_event = audit_event


def _normalize_tenant_name(value: str) -> str:
    normalized = value.strip()
    if (
        not normalized
        or len(normalized) > 255
        or _CONTROL_CHAR_PATTERN.search(normalized)
    ):
        raise TenantCreationError(
            IdentityErrorCode.TENANT_NAME_INVALID,
            "Tenant name is invalid.",
            status_code=422,
        )
    return normalized


def _normalize_tenant_slug(value: str) -> str:
    normalized = value.strip().lower()
    if (
        len(normalized) < 3
        or len(normalized) > 128
        or not _TENANT_SLUG_PATTERN.fullmatch(normalized)
    ):
        raise TenantCreationError(
            IdentityErrorCode.TENANT_SLUG_INVALID,
            "Tenant slug is invalid.",
            status_code=422,
        )
    return normalized


def _normalize_external_tenant_id(value: str | None, slug: str) -> str:
    normalized = (value or "").strip()
    if not normalized:
        # The legacy database column remains non-null. This deterministic,
        # SBOM-owned compatibility identifier is not derived from any JWT.
        return f"sbom-{slug}"
    if len(normalized) > 255 or _CONTROL_CHAR_PATTERN.search(normalized):
        raise TenantCreationError(
            IdentityErrorCode.TENANT_CREATION_FAILED,
            "External tenant identifier is invalid.",
            status_code=422,
        )
    return normalized


def _validate_initial_admin(user: IAMUser | None) -> IAMUser:
    if user is None:
        raise TenantCreationError(
            IdentityErrorCode.INITIAL_TENANT_ADMIN_NOT_FOUND,
            "The selected initial Tenant Administrator was not found.",
            status_code=404,
        )
    if user.status == "DISABLED":
        raise TenantCreationError(
            IdentityErrorCode.ACCOUNT_DISABLED,
            "The selected initial Tenant Administrator is not eligible.",
            status_code=422,
        )
    if user.status == "PENDING":
        raise TenantCreationError(
            IdentityErrorCode.ACCOUNT_PENDING_APPROVAL,
            "The selected initial Tenant Administrator is not eligible.",
            status_code=422,
        )
    if user.status != "ACTIVE":
        raise TenantCreationError(
            IdentityErrorCode.INITIAL_TENANT_ADMIN_INELIGIBLE,
            "The selected initial Tenant Administrator is not eligible.",
            status_code=422,
        )
    if not user.email_verified or user.verification_required:
        raise TenantCreationError(
            IdentityErrorCode.EMAIL_VERIFICATION_REQUIRED,
            "The selected initial Tenant Administrator must have a verified email.",
            status_code=422,
        )
    return user


def _validate_platform_requester(db: Session, actor_user_id: int) -> None:
    """Re-check and lock database platform authority inside the transaction."""
    grant = db.scalar(
        select(PlatformUserRole)
        .where(
            PlatformUserRole.user_id == actor_user_id,
            PlatformUserRole.role == "PLATFORM_ADMIN",
            PlatformUserRole.status == "ACTIVE",
        )
        .with_for_update()
    )
    actor = db.scalar(
        select(IAMUser).where(IAMUser.id == actor_user_id).with_for_update()
    )
    if (
        grant is None
        or actor is None
        or actor.status != "ACTIVE"
        or not actor.email_verified
        or actor.verification_required
    ):
        raise TenantCreationError(
            IdentityErrorCode.PLATFORM_PERMISSION_DENIED,
            "Platform permission is required for this action.",
            status_code=403,
        )


def _constraint_name(exc: IntegrityError) -> str:
    original = getattr(exc, "orig", None)
    diagnostic = getattr(original, "diag", None)
    return str(getattr(diagnostic, "constraint_name", "") or "")


def _map_integrity_error(exc: IntegrityError) -> TenantCreationError:
    constraint = _constraint_name(exc)
    rendered = str(getattr(exc, "orig", "")).lower()
    if constraint == "uq_tenants_slug" or (
        not constraint and "tenants.slug" in rendered
    ):
        return TenantCreationError(
            IdentityErrorCode.TENANT_SLUG_CONFLICT,
            "A tenant with this slug already exists.",
            status_code=409,
            audit_event=IdentityAuditEvent.TENANT_SLUG_CONFLICT,
        )
    if constraint == "uq_tenants_external_iam_tenant_id" or (
        not constraint and "tenants.external_iam_tenant_id" in rendered
    ):
        return TenantCreationError(
            IdentityErrorCode.TENANT_EXTERNAL_ID_CONFLICT,
            "A tenant with this external tenant identifier already exists.",
            status_code=409,
            audit_event=IdentityAuditEvent.TENANT_EXTERNAL_ID_CONFLICT,
        )
    if constraint == "uq_tenant_users_tenant_user" or (
        not constraint and "tenant_users.tenant_id" in rendered
    ):
        return TenantCreationError(
            IdentityErrorCode.INITIAL_TENANT_ADMIN_ASSIGNMENT_FAILED,
            "Initial Tenant Administrator assignment failed.",
            status_code=409,
            audit_event=IdentityAuditEvent.TENANT_INITIAL_ADMIN_ASSIGNMENT_FAILED,
        )
    return TenantCreationError(
        IdentityErrorCode.TENANT_CREATION_FAILED,
        "Tenant creation failed.",
        status_code=500,
    )


def _write_creation_failure_audits(
    db: Session,
    *,
    actor_user_id: int,
    target_user_id: int | None,
    error: TenantCreationError,
    request,
    safe_request: dict[str, Any],
) -> None:
    common = {
        "outcome": "FAILED",
        "actor_user_id": actor_user_id,
        "target_user_id": target_user_id,
        "tenant_id": None,
        "request": request,
        "new_value": {
            **safe_request,
            "reason_code": str(error.code),
        },
        "detail": str(error.code),
    }
    audit_service.write_authorization_audit(
        db,
        action=str(IdentityAuditEvent.PLATFORM_TENANT_CREATE_FAILED),
        **common,
    )
    audit_service.write_authorization_audit(
        db,
        action=str(IdentityAuditEvent.TENANT_CREATION_ROLLED_BACK),
        **common,
    )
    if error.audit_event is not None:
        audit_service.write_authorization_audit(
            db,
            action=str(error.audit_event),
            **common,
        )


def create_tenant_with_initial_admin(
    db: Session,
    *,
    actor_user_id: int,
    name: str,
    slug: str,
    external_iam_tenant_id: str | None,
    initial_admin_user_id: int,
    request=None,
    failure_hook: Callable[[str], None] | None = None,
) -> TenantCreationResult:
    """Atomically create an active tenant and its only initial membership.

    Locking order is requester grant/user, initial administrator, uniqueness
    checks, tenant, membership, then audit rows. The platform dependency
    authorizes the route and this transaction re-checks that authority.
    """

    safe_request: dict[str, Any] = {
        "initial_admin_user_id": initial_admin_user_id,
    }
    audited_target_user_id: int | None = None
    operation_stage = "validation"
    unexpected_error: Exception | None = None
    try:
        normalized_name = _normalize_tenant_name(name)
        normalized_slug = _normalize_tenant_slug(slug)
        normalized_external_id = _normalize_external_tenant_id(
            external_iam_tenant_id,
            normalized_slug,
        )
        safe_request.update(
            {
                "name": normalized_name,
                "slug": normalized_slug,
                "external_iam_tenant_id": normalized_external_id,
            }
        )

        # FastAPI authorization dependencies can leave SQLAlchemy's implicit
        # read transaction open. It contains no application writes: the
        # resolver commits provisioning/audit work before yielding context.
        # Close it before beginning the service-owned atomic transaction.
        if db.in_transaction():
            db.rollback()

        with db.begin():
            _validate_platform_requester(db, actor_user_id)
            audit_service.write_authorization_audit(
                db,
                action=str(IdentityAuditEvent.PLATFORM_TENANT_CREATE_REQUESTED),
                actor_user_id=actor_user_id,
                target_user_id=initial_admin_user_id,
                tenant_id=None,
                request=request,
                new_value=safe_request,
            )

            initial_admin = db.execute(
                select(IAMUser)
                .where(IAMUser.id == initial_admin_user_id)
                .with_for_update()
            ).scalar_one_or_none()
            audited_target_user_id = (
                initial_admin.id if initial_admin is not None else None
            )
            initial_admin = _validate_initial_admin(initial_admin)
            audit_service.write_authorization_audit(
                db,
                action=str(IdentityAuditEvent.TENANT_INITIAL_ADMIN_VALIDATED),
                actor_user_id=actor_user_id,
                target_user_id=initial_admin.id,
                tenant_id=None,
                request=request,
                new_value={"status": "ELIGIBLE"},
            )

            if db.scalar(select(Tenant.id).where(Tenant.slug == normalized_slug)):
                raise TenantCreationError(
                    IdentityErrorCode.TENANT_SLUG_CONFLICT,
                    "A tenant with this slug already exists.",
                    status_code=409,
                    audit_event=IdentityAuditEvent.TENANT_SLUG_CONFLICT,
                )
            if db.scalar(
                select(Tenant.id).where(
                    Tenant.external_iam_tenant_id == normalized_external_id
                )
            ):
                raise TenantCreationError(
                    IdentityErrorCode.TENANT_EXTERNAL_ID_CONFLICT,
                    "A tenant with this external tenant identifier already exists.",
                    status_code=409,
                    audit_event=IdentityAuditEvent.TENANT_EXTERNAL_ID_CONFLICT,
                )

            now = datetime.now(UTC)
            tenant = Tenant(
                name=normalized_name,
                slug=normalized_slug,
                external_iam_tenant_id=normalized_external_id,
                status="ACTIVE",
                created_at=now,
                updated_at=now,
            )
            db.add(tenant)
            db.flush()
            operation_stage = "membership"
            if failure_hook is not None:
                failure_hook("tenant_flushed")

            membership = TenantUser(
                tenant_id=tenant.id,
                user_id=initial_admin.id,
                role="TENANT_ADMIN",
                status="ACTIVE",
                created_at=now,
                updated_at=now,
            )
            db.add(membership)
            db.flush()
            tenant_role_assignment_service.create_initial_assignment(
                db,
                membership,
                role_code="TENANT_ADMIN",
                actor_user_id=actor_user_id,
                source="TENANT_CREATION",
                request=request,
            )
            operation_stage = "audit"
            if failure_hook is not None:
                failure_hook("membership_flushed")

            tenant_value = {
                "name": tenant.name,
                "slug": tenant.slug,
                "external_iam_tenant_id": tenant.external_iam_tenant_id,
                "status": tenant.status,
            }
            audit_service.write_authorization_audit(
                db,
                action=str(IdentityAuditEvent.PLATFORM_TENANT_CREATED),
                actor_user_id=actor_user_id,
                target_user_id=initial_admin.id,
                tenant_id=tenant.id,
                request=request,
                new_value=tenant_value,
            )
            audit_service.write_authorization_audit(
                db,
                action=str(IdentityAuditEvent.TENANT_INITIAL_ADMIN_ASSIGNED),
                actor_user_id=actor_user_id,
                target_user_id=initial_admin.id,
                target_membership_id=membership.id,
                tenant_id=tenant.id,
                request=request,
                new_value={"role": "TENANT_ADMIN", "status": "ACTIVE"},
            )
            if failure_hook is not None:
                failure_hook("audit_added")

        return TenantCreationResult(tenant, membership, initial_admin)
    except IntegrityError as exc:
        db.rollback()
        error = _map_integrity_error(exc)
    except TenantCreationError as exc:
        db.rollback()
        error = exc
    except Exception as exc:
        db.rollback()
        unexpected_error = exc
        log.warning(
            "tenant.create_failed: stage=%s error_type=%s",
            operation_stage,
            type(exc).__name__,
        )
        if operation_stage == "membership":
            error = TenantCreationError(
                IdentityErrorCode.INITIAL_TENANT_ADMIN_ASSIGNMENT_FAILED,
                "Initial Tenant Administrator assignment failed.",
                status_code=500,
                audit_event=(
                    IdentityAuditEvent.TENANT_INITIAL_ADMIN_ASSIGNMENT_FAILED
                ),
            )
        else:
            error = TenantCreationError(
                IdentityErrorCode.TENANT_CREATION_FAILED,
                "Tenant creation failed.",
                status_code=500,
            )

    try:
        with db.begin():
            _write_creation_failure_audits(
                db,
                actor_user_id=actor_user_id,
                target_user_id=audited_target_user_id,
                error=error,
                request=request,
                safe_request=safe_request,
            )
    except Exception:
        db.rollback()
    if unexpected_error is not None:
        raise error from unexpected_error
    raise error


def _tenant_identity_filter(tenant_model, value: str):
    clauses = [tenant_model.slug == value, tenant_model.external_iam_tenant_id == value]
    if value.isdigit():
        clauses.append(tenant_model.id == int(value))
    return or_(*clauses)


def get_or_create_user_from_claims(db: Session, claims: dict[str, Any]) -> tuple[IAMUser, bool]:
    """Compatibility wrapper around the Phase 4 provisioning service."""
    result = provision_local_identity(db, claims)
    return result.user, result.changed


def validate_tenant_role(role: str) -> str:
    normalized = normalize_role(role)
    if normalized not in TENANT_ROLES:
        raise HTTPException(status_code=422, detail="Invalid tenant role")
    return normalized


def validate_membership_status(status_value: str) -> str:
    normalized = status_value.strip().upper()
    if normalized not in MEMBERSHIP_STATUSES:
        raise HTTPException(status_code=422, detail="Invalid membership status")
    return normalized


def get_user_memberships(db: Session, user_id: int) -> list[tuple[TenantUser, Tenant]]:
    return list(
        db.execute(
            select(TenantUser, Tenant)
            .join(Tenant, Tenant.id == TenantUser.tenant_id)
            .where(
                TenantUser.user_id == user_id,
                TenantUser.status == "ACTIVE",
                Tenant.status == "ACTIVE",
            )
        ).all()
    )


def resolve_active_tenant(
    db: Session,
    user: IAMUser,
    memberships: list[tuple[TenantUser, Tenant]],
    *,
    selected_tenant: str | None,
    tenant_claim: Any,
    is_platform_admin: bool,
    auth_enabled: bool,
    allow_platform_context: bool = False,
) -> tuple[Tenant | None, TenantUser | None, frozenset[str], frozenset[str], bool]:
    """Resolve tenant, membership, roles, permissions. Raises HTTPException on denial."""
    settings = get_settings()
    requested = (selected_tenant or "").strip()
    selected: Tenant | None = None
    membership: TenantUser | None = None

    if requested:
        for member, tenant in memberships:
            if requested in {str(tenant.id), tenant.slug, tenant.external_iam_tenant_id}:
                membership, selected = member, tenant
                break
        if selected is None and is_platform_admin:
            selected = db.execute(
                select(Tenant).where(Tenant.status == "ACTIVE", _tenant_identity_filter(Tenant, requested))
            ).scalar_one_or_none()
    elif tenant_claim is not None:
        claim_value = str(tenant_claim)
        for member, tenant in memberships:
            if claim_value in {str(tenant.id), tenant.slug, tenant.external_iam_tenant_id}:
                membership, selected = member, tenant
                break
        if selected is None and is_platform_admin:
            selected = db.execute(
                select(Tenant).where(Tenant.status == "ACTIVE", Tenant.external_iam_tenant_id == claim_value)
            ).scalar_one_or_none()
    elif len(memberships) == 1:
        membership, selected = memberships[0]
    elif not auth_enabled and settings.dev_default_tenant:
        selected = db.execute(
            select(Tenant).where(Tenant.slug == settings.default_tenant_slug, Tenant.status == "ACTIVE")
        ).scalar_one_or_none()
        if selected:
            membership = db.execute(
                select(TenantUser).where(
                    TenantUser.tenant_id == selected.id,
                    TenantUser.user_id == user.id,
                    TenantUser.status == "ACTIVE",
                )
            ).scalar_one_or_none()

    if selected is None and is_platform_admin and allow_platform_context:
        roles = frozenset({"PLATFORM_ADMIN"})
        return (
            None,
            None,
            roles,
            authorization_catalog_service.resolve_permissions_for_roles(
                db, roles, actor_user_id=user.id
            ),
            True,
        )

    if selected is None or (membership is None and not is_platform_admin):
        raise HTTPException(status_code=403, detail="Tenant access denied")

    effective_roles: set[str] = (
        set(
            tenant_role_assignment_service.effective_role_codes(
                db, membership, actor_user_id=user.id
            )
        )
        if membership
        else set()
    )
    permissions: set[str] = (
        set(
            tenant_role_assignment_service.effective_permissions(
                db, membership, actor_user_id=user.id
            )
        )
        if membership
        else set()
    )
    if is_platform_admin:
        effective_roles.add("PLATFORM_ADMIN")
        permissions.update(
            authorization_catalog_service.resolve_permissions_for_roles(
                db,
                frozenset({"PLATFORM_ADMIN"}),
                actor_user_id=user.id,
            )
        )
    return (
        selected,
        membership,
        frozenset(effective_roles),
        frozenset(permissions),
        is_platform_admin,
    )


def get_available_tenants_for_user(db: Session, user_id: int, is_platform_admin: bool) -> list[tuple[Tenant, str | None]]:
    if is_platform_admin:
        tenants = db.execute(select(Tenant).where(Tenant.status == "ACTIVE").order_by(Tenant.name)).scalars()
        return [(t, "PLATFORM_ADMIN") for t in tenants]
    rows = db.execute(
        select(Tenant, TenantUser.role)
        .join(TenantUser, TenantUser.tenant_id == Tenant.id)
        .where(
            TenantUser.user_id == user_id,
            TenantUser.status == "ACTIVE",
            Tenant.status == "ACTIVE",
        )
        .order_by(Tenant.name)
    ).all()
    return [(tenant, role) for tenant, role in rows]


def list_tenant_users(db: Session, tenant_id: int) -> list[tuple[TenantUser, IAMUser]]:
    return list(
        db.execute(
            select(TenantUser, IAMUser)
            .join(IAMUser, IAMUser.id == TenantUser.user_id)
            .where(TenantUser.tenant_id == tenant_id)
            .order_by(IAMUser.email, IAMUser.external_iam_user_id)
        ).all()
    )


def add_user_to_tenant(
    db: Session,
    tenant_id: int,
    *,
    external_iam_user_id: str,
    role: str,
    status: str = "ACTIVE",
    actor_user_id: int | None = None,
    assignment_source: str = "API",
    request=None,
) -> tuple[TenantUser, IAMUser]:
    now = datetime.now(UTC)
    role = normalize_role(role)
    status = validate_membership_status(status)
    user = db.execute(select(IAMUser).where(IAMUser.external_iam_user_id == external_iam_user_id)).scalar_one_or_none()
    if user is None:
        raise HTTPException(status_code=404, detail="IAM user not found; the user must sign in once before onboarding")
    if user.status == "DISABLED":
        raise HTTPException(status_code=422, detail="Disabled IAM user cannot receive an active membership")
    if status == "ACTIVE" and user.status == "PENDING":
        # Adding an active membership is the tenant administrator's explicit
        # onboarding approval for this discovered identity.
        user.status = "ACTIVE"
        user.updated_at = now
    membership = db.execute(
        select(TenantUser).where(TenantUser.tenant_id == tenant_id, TenantUser.user_id == user.id)
    ).scalar_one_or_none()
    if membership is None:
        membership = TenantUser(
            tenant_id=tenant_id,
            user_id=user.id,
            role=role,
            status=status,
            created_at=now,
            updated_at=now,
        )
        db.add(membership)
        db.flush()
        tenant_role_assignment_service.create_initial_assignment(
            db,
            membership,
            role_code=role,
            actor_user_id=actor_user_id,
            source=assignment_source,
            request=request,
        )
    else:
        membership.status = status
        membership.updated_at = now
        active_count = tenant_role_assignment_service.active_assignment_count(
            db, membership.id
        )
        if active_count == 0:
            tenant_role_assignment_service.create_initial_assignment(
                db,
                membership,
                role_code=role,
                actor_user_id=actor_user_id,
                source=assignment_source,
                request=request,
            )
        elif membership.role != role:
            raise HTTPException(
                status_code=409,
                detail={
                    "code": str(
                        IdentityErrorCode.MULTI_ROLE_COMPATIBILITY_CONFLICT
                    ),
                    "message": (
                        "Use the tenant role-assignment API to replace roles."
                    ),
                },
            )
    db.flush()
    return membership, user


def update_user_role(
    db: Session,
    tenant_id: int,
    membership_id: int,
    *,
    role: str | None = None,
    status: str | None = None,
) -> tuple[TenantUser, dict, dict]:
    membership = db.execute(
        select(TenantUser).where(TenantUser.id == membership_id, TenantUser.tenant_id == tenant_id)
    ).scalar_one_or_none()
    if membership is None:
        raise HTTPException(status_code=404, detail="Membership not found")
    old = {"role": membership.role, "status": membership.status}
    if role is not None:
        membership.role = validate_tenant_role(role)
    if status is not None:
        membership.status = validate_membership_status(status)
    membership.updated_at = datetime.now(UTC)
    new = {"role": membership.role, "status": membership.status}
    db.flush()
    return membership, old, new


def disable_user_membership(db: Session, tenant_id: int, membership_id: int) -> TenantUser:
    membership = db.execute(
        select(TenantUser).where(TenantUser.id == membership_id, TenantUser.tenant_id == tenant_id)
    ).scalar_one_or_none()
    if membership is None:
        raise HTTPException(status_code=404, detail="Membership not found")
    membership.status = "DISABLED"
    membership.updated_at = datetime.now(UTC)
    db.flush()
    return membership


def get_tenant_membership(db: Session, tenant_id: int, membership_id: int) -> tuple[TenantUser, IAMUser]:
    row = db.execute(
        select(TenantUser, IAMUser)
        .join(IAMUser, IAMUser.id == TenantUser.user_id)
        .where(TenantUser.id == membership_id, TenantUser.tenant_id == tenant_id)
    ).one_or_none()
    if row is None:
        raise HTTPException(status_code=404, detail="Membership not found")
    return row


def _active_tenant_admin_count(db: Session, tenant_id: int, *, excluding: int | None = None) -> int:
    statement = (
        select(TenantUser.id)
        .join(IAMUser, IAMUser.id == TenantUser.user_id)
        .join(
            TenantUserRoleAssignment,
            TenantUserRoleAssignment.tenant_user_id == TenantUser.id,
        )
        .join(
            AuthorizationRole,
            AuthorizationRole.id == TenantUserRoleAssignment.role_id,
        )
        .where(
            TenantUser.tenant_id == tenant_id,
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
    if excluding is not None:
        statement = statement.where(TenantUser.id != excluding)
    return len(db.execute(statement).scalars().all())


def ensure_not_last_active_tenant_admin(
    db: Session,
    membership: TenantUser,
    *,
    next_role: str | None = None,
    next_status: str | None = None,
    deleting: bool = False,
    platform_override: bool = False,
) -> None:
    # Serialize every administrator-removal path on the tenant row, then lock
    # candidate memberships in a stable order. This covers legacy membership
    # deactivation/removal as well as Phase 9 role replacement.
    db.scalar(
        select(Tenant)
        .where(Tenant.id == membership.tenant_id)
        .with_for_update()
    )
    list(
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
    removes_admin = deleting or (next_role is not None and next_role != "TENANT_ADMIN") or (
        next_status is not None and next_status != "ACTIVE"
    )
    if (
        "TENANT_ADMIN"
        in tenant_role_assignment_service.effective_role_codes(
            db, membership, actor_user_id=membership.user_id
        )
        and membership.status == "ACTIVE"
        and removes_admin
        and _active_tenant_admin_count(db, membership.tenant_id, excluding=membership.id) == 0
    ):
        raise identity_http_error(
            IdentityErrorCode.LAST_TENANT_ADMIN_PROTECTED,
            "The last effective Tenant Administrator cannot be removed.",
            status_code=409,
        )


def set_membership_status(db: Session, tenant_id: int, membership_id: int, status_value: str) -> tuple[TenantUser, dict, dict]:
    return update_user_role(db, tenant_id, membership_id, status=validate_membership_status(status_value))


def remove_membership(db: Session, tenant_id: int, membership_id: int) -> TenantUser:
    membership, _user = get_tenant_membership(db, tenant_id, membership_id)
    db.delete(membership)
    db.flush()
    return membership

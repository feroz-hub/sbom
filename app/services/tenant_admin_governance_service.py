"""Restricted control-plane mutations of Tenant Administrator authority."""

from __future__ import annotations

from typing import Literal

from fastapi import HTTPException, Request
from sqlalchemy import select
from sqlalchemy.orm import Session

from ..authorization_catalog_seed_v6 import TENANT_ADMIN_GOVERNANCE_PERMISSION
from ..core.context import CurrentContext, minimal_background_context, tenant_scope
from ..core.identity_states import IdentityErrorCode, identity_http_error
from ..core.permissions import normalize_role
from ..models import Tenant, TenantUserRoleAssignmentHistory
from . import audit_service, authorization_catalog_service
from . import tenant_role_assignment_service as roles
from . import tenant_service as tenants

Operation = Literal["revoke", "deactivate", "remove"]


def _snapshot(db, membership) -> dict:
    _membership, assignments = roles.list_assignments(db, membership.tenant_id, membership.user_id)
    primary_role = next(
        (
            role.code
            for assignment, role in assignments
            if assignment.status == "ACTIVE" and assignment.is_primary and role.status == "ACTIVE"
        ),
        membership.role,
    )
    return {
        "tenant_id": membership.tenant_id,
        "membership_id": membership.id,
        "membership_public_id": str(membership.public_id),
        "user_id": membership.user_id,
        "status": membership.status,
        "roles": sorted(roles.assigned_role_codes(db, membership)),
        "primary_role": primary_role,
        "role_assignment_version": membership.role_assignment_version,
    }


def mutate_administrator(
    db: Session,
    *,
    context: CurrentContext,
    tenant_id: int,
    membership_id: int,
    operation: Operation,
    expected_version: int | None = None,
    replacement_primary_role_code: str | None = None,
    reason: str | None = None,
    request: Request | None = None,
) -> dict:
    """Own one transaction for role/lifecycle changes and the governance audit.

    Tenant scoping here is only for authorization metadata, after verified
    control-plane authority. It never grants a tenant context to the actor.
    """
    if (
        context.tenant_id is not None
        or not context.is_platform_admin
        or not context.has_permission(TENANT_ADMIN_GOVERNANCE_PERMISSION)
    ):
        raise identity_http_error(
            IdentityErrorCode.PLATFORM_PERMISSION_DENIED, "Platform governance context is required.", status_code=403
        )
    if operation not in {"revoke", "deactivate", "remove"}:
        raise ValueError("Unknown administrator governance operation")
    reason = roles._bounded_reason(reason)
    if db.in_transaction():
        db.rollback()
    action = f"TENANT_ADMIN_{ {'revoke': 'REVOKED', 'deactivate': 'DEACTIVATED', 'remove': 'REMOVED'}[operation] }"
    try:
        with tenant_scope(minimal_background_context(tenant_id)), db.begin():
            # Serialize with role, lifecycle and global-account administration.
            tenant = db.scalar(
                select(Tenant).where(Tenant.id == tenant_id).with_for_update().execution_options(populate_existing=True)
            )
            if tenant is None:
                raise HTTPException(404, "Tenant not found")
            try:
                tenants._validate_platform_requester(db, context.user_id)
            except tenants.TenantCreationError as exc:
                raise identity_http_error(exc.code, exc.message, status_code=exc.status_code) from exc
            permissions = authorization_catalog_service.resolve_permissions_for_roles(db, {"PLATFORM_ADMIN"})
            if TENANT_ADMIN_GOVERNANCE_PERMISSION not in permissions:
                raise identity_http_error(
                    IdentityErrorCode.PLATFORM_PERMISSION_DENIED,
                    "Platform governance permission is required.",
                    status_code=403,
                )
            membership, _user = tenants.lock_tenant_membership(db, tenant_id, membership_id)
            old = _snapshot(db, membership)
            if "TENANT_ADMIN" not in old["roles"]:
                raise identity_http_error(
                    IdentityErrorCode.TENANT_ROLE_NOT_ASSIGNABLE,
                    "Target membership has no active Tenant Administrator assignment.",
                    status_code=409,
                )
            user_id = membership.user_id
            if operation == "revoke":
                roles._require_database_mutation_mode()
                roles._check_version(membership, expected_version)
                replacement = normalize_role(replacement_primary_role_code) if replacement_primary_role_code else None
                if replacement:
                    roles.validate_role_delegation([replacement], is_platform_admin=False)
                    roles._catalog_roles(db, [replacement], for_update=True)
                if old["primary_role"] == "TENANT_ADMIN" and replacement is None:
                    raise roles._problem(
                        IdentityErrorCode.PRIMARY_TENANT_ROLE_REPLACEMENT_REQUIRED,
                        "An explicit ordinary replacement primary role is required.",
                        409,
                    )
                remaining = set(old["roles"]) - {"TENANT_ADMIN"}
                if replacement:
                    remaining.add(replacement)
                if not remaining:
                    raise roles._problem(
                        IdentityErrorCode.ACTIVE_MEMBERSHIP_REQUIRES_ROLE,
                        "An explicit ordinary replacement tenant role is required.",
                        409,
                    )
                roles.revoke_role(
                    db,
                    tenant_id,
                    user_id,
                    role_code="TENANT_ADMIN",
                    replacement_primary_role_code=replacement,
                    expected_version=expected_version,
                    reason=reason,
                    actor_user_id=context.user_id,
                    is_platform_admin=True,
                    request=request,
                    caller_owns_transaction=True,
                    grant_replacement_role=True,
                )
                # Sessions disable autoflush; snapshots must see the new
                # assignment state before the transaction's success audit.
                db.flush()
                new = _snapshot(db, membership)
            else:
                tenants.ensure_not_last_active_tenant_admin(
                    db,
                    membership,
                    next_status="DISABLED" if operation == "deactivate" else None,
                    deleting=operation == "remove",
                )
                if operation == "deactivate":
                    tenants.set_membership_status(db, tenant_id, membership_id, "DISABLED")
                    new = _snapshot(db, membership)
                else:
                    # History FKs are SET NULL; audit snapshots retain the exact
                    # deleted identity and complete current role/assignment state.
                    assignments = roles._assignments(db, membership.id, for_update=True)
                    old["assignments"] = [
                        {
                            "assignment_id": item.id,
                            "role_id": item.role_id,
                            "status": item.status,
                            "is_primary": item.is_primary,
                            "version": item.version,
                        }
                        for item in assignments
                    ]
                    old["history_ids"] = list(
                        db.scalars(
                            select(TenantUserRoleAssignmentHistory.id).where(
                                TenantUserRoleAssignmentHistory.tenant_id == tenant_id,
                                TenantUserRoleAssignmentHistory.tenant_user_id == membership_id,
                            )
                        )
                    )
                    tenants.remove_membership(db, tenant_id, membership_id)
                    new = {
                        "tenant_id": tenant_id,
                        "membership_id": membership_id,
                        "user_id": user_id,
                        "status": "REMOVED",
                    }
            audit_service.write_authorization_audit(
                db,
                action=action,
                actor_user_id=context.user_id,
                target_user_id=user_id,
                target_membership_id=None if operation == "remove" else membership_id,
                tenant_id=tenant_id,
                old_value=old,
                new_value={**new, "reason": reason},
                detail=reason,
                request=request,
            )
        return new
    except (HTTPException, roles.AssignmentProblem) as exc:
        # The mutation transaction has rolled back before recording the denial.
        detail = str(exc.code) if isinstance(exc, roles.AssignmentProblem) else str(exc.detail)
        audit_service.write_authorization_audit(
            db,
            action=action,
            outcome="DENIED",
            actor_user_id=context.user_id,
            tenant_id=tenant_id if db.get(Tenant, tenant_id) is not None else None,
            new_value={"membership_id": membership_id, "reason": reason},
            detail=detail,
            request=request,
        )
        db.commit()
        if isinstance(exc, roles.AssignmentProblem):
            error = {"code": str(exc.code), "message": exc.message}
            if exc.current_version is not None:
                error["current_version"] = exc.current_version
            raise HTTPException(exc.status_code, error) from exc
        raise

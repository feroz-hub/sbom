"""Explicit IAM wire identifiers. Provider/session and membership IDs stay separate."""

from fastapi import HTTPException
from sqlalchemy import select

from .models import IAMUser, TenantUser

USER_SCHEMAS = frozenset(
    {"AuthContextUser", "PlatformUserSummary", "PlatformUserDetail", "UserSearchResult", "TenantUserCandidate"}
)
USER_FIELDS = frozenset(
    {
        "user_id",
        "initial_admin_user_id",
        "actor_user_id",
        "target_user_id",
        "assigned_by_user_id",
        "created_by_user_id",
        "iam_user_id",
    }
)
IAM_SCHEMA_FIELDS = frozenset(
    {
        "PlatformGrantSummary",
        "PlatformAdministratorGrantRequest",
        "PlatformAdministratorGrantResponse",
        "PlatformUserStatusResponse",
        "TenantCreateRequest",
        "InitialTenantAdministratorResponse",
        "MembershipUpsert",
        "Membership",
        "RecoverTenantAdmin",
    }
)


def iam_route(path):
    return path.startswith(
        ("/api/platform/", "/api/tenants", "/api/auth/", "/api/v1/auth/", "/api/report-notifications")
    )


def iam_field(key, path):
    # Advisor events persist the local IAM integer actor, unlike repair/session
    # actor labels and provider subjects. Event/recommendation IDs stay integers.
    if (
        path
        in {
            "/api/component-advisor/audit/events",
            "/api/component-advisor/recommendations/{recommendation_id}/events",
        }
        and key == "actor_user_id"
    ):
        return "iam_users"
    return "iam_users" if iam_route(path) and key in USER_FIELDS else None


def user_lookup(context, request):
    """Called only after endpoint permission dependencies; never global discovery.

    Existing invite and governance endpoints intentionally select an eligible
    global account. Their own permission and eligibility checks remain in force.
    All other tenant selectors must already be members of the selected tenant.
    """
    table = IAMUser.__table__
    statement = select(table.c.id, table.c.public_id)
    if context is None:
        raise HTTPException(401, "Authentication required")
    path = request.scope["route"].path
    if path.startswith("/api/platform/") or path == "/api/tenants":
        if not context.is_platform_admin or context.tenant_id is not None:
            raise HTTPException(403, "Platform permission required")
        if path == "/api/tenants" and not context.has_permission("platform:tenant:bootstrap_admin"):
            raise HTTPException(403, "Initial administrator provisioning permission is required")
        return table, statement
    if not path.startswith("/api/tenants/") or context.tenant_id is None:
        raise HTTPException(404, "User not found")
    # tenant_id was decoded first and endpoint dependencies checked authority.
    if request.path_params.get("tenant_id") != context.tenant_id:
        raise HTTPException(404, "User not found")
    if request.method == "POST" and path.endswith(("/users", "/memberships")):
        if not context.has_permission("tenant:user:invite"):
            raise HTTPException(403, "Insufficient permission")
        return table, statement
    members = select(TenantUser.user_id).where(TenantUser.tenant_id == context.tenant_id)
    return table, statement.where(table.c.id.in_(members))


def missing_user(db, context, request):
    """Retain established error codes and failed governance audit semantics."""
    from .core.identity_states import IdentityAuditEvent, IdentityErrorCode, identity_http_error
    from .services import audit_service

    path = request.scope["route"].path
    code = IdentityErrorCode.USER_NOT_FOUND
    actions = ()
    outcome = "DENIED"
    if path == "/api/tenants" and request.method == "POST":
        code = IdentityErrorCode.INITIAL_TENANT_ADMIN_NOT_FOUND
        outcome = "FAILED"
        actions = (IdentityAuditEvent.PLATFORM_TENANT_CREATE_FAILED, IdentityAuditEvent.TENANT_CREATION_ROLLED_BACK)
    elif path == "/api/platform/administrators" and request.method == "POST":
        actions = (IdentityAuditEvent.PLATFORM_ADMIN_GRANT_REJECTED,)
    for action in actions:
        audit_service.write_authorization_audit(
            db,
            action=str(action),
            outcome=outcome,
            actor_user_id=context.user_id,
            target_user_id=None,
            tenant_id=None,
            request=request,
            new_value={"reason_code": str(code)},
            detail=str(code),
        )
    if actions:
        db.commit()
    raise identity_http_error(code, "User not found.", status_code=404)

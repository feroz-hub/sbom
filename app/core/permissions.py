from __future__ import annotations

from enum import Enum

TENANT_ROLES = frozenset({"TENANT_ADMIN", "SECURITY_ANALYST", "DEVELOPER", "VIEWER"})
MEMBERSHIP_STATUSES = frozenset({"ACTIVE", "DISABLED", "PENDING"})
USER_STATUSES = frozenset({"ACTIVE", "DISABLED", "PENDING"})
TENANT_STATUSES = frozenset({"ACTIVE", "DISABLED", "PENDING"})
PLATFORM_GRANT_STATUSES = frozenset({"ACTIVE", "DISABLED"})

ALL_PERMISSIONS = frozenset(
    {
        "sbom:read",
        "sbom:upload",
        "sbom:update",
        "sbom:delete",
        "sbom:export",
        "sbom:repair:read",
        "sbom:repair:update",
        "sbom:repair:revalidate",
        "sbom:repair:download",
        "sbom:repair:search",
        "project:read",
        "project:create",
        "project:update",
        "project:delete",
        "product:read",
        "product:create",
        "product:update",
        "product:delete",
        "product:assign_sbom",
        "product:manage_schedule",
        "component:read",
        "component:update",
        "lifecycle:read",
        "lifecycle:override",
        "lifecycle:provider:read",
        "lifecycle:provider:update",
        "lifecycle:provider:test",
        "lifecycle:provider:sync",
        "lifecycle:vendor-record:read",
        "lifecycle:vendor-record:write",
        "lifecycle:vendor-record:delete",
        "vex:read",
        "vex:write",
        "remediation:read",
        "remediation:write",
        "remediation:close",
        "dashboard:read",
        "tenant:user:read",
        "tenant:user:invite",
        "tenant:user:update",
        "tenant:settings:update",
        "schedule:read",
        "schedule:write",
        "analysis:read",
        "analysis:run",
        "platform:admin",
        "platform:user:read",
        "platform:user:write",
        "platform:tenant:create",
    }
)

ROLE_PERMISSIONS: dict[str, frozenset[str]] = {
    "PLATFORM_ADMIN": ALL_PERMISSIONS,
    "TENANT_ADMIN": frozenset(
        {
            "sbom:read",
            "sbom:upload",
            "sbom:update",
            "sbom:delete",
            "sbom:export",
            "sbom:repair:read",
            "sbom:repair:update",
            "sbom:repair:revalidate",
            "sbom:repair:download",
            "sbom:repair:search",
            "project:read",
            "project:create",
            "project:update",
            "project:delete",
            "product:read",
            "product:create",
            "product:update",
            "product:delete",
            "product:assign_sbom",
            "product:manage_schedule",
            "component:read",
            "component:update",
            "lifecycle:read",
            "lifecycle:override",
            "lifecycle:provider:read",
            "lifecycle:provider:update",
            "lifecycle:provider:test",
            "lifecycle:provider:sync",
            "lifecycle:vendor-record:read",
            "lifecycle:vendor-record:write",
            "lifecycle:vendor-record:delete",
            "vex:read",
            "vex:write",
            "remediation:read",
            "remediation:write",
            "remediation:close",
            "dashboard:read",
            "tenant:user:read",
            "tenant:user:invite",
            "tenant:user:update",
            "tenant:settings:update",
            "schedule:read",
            "schedule:write",
            "analysis:read",
            "analysis:run",
        }
    ),
    "SECURITY_ANALYST": frozenset(
        {
            "sbom:read",
            "sbom:upload",
            "sbom:update",
            "sbom:export",
            "sbom:repair:read",
            "sbom:repair:update",
            "sbom:repair:revalidate",
            "sbom:repair:download",
            "sbom:repair:search",
            "project:read",
            "project:create",
            "project:update",
            "product:read",
            "product:assign_sbom",
            "product:manage_schedule",
            "component:read",
            "component:update",
            "lifecycle:read",
            "lifecycle:override",
            "lifecycle:provider:read",
            "lifecycle:provider:test",
            "lifecycle:vendor-record:read",
            "vex:read",
            "vex:write",
            "remediation:read",
            "remediation:write",
            "remediation:close",
            "dashboard:read",
            "schedule:read",
            "schedule:write",
            "analysis:read",
            "analysis:run",
        }
    ),
    "DEVELOPER": frozenset(
        {
            "sbom:read",
            "sbom:repair:read",
            "sbom:repair:search",
            "project:read",
            "product:read",
            "component:read",
            "lifecycle:read",
            "vex:read",
            "remediation:read",
            "remediation:write",
            "dashboard:read",
            "schedule:read",
            "analysis:read",
        }
    ),
    "VIEWER": frozenset(
        {
            "sbom:read",
            "sbom:repair:read",
            "sbom:repair:search",
            "project:read",
            "product:read",
            "component:read",
            "lifecycle:read",
            "vex:read",
            "remediation:read",
            "dashboard:read",
            "schedule:read",
            "analysis:read",
        }
    ),
}


class Role(str, Enum):
    PLATFORM_ADMIN = "PLATFORM_ADMIN"
    TENANT_ADMIN = "TENANT_ADMIN"
    SECURITY_ANALYST = "SECURITY_ANALYST"
    DEVELOPER = "DEVELOPER"
    VIEWER = "VIEWER"


def normalize_role(role: str) -> str:
    return role.strip().upper().replace("-", "_").replace(" ", "_")


def get_permissions_for_role(role: str) -> frozenset[str]:
    return ROLE_PERMISSIONS.get(normalize_role(role), frozenset())


def has_permission(role: str, permission: str) -> bool:
    return permission in get_permissions_for_role(role)


def permissions_for_roles(roles: set[str] | frozenset[str]) -> frozenset[str]:
    permissions: set[str] = set()
    for role in roles:
        permissions.update(ROLE_PERMISSIONS.get(normalize_role(role), frozenset()))
    return frozenset(permissions)

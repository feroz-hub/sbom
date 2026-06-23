from __future__ import annotations

from enum import Enum

ALL_PERMISSIONS = frozenset(
    {
        "sbom:read",
        "sbom:upload",
        "sbom:update",
        "sbom:delete",
        "sbom:export",
        "project:read",
        "project:create",
        "project:update",
        "project:delete",
        "component:read",
        "component:update",
        "lifecycle:read",
        "lifecycle:override",
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
    }
)

ROLE_PERMISSIONS: dict[str, frozenset[str]] = {
    "PLATFORM_ADMIN": ALL_PERMISSIONS,
    "TENANT_ADMIN": ALL_PERMISSIONS,
    "SECURITY_ANALYST": frozenset(
        {
            "sbom:read",
            "sbom:upload",
            "sbom:update",
            "sbom:export",
            "project:read",
            "project:create",
            "project:update",
            "component:read",
            "component:update",
            "lifecycle:read",
            "lifecycle:override",
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
            "project:read",
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
            "project:read",
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

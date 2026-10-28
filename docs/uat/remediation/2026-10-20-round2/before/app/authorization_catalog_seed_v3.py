"""Frozen V3 catalogue additions: Secure Component Advisor (migration 067).

Spec section 9 permissions matrix mapped onto the existing roles
(docs/secure-component-advisor/phase0-analysis.md §8, decision D-7).
Do not edit after 067 ships; add a new seed version instead.
"""

COMPONENT_ADVISOR_ROLE_PERMISSIONS_V3 = {
    "TENANT_ADMIN": frozenset({
        "component_advisor:read",
        "component_advisor:recommendation:create",
        "component_advisor:recommendation:review",
        "component_advisor:recommendation:accept",
        "component_advisor:audit:read",
    }),
    "SECURITY_ANALYST": frozenset({
        "component_advisor:read",
        "component_advisor:recommendation:create",
        "component_advisor:recommendation:review",
        "component_advisor:audit:read",
    }),
    "DEVELOPER": frozenset({
        "component_advisor:read",
        "component_advisor:recommendation:create",
    }),
    "VIEWER": frozenset({
        "component_advisor:read",
    }),
}

COMPONENT_ADVISOR_PERMISSIONS_V3 = frozenset().union(*COMPONENT_ADVISOR_ROLE_PERMISSIONS_V3.values())

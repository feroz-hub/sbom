"""Frozen V4 catalogue additions: advisor policy configuration (migration 068).

Spec section 9 "Configure accepted-risk/trust policy": Admin/policy role
configures; Security Analyst may view and recommend only. Names follow the
scoped-configuration family convention ``tenant:<family>:<action>`` checked by
``app.services.configuration_scope.require_configuration_permission``.
Do not edit after 068 ships; add a new seed version instead.
"""

ADVISOR_POLICY_ROLE_PERMISSIONS_V4 = {
    "TENANT_ADMIN": frozenset({"tenant:advisor-policy:read", "tenant:advisor-policy:update"}),
    "SECURITY_ANALYST": frozenset({"tenant:advisor-policy:read"}),
}

ADVISOR_POLICY_PERMISSIONS_V4 = frozenset().union(*ADVISOR_POLICY_ROLE_PERMISSIONS_V4.values())

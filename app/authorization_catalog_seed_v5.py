"""Frozen V5 additions: platform Component Advisor policy defaults."""
from .authorization_catalog_seed_v2 import PLATFORM_ADMIN_PERMISSIONS_V2

PLATFORM_ADVISOR_POLICY_PERMISSIONS_V5 = frozenset({
    "platform:advisor-policy:read", "platform:advisor-policy:update",
})
PLATFORM_ADMIN_PERMISSIONS_V5 = PLATFORM_ADMIN_PERMISSIONS_V2 | PLATFORM_ADVISOR_POLICY_PERMISSIONS_V5

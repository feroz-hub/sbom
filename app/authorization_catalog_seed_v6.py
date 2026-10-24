"""Frozen V6: restricted Tenant Administrator governance."""

from .authorization_catalog_seed_v5 import PLATFORM_ADMIN_PERMISSIONS_V5

TENANT_ADMIN_GOVERNANCE_PERMISSION = "platform:tenant_admin:manage"
PLATFORM_ADMIN_PERMISSIONS_V6 = PLATFORM_ADMIN_PERMISSIONS_V5 | frozenset({TENANT_ADMIN_GOVERNANCE_PERMISSION})

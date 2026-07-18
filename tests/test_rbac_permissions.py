"""RBAC permission matrix tests."""

from __future__ import annotations

from app.core.permissions import Role, get_permissions_for_role, has_permission


def test_viewer_cannot_upload_sbom():
    assert not has_permission(Role.VIEWER.value, "sbom:upload")


def test_viewer_cannot_delete_sbom():
    assert not has_permission(Role.VIEWER.value, "sbom:delete")


def test_security_analyst_can_upload_sbom():
    assert has_permission(Role.SECURITY_ANALYST.value, "sbom:upload")


def test_product_permissions_follow_role_matrix():
    assert has_permission(Role.TENANT_ADMIN.value, "product:create")
    assert has_permission(Role.SECURITY_ANALYST.value, "product:assign_sbom")
    assert not has_permission(Role.SECURITY_ANALYST.value, "product:delete")
    assert not has_permission(Role.DEVELOPER.value, "product:create")
    assert not has_permission(Role.VIEWER.value, "product:assign_sbom")
    assert has_permission(Role.VIEWER.value, "product:read")


def test_tenant_admin_can_manage_users():
    perms = get_permissions_for_role(Role.TENANT_ADMIN.value)
    assert "tenant:user:update" in perms


def test_developer_cannot_manage_tenant_users():
    assert not has_permission(Role.DEVELOPER.value, "tenant:user:update")


def test_platform_admin_has_all_permissions():
    perms = get_permissions_for_role(Role.PLATFORM_ADMIN.value)
    assert "platform:admin" in perms
    assert "sbom:upload" in perms


def test_tenant_admin_has_no_platform_permissions():
    permissions = get_permissions_for_role(Role.TENANT_ADMIN.value)
    assert "platform:admin" not in permissions
    assert "platform:user:write" not in permissions
    assert "platform:tenant:create" not in permissions


def test_high_value_permission_separation():
    expected = {
        Role.PLATFORM_ADMIN: {"sbom:upload", "analysis:run", "tenant:user:update", "platform:admin"},
        Role.TENANT_ADMIN: {"sbom:upload", "analysis:run", "tenant:user:update"},
        Role.SECURITY_ANALYST: {"sbom:upload", "analysis:run", "vex:write", "remediation:write"},
        Role.DEVELOPER: {"sbom:read", "analysis:read", "remediation:write"},
        Role.VIEWER: {"sbom:read", "analysis:read"},
    }
    for role, permissions in expected.items():
        assert permissions <= get_permissions_for_role(role.value)
    assert not has_permission(Role.SECURITY_ANALYST.value, "tenant:user:update")
    assert not has_permission(Role.DEVELOPER.value, "analysis:run")
    assert not has_permission(Role.VIEWER.value, "remediation:write")

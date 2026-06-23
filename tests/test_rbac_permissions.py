"""RBAC permission matrix tests."""

from __future__ import annotations

from app.core.permissions import Role, get_permissions_for_role, has_permission


def test_viewer_cannot_upload_sbom():
    assert not has_permission(Role.VIEWER.value, "sbom:upload")


def test_viewer_cannot_delete_sbom():
    assert not has_permission(Role.VIEWER.value, "sbom:delete")


def test_security_analyst_can_upload_sbom():
    assert has_permission(Role.SECURITY_ANALYST.value, "sbom:upload")


def test_tenant_admin_can_manage_users():
    perms = get_permissions_for_role(Role.TENANT_ADMIN.value)
    assert "tenant:user:update" in perms


def test_developer_cannot_manage_tenant_users():
    assert not has_permission(Role.DEVELOPER.value, "tenant:user:update")


def test_platform_admin_has_all_permissions():
    perms = get_permissions_for_role(Role.PLATFORM_ADMIN.value)
    assert "platform:admin" in perms
    assert "sbom:upload" in perms

from datetime import UTC, datetime

from app.db import SessionLocal
from app.models import (
    AuthorizationPermission,
    AuthorizationRole,
    AuthorizationRolePermission,
    TenantUser,
)
from app.services import tenant_role_assignment_service as service
from app.settings import reset_settings
from sqlalchemy import select

from .phase6_helpers import now, seed_user
from .phase9_helpers import seed_role_membership


def test_multiple_active_roles_union_database_permissions():
    with SessionLocal() as db:
        user, membership, _ = seed_role_membership(db, role="VIEWER")
        service.grant_role(
            db,
            1,
            user.id,
            role_code="DEVELOPER",
            expected_version=1,
            make_primary=False,
            reason="test",
            actor_user_id=user.id,
            is_platform_admin=False,
        )
        membership = db.get(type(membership), membership.id)
        roles = service.effective_role_codes(db, membership)
        permissions = service.effective_permissions(db, membership)
    assert roles == {"VIEWER", "DEVELOPER"}
    assert "remediation:write" in permissions
    assert "analysis:read" in permissions


def test_custom_assignable_tenant_role_is_effective():
    with SessionLocal() as db:
        user, membership, _ = seed_role_membership(db)
        now = datetime.now(UTC)
        role = AuthorizationRole(
            code="CUSTOM_REVIEWER",
            name="Custom Reviewer",
            scope="TENANT",
            status="ACTIVE",
            is_system=False,
            is_assignable=True,
            version=1,
            created_at=now,
            updated_at=now,
        )
        permission = db.scalar(
            select(AuthorizationPermission).where(
                AuthorizationPermission.code == "sbom:upload"
            )
        )
        db.add(role)
        db.flush()
        db.add(
            AuthorizationRolePermission(
                role_id=role.id,
                permission_id=permission.id,
                is_protected=False,
                created_at=now,
                updated_at=now,
            )
        )
        db.commit()
        service.grant_role(
            db,
            1,
            user.id,
            role_code=role.code,
            expected_version=1,
            make_primary=True,
            reason=None,
            actor_user_id=user.id,
            is_platform_admin=False,
        )
        membership = db.get(type(membership), membership.id)
        assert membership.role == "CUSTOM_REVIEWER"
        assert "sbom:upload" in service.effective_permissions(db, membership)


def test_database_mode_fails_closed_and_compare_enforces_legacy(monkeypatch):
    with SessionLocal() as db:
        user = seed_user(db)
        membership = TenantUser(
            tenant_id=1,
            user_id=user.id,
            role="VIEWER",
            status="ACTIVE",
            created_at=now(),
            updated_at=now(),
        )
        db.add(membership)
        db.commit()
        assert service.effective_role_codes(db, membership) == frozenset()
        monkeypatch.setenv("TENANT_ROLE_ASSIGNMENT_MODE", "COMPARE")
        reset_settings()
        assert service.effective_role_codes(db, membership) == {"VIEWER"}
        monkeypatch.delenv("TENANT_ROLE_ASSIGNMENT_MODE", raising=False)
        reset_settings()


def test_primary_only_change_keeps_permission_union_and_updates_legacy_role():
    with SessionLocal() as db:
        user, membership, _ = seed_role_membership(db, role="VIEWER")
        service.grant_role(
            db,
            1,
            user.id,
            role_code="DEVELOPER",
            expected_version=1,
            make_primary=False,
            reason=None,
            actor_user_id=user.id,
            is_platform_admin=False,
        )
        membership = db.get(TenantUser, membership.id)
        before = service.effective_permissions(db, membership)
        service.grant_role(
            db,
            1,
            user.id,
            role_code="DEVELOPER",
            expected_version=2,
            make_primary=True,
            reason="primary only",
            actor_user_id=user.id,
            is_platform_admin=False,
        )
        membership = db.get(TenantUser, membership.id)
        after = service.effective_permissions(db, membership)
    assert membership.role == "DEVELOPER"
    assert membership.role_assignment_version == 3
    assert before == after

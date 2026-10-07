"""Control-plane authority never substitutes for explicit customer membership."""

import pytest
from app.authorization_catalog_seed_v5 import PLATFORM_ADMIN_PERMISSIONS_V5
from app.authorization_catalog_seed_v2 import PLATFORM_ADMIN_PERMISSIONS_V2
from app.core.permissions import ROLE_PERMISSIONS
from app.core.security import get_current_user
from app.db import SessionLocal
from app.services.auth_context_service import resolve_authorization_state

from tests.phase6_helpers import identity_claims, seed_membership, seed_platform_grant, seed_user


def test_platform_catalog_contains_only_control_plane_permissions():
    assert ROLE_PERMISSIONS["PLATFORM_ADMIN"] == PLATFORM_ADMIN_PERMISSIONS_V5
    assert all(permission.startswith("platform:") for permission in PLATFORM_ADMIN_PERMISSIONS_V5)
    assert not any(permission.startswith("platform:user:") for permission in PLATFORM_ADMIN_PERMISSIONS_V5)


def test_forward_migration_repairs_existing_12_permission_catalog(app):
    import importlib.util
    from pathlib import Path

    from app.models import AuthorizationPermission, AuthorizationRole, AuthorizationRolePermission
    from app.services.authorization_catalog_service import resolve_permissions_for_roles
    from sqlalchemy import delete, select

    path = Path(__file__).resolve().parents[1] / "alembic/versions/066_platform_configuration_permissions.py"
    spec = importlib.util.spec_from_file_location("platform_config_repair", path)
    migration = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(migration)
    with SessionLocal() as db:
        role_id = db.scalar(select(AuthorizationRole.id).where(AuthorizationRole.code == "PLATFORM_ADMIN"))
        ids = select(AuthorizationPermission.id).where(AuthorizationPermission.code.in_(migration.PERMISSIONS))
        db.execute(delete(AuthorizationRolePermission).where(
            AuthorizationRolePermission.role_id == role_id,
            AuthorizationRolePermission.permission_id.in_(ids),
        ))
        assert not resolve_permissions_for_roles(db, {"PLATFORM_ADMIN"})
        migration._seed(db.connection())
        migration._seed(db.connection())
        permissions = resolve_permissions_for_roles(db, {"PLATFORM_ADMIN"})
        assert permissions == PLATFORM_ADMIN_PERMISSIONS_V5
        assert "platform:tenant:read" in permissions
        assert "tenant:user:read" not in permissions


def test_pure_platform_auth_responses_require_no_membership(app, client):
    with SessionLocal() as db:
        actor = seed_user(db)
        seed_platform_grant(db, actor)
        claims = identity_claims(actor)
        db.commit()
    app.dependency_overrides[get_current_user] = lambda: claims
    try:
        response = client.get("/api/auth/me")
        assert response.status_code == 200
        body = response.json()
        assert body["is_platform_admin"] is True
        assert body["tenant_id"] is None
        assert "platform:tenant:read" in body["permissions"]
        assert "tenant:user:read" not in body["permissions"]
        response = client.get("/api/auth/context")
        assert response.status_code == 200
        context = response.json()
        assert context["platform"]["is_platform_admin"] is True
        assert "platform:tenant:read" in context["platform"]["permissions"]
        assert context["tenant_context"]["active_tenant"] is None
        assert context["tenant_context"]["available_tenants"] == []
        assert client.get("/api/platform/summary").status_code == 200
    finally:
        app.dependency_overrides.pop(get_current_user, None)


@pytest.mark.parametrize(
    ("method", "path", "payload"),
    [
        ("GET", "/api/tenants/1/users", None),
        ("POST", "/api/tenants/1/users", {"user_id": 1, "roles": ["VIEWER"]}),
        ("PUT", "/api/tenants/1/users/1/roles", {"roles": ["VIEWER"]}),
        ("DELETE", "/api/tenants/1/users/1", None),
        ("GET", "/api/projects", None),
        ("POST", "/api/projects", {"name": "Unauthorized"}),
        ("POST", "/api/projects/1/products", {"name": "Unauthorized"}),
        ("GET", "/api/sboms", None),
        ("POST", "/api/sboms/upload", {}),
        ("POST", "/api/sboms/1/analyze", {}),
        ("GET", "/api/vex/investigations", None),
        ("POST", "/api/remediation", {}),
        ("GET", "/api/tenants/1/schedule", None),
        ("GET", "/api/tenants/1/user-candidates?q=dev", None),
        ("GET", "/api/tenants/1/audit-history", None),
    ],
)
def test_pure_platform_admin_cannot_enter_tenant(app, client, method, path, payload):
    with SessionLocal() as db:
        actor = seed_user(db)
        seed_platform_grant(db, actor)
        claims = identity_claims(actor)
        db.commit()
    app.dependency_overrides[get_current_user] = lambda: claims
    try:
        response = client.request(method, path, json=payload, headers={"X-Tenant-ID": "1"})
        assert response.status_code == 403, response.text
    finally:
        app.dependency_overrides.pop(get_current_user, None)


def test_catalog_fails_closed_if_v2_mapping_missing(app):
    from app.models import AuthorizationRole, AuthorizationRolePermission
    from app.services.authorization_catalog_service import resolve_permissions_for_roles
    from sqlalchemy import delete, select

    with SessionLocal() as db:
        role = db.scalar(select(AuthorizationRole).where(AuthorizationRole.code == "PLATFORM_ADMIN"))
        db.execute(delete(AuthorizationRolePermission).where(AuthorizationRolePermission.role_id == role.id))
        assert resolve_permissions_for_roles(db, {"PLATFORM_ADMIN"}) == frozenset()


@pytest.mark.parametrize(
    "forbidden", ["sbom:read", "tenant:user:invite", "platform:user:read", "platform:user:manage_status"]
)
def test_platform_catalog_rejects_operational_and_identity_admin_grants(app, forbidden):
    from app.core.context import CurrentContext
    from app.models import AuthorizationRole
    from app.services.authorization_catalog_service import CatalogProblem, replace_role_permissions
    from sqlalchemy import select

    with SessionLocal() as db:
        actor = seed_user(db)
        role = db.scalar(select(AuthorizationRole).where(AuthorizationRole.code == "PLATFORM_ADMIN"))
        context = CurrentContext(
            user_id=actor.id,
            external_user_id="test",
            email=actor.email,
            display_name=actor.display_name,
            tenant_id=None,
            external_tenant_id=None,
            roles=frozenset({"PLATFORM_ADMIN"}),
            permissions=PLATFORM_ADMIN_PERMISSIONS_V5,
            is_platform_admin=True,
        )
        with pytest.raises(CatalogProblem):
            replace_role_permissions(
                db,
                role.id,
                permission_codes=[*PLATFORM_ADMIN_PERMISSIONS_V5, forbidden],
                expected_version=role.version,
                reason="negative scope test",
                context=context,
                request=None,
            )


def test_dedicated_admin_recovery_keeps_actor_platform_only(app, client):
    from app.models import TenantUser
    from app.services.tenant_role_assignment_service import effective_role_codes

    with SessionLocal() as db:
        actor = seed_user(db)
        seed_platform_grant(db, actor)
        candidate = seed_user(db)
        claims = identity_claims(actor)
        actor_id, candidate_id = actor.id, candidate.id
        db.commit()
    app.dependency_overrides[get_current_user] = lambda: claims
    try:
        response = client.post("/api/platform/tenants/1/recover-admin", json={"user_id": candidate_id})
        assert response.status_code == 200, response.text
        with SessionLocal() as db:
            member = db.query(TenantUser).filter_by(tenant_id=1, user_id=candidate_id).one()
            assert effective_role_codes(db, member) == {"TENANT_ADMIN"}
            assert db.query(TenantUser).filter_by(user_id=actor_id).count() == 0
        assert client.post("/api/platform/tenants/1/recover-admin", json={"user_id": candidate_id}).status_code == 200
        assert client.get("/api/tenants/1/users", headers={"X-Tenant-ID": "1"}).status_code == 403
    finally:
        app.dependency_overrides.pop(get_current_user, None)


def test_v2_migration_preserves_tenant_mappings(app):
    import importlib.util
    from pathlib import Path

    from app.models import AuthorizationRole, AuthorizationRolePermission
    from app.services.authorization_catalog_service import database_permissions_for_roles
    from sqlalchemy import select

    path = Path(__file__).resolve().parents[1] / "alembic/versions/064_platform_tenant_segregation_v2.py"
    spec = importlib.util.spec_from_file_location("v2_migration_test", path)
    migration = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(migration)
    with SessionLocal() as db:
        tenant_role = db.scalar(select(AuthorizationRole).where(AuthorizationRole.code == "VIEWER"))
        before = set(
            db.scalars(
                select(AuthorizationRolePermission.permission_id).where(
                    AuthorizationRolePermission.role_id == tenant_role.id
                )
            )
        )
        migration._seed(db.connection())
        migration._seed(db.connection())
        assert database_permissions_for_roles(db, {"PLATFORM_ADMIN"}) == PLATFORM_ADMIN_PERMISSIONS_V2
        after = set(
            db.scalars(
                select(AuthorizationRolePermission.permission_id).where(
                    AuthorizationRolePermission.role_id == tenant_role.id
                )
            )
        )
        assert before == after
    with pytest.raises(RuntimeError, match="cannot be downgraded"):
        migration.downgrade()


def test_tenant_audit_pagination_excludes_context_telemetry(app, client):
    from app.models import AuthorizationAuditLog

    from tests.phase6_helpers import now

    with SessionLocal() as db:
        actor = seed_user(db)
        seed_membership(db, actor, role="TENANT_ADMIN")
        claims = identity_claims(actor)
        for _index in range(9):
            db.add(
                AuthorizationAuditLog(
                    tenant_id=1,
                    actor_user_id=actor.id,
                    action="TENANT_MEMBER_ADDED",
                    outcome="SUCCESS",
                    created_at=now(),
                )
            )
        db.add(
            AuthorizationAuditLog(
                tenant_id=1,
                actor_user_id=actor.id,
                action="IAM_AUTH_CONTEXT_RESOLVED",
                outcome="SUCCESS",
                created_at=now(),
            )
        )
        db.commit()
    app.dependency_overrides[get_current_user] = lambda: claims
    try:
        result = client.get(
            "/api/tenants/1/audit-history",
            params={"page_size": 5, "administrative_only": True},
            headers={"X-Tenant-ID": "1"},
        )
        assert result.status_code == 200, result.text
        body = result.json()
        assert body["total"] == 9 and body["total_pages"] == 2 and len(body["items"]) == 5
        assert all(event["label"] == "Member added" for event in body["items"])
        second = client.get(
            "/api/tenants/1/audit-history?page=2&page_size=5&administrative_only=true", headers={"X-Tenant-ID": "1"}
        ).json()
        assert len(second["items"]) == 4
        assert client.get("/api/platform/summary").status_code == 403
        assert client.get("/api/tenants/999/audit-history", headers={"X-Tenant-ID": "1"}).status_code == 404
    finally:
        app.dependency_overrides.pop(get_current_user, None)


@pytest.mark.parametrize(
    "path",
    ["/api/platform/users", "/api/platform/users/search?q=dev", "/api/platform/users/1", "/api/platform/users/1/audit"],
)
def test_platform_admin_has_no_global_directory(app, client, path):
    with SessionLocal() as db:
        actor = seed_user(db)
        seed_platform_grant(db, actor)
        claims = identity_claims(actor)
        db.commit()
    app.dependency_overrides[get_current_user] = lambda: claims
    try:
        assert client.get(path).status_code == 403
    finally:
        app.dependency_overrides.pop(get_current_user, None)


@pytest.mark.parametrize(
    ("method", "path", "payload"),
    [
        ("PATCH", "/api/platform/users/1/status", {"status": "DISABLED"}),
        ("PATCH", "/api/platform/users/1/profile", {"display_name": "Changed"}),
        ("POST", "/api/platform/users/1/unlock", {}),
        ("POST", "/api/platform/users/1/force-password-change", {}),
        ("POST", "/api/platform/users/1/logout-all", {}),
    ],
)
def test_platform_admin_cannot_manage_arbitrary_global_accounts(app, client, method, path, payload):
    with SessionLocal() as db:
        actor = seed_user(db)
        seed_platform_grant(db, actor)
        claims = identity_claims(actor)
        db.commit()
    app.dependency_overrides[get_current_user] = lambda: claims
    try:
        assert client.request(method, path, json=payload).status_code == 403
    finally:
        app.dependency_overrides.pop(get_current_user, None)


def test_existing_identity_memberships_are_independent(app, client):
    from app.models import IAMUser, Tenant, TenantUser

    from tests.phase6_helpers import now

    with SessionLocal() as db:
        db.expire_on_commit = False
        other = Tenant(name="Other tenant", slug="other-tenant", status="ACTIVE", created_at=now(), updated_at=now())
        db.add(other)
        db.flush()
        actor = seed_user(db)
        seed_membership(db, actor, role="TENANT_ADMIN")
        candidate = seed_user(db, email="independent@example.test", display_name="Independent User")
        second_member = seed_membership(db, candidate, tenant_id=other.id, role="VIEWER")
        claims = identity_claims(actor)
        candidate_id, other_member_id = candidate.id, second_member.id
        db.commit()
    app.dependency_overrides[get_current_user] = lambda: claims
    headers = {"X-Tenant-ID": "1"}
    try:
        found = client.get("/api/tenants/1/user-candidates?q=Independent", headers=headers).json()["items"]
        assert len(found) == 1 and found[0]["id"] == candidate_id
        assert not any(key in found[0] for key in ["memberships", "tenant_id", "roles", "external_subject"])
        created = client.post(
            "/api/tenants/1/users", json={"user_id": candidate_id, "roles": ["DEVELOPER"]}, headers=headers
        )
        assert created.status_code == 201, created.text
        assert (
            client.post(
                "/api/tenants/1/users", json={"user_id": candidate_id, "roles": ["VIEWER"]}, headers=headers
            ).status_code
            == 409
        )
        with SessionLocal() as db:
            member = db.query(TenantUser).filter_by(tenant_id=1, user_id=candidate_id).one()
            current_member_id = member.id
        response = client.post(f"/api/tenants/1/users/{current_member_id}/deactivate", headers=headers)
        assert response.status_code == 200, response.text
        with SessionLocal() as db:
            assert db.get(IAMUser, candidate_id).status == "ACTIVE"
            assert db.get(TenantUser, other_member_id).status == "ACTIVE"
            assert db.get(TenantUser, current_member_id).status == "DISABLED"
    finally:
        app.dependency_overrides.pop(get_current_user, None)


def test_dual_role_authority_is_independent(app, client):
    with SessionLocal() as db:
        actor = seed_user(db)
        seed_platform_grant(db, actor)
        seed_membership(db, actor, role="VIEWER")
        claims = identity_claims(actor)
        db.commit()
        state = resolve_authorization_state(db, actor, allow_platform_context=True)
        assert state.active_tenant is None
        assert len(state.memberships) == 1
    app.dependency_overrides[get_current_user] = lambda: claims
    try:
        platform = client.get("/api/auth/me").json()
        assert platform["tenant_id"] is None
        assert "platform:tenant:read" in platform["permissions"]
        assert "tenant:user:read" not in platform["permissions"]
        body = client.get("/api/auth/me", headers={"X-Tenant-ID": "1"}).json()
        assert body["roles"] == ["VIEWER"]
        assert set(body["permissions"]) == set(ROLE_PERMISSIONS["VIEWER"])
        assert "platform:admin" not in body["permissions"]
        assert client.get("/api/platform/summary", headers={"X-Tenant-ID": "1"}).status_code == 200
    finally:
        app.dependency_overrides.pop(get_current_user, None)

"""Phase 1 governance through signed native JWTs and real database RBAC.

No authentication/context dependency overrides or injected permissions.
"""

import importlib.util
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
from threading import Barrier
from uuid import uuid4

import pytest
from app.authorization_catalog_seed_v6 import PLATFORM_ADMIN_PERMISSIONS_V6, TENANT_ADMIN_GOVERNANCE_PERMISSION
from app.core.context import minimal_background_context, tenant_scope
from app.db import SessionLocal
from app.models import (
    AuthorizationAuditLog,
    AuthorizationPermission,
    AuthorizationRole,
    AuthorizationRolePermission,
    IAMUser,
    NativeUserCredential,
    PlatformUserRole,
    Tenant,
    TenantUser,
    TenantUserRoleAssignment,
    TenantUserRoleAssignmentHistory,
    UserIdentity,
)
from app.services import native_auth_service, native_jwt_service, password_service
from app.services import tenant_role_assignment_service as roles
from sqlalchemy import func, select

from tests.phase6_helpers import now, seed_platform_grant, seed_user
from tests.public_id_fixture import membership_uuid, tenant_uuid, user_uuid
from tests.test_native_iam_phase2 import native_config as native_config

PASSWORD = "governance integration test passphrase"


@pytest.fixture(scope="module")
def password_hash():
    return password_service.hash_password(PASSWORD)


def member(db, user, codes=("TENANT_ADMIN",), *, primary=None, tenant_id=1):
    stamp = now()
    item = TenantUser(
        tenant_id=tenant_id,
        user_id=user.id,
        role=primary or codes[0],
        status="ACTIVE",
        role_assignment_version=1,
        created_at=stamp,
        updated_at=stamp,
    )
    db.add(item)
    db.flush()
    roles.create_initial_assignments(
        db, item, role_codes=codes, primary_role_code=primary or codes[0], actor_user_id=user.id, source="SYSTEM"
    )
    return item


def native_user(db, password_hash):
    user = seed_user(db)
    stamp = now()
    credential = NativeUserCredential(
        user_id=user.id,
        password_hash=password_hash,
        password_changed_at=stamp,
        security_version=1,
        created_at=stamp,
        updated_at=stamp,
    )
    db.add_all(
        [
            credential,
            UserIdentity(
                user_id=user.id,
                provider_type="NATIVE",
                provider_identifier=user.email,
                created_at=stamp,
                updated_at=stamp,
            ),
        ]
    )
    db.flush()
    return user, native_jwt_service.issue_token(user, credential)


@pytest.fixture
def scenario(client, native_config, password_hash):
    with SessionLocal() as db:
        actor, token = native_user(db, password_hash)
        seed_platform_grant(db, actor)
        target, target_token = native_user(db, password_hash)
        membership = member(db, target)
        backup = seed_user(db)
        backup_member = member(db, backup)
        db.commit()
        data = dict(
            client=client,
            actor_id=actor.id,
            target_id=target.id,
            backup_id=backup.id,
            membership_id=membership.id,
            backup_membership_id=backup_member.id,
            token=token,
            target_token=target_token,
        )
    data["url"] = f"/api/platform/tenants/{tenant_uuid(1)}/administrators/{membership_uuid(data['membership_id'])}"
    data["headers"] = {"Authorization": f"Bearer {token}"}
    return data


def mutate(scenario, operation, *, body=None, headers=None, url=None):
    path = url or scenario["url"]
    if operation == "remove":
        return scenario["client"].delete(
            path, headers=headers if headers is not None else scenario["headers"], params={"reason": "governance test"}
        )
    return scenario["client"].post(
        path + "/" + operation,
        headers=headers if headers is not None else scenario["headers"],
        json=body
        if body is not None
        else (
            {"expected_version": 1, "replacement_primary_role_code": "VIEWER", "reason": "governance test"}
            if operation == "revoke"
            else {"reason": "governance test"}
        ),
    )


@pytest.mark.parametrize("operation", ["revoke", "deactivate", "remove"])
def test_platform_governance_preserves_identity_other_memberships_and_grants(scenario, operation):
    s = scenario
    with SessionLocal() as db:
        target = db.get(IAMUser, s["target_id"])
        global_before = (target.status, target.email, target.email_verified)
        stamp = now()
        tenant = Tenant(
            name="Other governance tenant", slug="other-governance", status="ACTIVE", created_at=stamp, updated_at=stamp
        )
        db.add(tenant)
        db.flush()
        other = member(db, target, ("VIEWER",), tenant_id=tenant.id)
        grant = seed_platform_grant(db, target)
        other_id, other_tenant_id, grant_id = other.id, tenant.id, grant.id
        db.commit()
    result = mutate(s, operation)
    assert result.status_code == (204 if operation == "remove" else 200), result.text
    if operation != "remove":
        assert result.json()["membership_id"] == membership_uuid(s["membership_id"])
        assert result.json()["user_id"] == user_uuid(s["target_id"])
    with SessionLocal() as db, tenant_scope(minimal_background_context(1)):
        target = db.get(IAMUser, s["target_id"])
        assert (target.status, target.email, target.email_verified) == global_before
        assert db.get(PlatformUserRole, grant_id).status == "ACTIVE"
        assert db.get(TenantUser, other_id).status == "ACTIVE"
        membership = db.get(TenantUser, s["membership_id"])
        if operation == "remove":
            assert membership is None
            assert (
                db.scalar(
                    select(func.count())
                    .select_from(TenantUserRoleAssignment)
                    .where(TenantUserRoleAssignment.tenant_user_id == s["membership_id"])
                )
                == 0
            )
        elif operation == "deactivate":
            assert membership.status == "DISABLED"
            assert roles.assigned_role_codes(db, membership) == {"TENANT_ADMIN"}
            assert membership.role_assignment_version == 1
        else:
            assert membership.status == "ACTIVE"
            assert roles.effective_role_codes(db, membership) == {"VIEWER"}
            assert membership.role_assignment_version == 2
        event = db.scalar(
            select(AuthorizationAuditLog).where(
                AuthorizationAuditLog.action
                == {
                    "revoke": "TENANT_ADMIN_REVOKED",
                    "deactivate": "TENANT_ADMIN_DEACTIVATED",
                    "remove": "TENANT_ADMIN_REMOVED",
                }[operation],
                AuthorizationAuditLog.outcome == "SUCCESS",
            )
        )
        assert event.actor_user_id == s["actor_id"] and event.target_user_id == s["target_id"]
        assert event.tenant_id == 1 and event.old_value["membership_id"] == s["membership_id"]
        assert event.new_value["reason"] == "governance test" and event.created_at
        if operation == "remove":
            assert event.target_membership_id is None
            assert event.old_value["membership_public_id"] == s["url"].rsplit("/", 1)[1]
            history_ids = event.old_value["history_ids"]
            assert history_ids
            history = list(
                db.scalars(
                    select(TenantUserRoleAssignmentHistory).where(TenantUserRoleAssignmentHistory.id.in_(history_ids))
                )
            )
            assert len(history) == len(history_ids)
            assert all(row.tenant_user_id is None and row.assignment_id is None for row in history)
        assert db.scalar(select(func.count()).select_from(TenantUser).where(TenantUser.user_id == s["actor_id"])) == 0
    # The same signed identity token immediately sees local membership changes.
    headers = {"Authorization": f"Bearer {s['target_token']}", "X-Tenant-ID": tenant_uuid(1)}
    assert s["client"].get(f"/api/tenants/{tenant_uuid(1)}/users", headers=headers).status_code == 403
    headers["X-Tenant-ID"] = tenant_uuid(other_tenant_id)
    assert s["client"].get("/api/projects", headers=headers).status_code == 200
    # Pure platform actor remains outside customer data planes.
    assert s["client"].get("/api/sboms", headers={**s["headers"], "X-Tenant-ID": tenant_uuid(1)}).status_code == 403


@pytest.mark.parametrize("role", ["TENANT_ADMIN", "SECURITY_ANALYST", "DEVELOPER", "VIEWER"])
@pytest.mark.parametrize("operation", ["revoke", "deactivate", "remove"])
def test_governance_requires_real_platform_grant(scenario, password_hash, role, operation):
    with SessionLocal() as db:
        user, token = native_user(db, password_hash)
        member(db, user, (role,))
        db.commit()
    assert mutate(scenario, operation, headers={"Authorization": f"Bearer {token}"}).status_code == 403


@pytest.mark.parametrize("operation", ["revoke", "deactivate", "remove"])
def test_governance_requires_authenticated_bearer(scenario, operation):
    assert mutate(scenario, operation, headers={}).status_code == 401
    assert mutate(scenario, operation, headers={"Authorization": "Bearer invalid"}).status_code == 401


@pytest.mark.parametrize("operation", ["revoke", "deactivate", "remove"])
def test_governance_rechecks_disabled_platform_grant(scenario, operation):
    with SessionLocal() as db:
        grant = db.scalar(select(PlatformUserRole).where(PlatformUserRole.user_id == scenario["actor_id"]))
        grant.status = "DISABLED"
        db.commit()
    assert mutate(scenario, operation).status_code == 403


@pytest.mark.parametrize("operation", ["revoke", "deactivate", "remove"])
def test_last_effective_administrator_is_protected(scenario, operation):
    with SessionLocal() as db:
        db.get(TenantUser, scenario["backup_membership_id"]).status = "DISABLED"
        db.commit()
    result = mutate(scenario, operation)
    assert result.status_code == 409, result.text
    assert result.json()["detail"]["code"] == "IAM_LAST_TENANT_ADMIN_PROTECTED"
    with SessionLocal() as db:
        membership = db.get(TenantUser, scenario["membership_id"])
        assert membership.status == "ACTIVE" and membership.role_assignment_version == 1
        assert roles.assigned_role_codes(db, membership) == {"TENANT_ADMIN"}
        assert (
            db.scalar(
                select(func.count())
                .select_from(AuthorizationAuditLog)
                .where(
                    AuthorizationAuditLog.action
                    == "TENANT_ADMIN_"
                    + {"revoke": "REVOKED", "deactivate": "DEACTIVATED", "remove": "REMOVED"}[operation],
                    AuthorizationAuditLog.outcome == "DENIED",
                )
            )
            == 1
        )


@pytest.mark.parametrize("backup_state", ["disabled-user", "unverified", "revoked-assignment", "disabled-role"])
def test_ineffective_backup_does_not_count(scenario, backup_state):
    with SessionLocal() as db, tenant_scope(minimal_background_context(1)):
        if backup_state == "disabled-user":
            db.get(IAMUser, scenario["backup_id"]).status = "DISABLED"
        elif backup_state == "unverified":
            user = db.get(IAMUser, scenario["backup_id"])
            user.email_verified, user.verification_required = False, True
        elif backup_state == "revoked-assignment":
            assignment = db.scalar(
                select(TenantUserRoleAssignment).where(
                    TenantUserRoleAssignment.tenant_user_id == scenario["backup_membership_id"]
                )
            )
            assignment.status, assignment.is_primary, assignment.revoked_at = "REVOKED", False, now()
        else:
            db.scalar(select(AuthorizationRole).where(AuthorizationRole.code == "TENANT_ADMIN")).status = "DISABLED"
        db.commit()
    assert mutate(scenario, "remove").status_code == 409


@pytest.mark.parametrize(
    "body,status",
    [
        ({"expected_version": 1}, 409),
        ({"expected_version": 1, "replacement_primary_role_code": "UNKNOWN"}, 422),
        ({"expected_version": 1, "replacement_primary_role_code": "PLATFORM_ADMIN"}, 403),
        ({"expected_version": 1, "replacement_primary_role_code": "TENANT_ADMIN"}, 403),
        ({"expected_version": 7, "replacement_primary_role_code": "VIEWER"}, 409),
        ({"expected_version": 1, "replacement_primary_role_code": "VIEWER", "is_platform_admin": True}, 422),
    ],
)
def test_invalid_revoke_is_atomic(scenario, body, status):
    result = mutate(scenario, "revoke", body=body)
    assert result.status_code == status, result.text
    with SessionLocal() as db, tenant_scope(minimal_background_context(1)):
        membership = db.get(TenantUser, scenario["membership_id"])
        assert membership.role_assignment_version == 1 and membership.role == "TENANT_ADMIN"
        assert roles.assigned_role_codes(db, membership) == {"TENANT_ADMIN"}
        assert (
            db.scalar(
                select(func.count())
                .select_from(TenantUserRoleAssignmentHistory)
                .where(TenantUserRoleAssignmentHistory.tenant_user_id == membership.id)
            )
            == 1
        )


@pytest.mark.parametrize("primary,replacement", [("SECURITY_ANALYST", None), ("TENANT_ADMIN", "SECURITY_ANALYST")])
def test_multirole_revoke_retains_ordinary_roles(scenario, primary, replacement):
    with SessionLocal() as db, tenant_scope(minimal_background_context(1)):
        roles.replace_roles(
            db,
            1,
            scenario["target_id"],
            role_codes=["TENANT_ADMIN", "SECURITY_ANALYST", "DEVELOPER"],
            primary_role_code=primary,
            expected_version=1,
            reason=None,
            actor_user_id=scenario["actor_id"],
            is_platform_admin=True,
        )
    result = mutate(scenario, "revoke", body={"expected_version": 2, "replacement_primary_role_code": replacement})
    assert result.status_code == 200, result.text
    assert result.json()["roles"] == ["DEVELOPER", "SECURITY_ANALYST"]
    assert result.json()["primary_role"] == "SECURITY_ANALYST"
    assert result.json()["role_assignment_version"] == 3


@pytest.mark.parametrize(
    "assignable,scope,status,expected",
    [
        (True, "TENANT", "ACTIVE", 200),
        (False, "TENANT", "ACTIVE", 422),
        (True, "PLATFORM", "ACTIVE", 422),
        (True, "TENANT", "DISABLED", 422),
    ],
)
def test_custom_replacement_catalog_rules(scenario, assignable, scope, status, expected):
    with SessionLocal() as db:
        stamp = now()
        db.add(
            AuthorizationRole(
                code="CUSTOM_REPLACEMENT",
                name="Custom replacement",
                scope=scope,
                status=status,
                is_system=False,
                is_assignable=assignable,
                version=1,
                created_at=stamp,
                updated_at=stamp,
            )
        )
        db.commit()
    response = mutate(
        scenario, "revoke", body={"expected_version": 1, "replacement_primary_role_code": "CUSTOM_REPLACEMENT"}
    )
    assert response.status_code == expected, response.text


@pytest.mark.parametrize("operation", ["revoke", "deactivate", "remove"])
def test_exact_tenant_membership_identity_required(scenario, operation):
    with SessionLocal() as db:
        stamp = now()
        other = Tenant(name="Mismatch", slug="governance-mismatch", status="ACTIVE", created_at=stamp, updated_at=stamp)
        db.add(other)
        db.commit()
        other_id = other.id
    wrong_tenant = scenario["url"].replace(tenant_uuid(1), tenant_uuid(other_id))
    assert mutate(scenario, operation, url=wrong_tenant).status_code == 404
    missing_tenant = scenario["url"].replace(tenant_uuid(1), str(uuid4()))
    assert mutate(scenario, operation, url=missing_tenant).status_code == 404
    missing_member = scenario["url"].rsplit("/", 1)[0] + "/" + str(uuid4())
    assert mutate(scenario, operation, url=missing_member).status_code == 404
    with SessionLocal() as db:
        db.get(
            TenantUser, scenario["membership_id"]
        ).role = "VIEWER"  # Primary-column manipulation cannot hide authority.
        db.commit()
    assert mutate(scenario, operation).status_code in {200, 204}


@pytest.mark.parametrize("self_target", [False, True])
@pytest.mark.parametrize("path", ["delete", "deactivate", "patch-status", "patch-combined", "replace", "revoke"])
def test_tenant_context_cannot_remove_admin_authority_even_when_secondary(scenario, password_hash, self_target, path):
    s = scenario
    with SessionLocal() as db, tenant_scope(minimal_background_context(1)):
        actor, token = native_user(db, password_hash)
        actor_member = member(db, actor, ("SECURITY_ANALYST", "TENANT_ADMIN"), primary="SECURITY_ANALYST")
        if self_target:
            target_id, mid = actor.id, actor_member.id
        else:
            target_id, mid = s["target_id"], s["membership_id"]
            db.commit()
            roles.replace_roles(
                db,
                1,
                target_id,
                role_codes=["TENANT_ADMIN", "SECURITY_ANALYST"],
                primary_role_code="SECURITY_ANALYST",
                expected_version=1,
                reason=None,
                actor_user_id=s["actor_id"],
                is_platform_admin=True,
            )
        db.commit()
        version = db.get(TenantUser, mid).role_assignment_version
    headers = {"Authorization": f"Bearer {token}", "X-Tenant-ID": tenant_uuid(1)}
    url = f"/api/tenants/{tenant_uuid(1)}/users/{membership_uuid(mid)}"
    if path == "delete":
        response = s["client"].delete(url, headers=headers)
    elif path == "deactivate":
        response = s["client"].post(url + "/deactivate", headers=headers)
    elif path.startswith("patch"):
        body = {"status": "DISABLED"}
        if path == "patch-combined":
            body.update(role="VIEWER", replace_all_roles=True)
        response = s["client"].patch(url, json=body, headers=headers)
    elif path == "replace":
        response = s["client"].put(
            f"/api/tenants/{tenant_uuid(1)}/users/{user_uuid(target_id)}/roles",
            headers=headers,
            json={"role_codes": ["VIEWER"], "expected_version": version, "primary_role_code": "VIEWER"},
        )
    else:
        response = s["client"].request(
            "DELETE",
            f"/api/tenants/{tenant_uuid(1)}/users/{user_uuid(target_id)}/roles/TENANT_ADMIN",
            headers=headers,
            json={"expected_version": version},
        )
    assert response.status_code == 403, response.text
    with SessionLocal() as db:
        membership = db.get(TenantUser, mid)
        assert membership.status == "ACTIVE" and membership.role_assignment_version == version
        assert "TENANT_ADMIN" in roles.assigned_role_codes(db, membership)


def test_ordinary_user_management_still_works(scenario, password_hash):
    with SessionLocal() as db:
        actor, token = native_user(db, password_hash)
        member(db, actor)
        ordinary = member(db, seed_user(db), ("VIEWER",))
        mid = ordinary.id
        db.commit()
    headers = {"Authorization": f"Bearer {token}", "X-Tenant-ID": tenant_uuid(1)}
    url = f"/api/tenants/{tenant_uuid(1)}/users/{membership_uuid(mid)}"
    assert (
        scenario["client"].patch(url, headers=headers, json={"role": "DEVELOPER", "status": "DISABLED"}).status_code
        == 200
    )
    assert scenario["client"].post(url + "/activate", headers=headers).status_code == 200
    assert scenario["client"].delete(url, headers=headers).status_code == 204


@pytest.mark.parametrize(
    "operations",
    [
        ("remove", "remove"),
        ("deactivate", "deactivate"),
        ("revoke", "revoke"),
        ("remove", "revoke"),
        ("deactivate", "remove"),
    ],
)
def test_concurrent_governance_leaves_one_effective_admin(scenario, operations):
    from app.main import app
    from app.services.tenant_service import _active_tenant_admin_count
    from fastapi.testclient import TestClient

    urls = [
        scenario["url"],
        scenario["url"].rsplit("/", 1)[0] + "/" + membership_uuid(scenario["backup_membership_id"]),
    ]
    barrier = Barrier(2)

    def attempt(index):
        with TestClient(app) as api:
            barrier.wait(timeout=10)
            return mutate({**scenario, "client": api}, operations[index], url=urls[index]).status_code

    with ThreadPoolExecutor(max_workers=2) as pool:
        responses = list(pool.map(attempt, range(2)))
    assert responses.count(409) == 1 and sum(code in {200, 204} for code in responses) == 1
    with SessionLocal() as db:
        assert _active_tenant_admin_count(db, 1) == 1


def test_audit_failure_rolls_back_role_and_lifecycle_mutation(scenario, monkeypatch):
    from app.main import app
    from app.services import audit_service
    from fastapi.testclient import TestClient

    original = audit_service.write_authorization_audit

    def fail_governance(db, **kwargs):
        if kwargs.get("action") in {"TENANT_ADMIN_REVOKED", "TENANT_ADMIN_DEACTIVATED", "TENANT_ADMIN_REMOVED"}:
            raise RuntimeError("simulated audit failure")
        return original(db, **kwargs)

    monkeypatch.setattr(audit_service, "write_authorization_audit", fail_governance)
    with TestClient(app, raise_server_exceptions=False) as api:
        for operation in ("revoke", "deactivate", "remove"):
            assert mutate({**scenario, "client": api}, operation).status_code == 500
    with SessionLocal() as db:
        membership = db.get(TenantUser, scenario["membership_id"])
        assert membership.status == "ACTIVE" and membership.role_assignment_version == 1
        assert roles.assigned_role_codes(db, membership) == {"TENANT_ADMIN"}


def test_native_login_and_same_token_sees_revoked_authority(scenario):
    with SessionLocal() as db:
        target = db.get(IAMUser, scenario["target_id"])
        token = native_auth_service.login(db, target.email, PASSWORD)
        db.commit()
    headers = {"Authorization": f"Bearer {token}", "X-Tenant-ID": tenant_uuid(1)}
    url = f"/api/tenants/{tenant_uuid(1)}/users"
    assert scenario["client"].get(url, headers=headers).status_code == 200
    assert mutate(scenario, "revoke").status_code == 200
    assert scenario["client"].get(url, headers=headers).status_code == 403
    assert scenario["client"].get("/api/projects", headers=headers).status_code == 200


def test_governance_catalog_migration_is_idempotent_and_protected():
    path = Path(__file__).resolve().parents[1] / "alembic/versions/103_tenant_admin_governance.py"
    spec = importlib.util.spec_from_file_location("governance_migration", path)
    migration = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(migration)
    with SessionLocal() as db:
        before = set(db.execute(select(AuthorizationRolePermission.role_id, AuthorizationRolePermission.permission_id)))
        migration._seed(db.connection())
        migration._seed(db.connection())
        assert (
            set(db.execute(select(AuthorizationRolePermission.role_id, AuthorizationRolePermission.permission_id)))
            == before
        )
        permission = db.scalar(
            select(AuthorizationPermission).where(AuthorizationPermission.code == TENANT_ADMIN_GOVERNANCE_PERMISSION)
        )
        mappings = list(
            db.scalars(
                select(AuthorizationRolePermission).where(AuthorizationRolePermission.permission_id == permission.id)
            )
        )
        assert len(mappings) == 1 and mappings[0].is_protected
        assert db.get(AuthorizationRole, mappings[0].role_id).code == "PLATFORM_ADMIN"
        assert permission.scope == "PLATFORM"
        assert all(code.startswith("platform:") for code in PLATFORM_ADMIN_PERMISSIONS_V6)


@pytest.mark.parametrize("operation", ["revoke", "deactivate", "remove"])
def test_ordinary_membership_is_not_a_governance_target(scenario, operation):
    with SessionLocal() as db:
        ordinary = member(db, seed_user(db), ("VIEWER",))
        mid = ordinary.id
        db.commit()
    url = scenario["url"].rsplit("/", 1)[0] + "/" + membership_uuid(mid)
    assert mutate(scenario, operation, url=url).status_code == 409
    with SessionLocal() as db:
        assert db.get(TenantUser, mid).status == "ACTIVE"


@pytest.mark.parametrize("operation", ["revoke", "remove"])
def test_governance_can_manage_preserved_disabled_admin_assignments(scenario, operation):
    assert mutate(scenario, "deactivate").status_code == 200
    assert mutate(scenario, operation).status_code == (200 if operation == "revoke" else 204)
    with SessionLocal() as db:
        membership = db.get(TenantUser, scenario["membership_id"])
        if operation == "revoke":
            assert membership.status == "DISABLED" and roles.assigned_role_codes(db, membership) == {"VIEWER"}
        else:
            assert membership is None


@pytest.mark.parametrize("replacement_state", ["new", "revoked", "earlier"])
def test_explicit_replacement_grant_reactivation_and_earlier_primary(scenario, replacement_state):
    with SessionLocal() as db, tenant_scope(minimal_background_context(1)):
        target = db.get(IAMUser, scenario["target_id"])
        if replacement_state == "earlier":
            # Create a fresh membership where the replacement has a smaller PK
            # than the primary administrator assignment.
            target = seed_user(db)
            membership = member(db, target, ("VIEWER", "TENANT_ADMIN"), primary="TENANT_ADMIN")
            mid = membership.id
        else:
            mid = scenario["membership_id"]
            if replacement_state == "revoked":
                role = db.scalar(select(AuthorizationRole).where(AuthorizationRole.code == "VIEWER"))
                stamp = now()
                db.add(
                    TenantUserRoleAssignment(
                        tenant_id=1,
                        tenant_user_id=mid,
                        role_id=role.id,
                        status="REVOKED",
                        is_primary=False,
                        assignment_source="SYSTEM",
                        assigned_at=stamp,
                        revoked_at=stamp,
                        version=2,
                        created_at=stamp,
                        updated_at=stamp,
                    )
                )
        db.commit()
    url = scenario["url"].rsplit("/", 1)[0] + "/" + membership_uuid(mid)
    response = mutate(scenario, "revoke", url=url)
    assert response.status_code == 200, response.text
    assert response.json()["primary_role"] == "VIEWER"
    assert response.json()["role_assignment_version"] == 2
    with SessionLocal() as db, tenant_scope(minimal_background_context(1)):
        history = list(
            db.scalars(
                select(TenantUserRoleAssignmentHistory).where(TenantUserRoleAssignmentHistory.tenant_user_id == mid)
            )
        )
        assert any(row.event_type == "REVOKED" and row.role_code_snapshot == "TENANT_ADMIN" for row in history)
        assert any(row.event_type == "PRIMARY_CHANGED" and row.role_code_snapshot == "VIEWER" for row in history)
        if replacement_state == "revoked":
            assert any(row.event_type == "REACTIVATED" and row.role_code_snapshot == "VIEWER" for row in history)


def test_revoke_does_not_reassign_or_drop_unrelated_catalog_roles(scenario):
    with SessionLocal() as db, tenant_scope(minimal_background_context(1)):
        target = seed_user(db)
        target_id = target.id
        membership = member(db, target, ("TENANT_ADMIN", "SECURITY_ANALYST", "DEVELOPER"))
        mid = membership.id
        db.scalar(select(AuthorizationRole).where(AuthorizationRole.code == "SECURITY_ANALYST")).is_assignable = False
        db.scalar(select(AuthorizationRole).where(AuthorizationRole.code == "DEVELOPER")).status = "DISABLED"
        db.commit()
    response = mutate(scenario, "revoke", url=scenario["url"].rsplit("/", 1)[0] + "/" + membership_uuid(mid))
    assert response.status_code == 200, response.text
    with SessionLocal() as db, tenant_scope(minimal_background_context(1)):
        rows = roles.list_assignments(db, 1, target_id)[1]
        assert {role.code for assignment, role in rows if assignment.status == "ACTIVE"} == {
            "VIEWER",
            "SECURITY_ANALYST",
            "DEVELOPER",
        }


def test_custom_user_manager_cannot_bypass_admin_membership_protection(scenario, password_hash):
    with SessionLocal() as db:
        stamp = now()
        custom = AuthorizationRole(
            code="CUSTOM_USER_MANAGER",
            name="Custom user manager",
            scope="TENANT",
            status="ACTIVE",
            is_system=False,
            is_assignable=True,
            version=1,
            created_at=stamp,
            updated_at=stamp,
        )
        db.add(custom)
        db.flush()
        permission = db.scalar(
            select(AuthorizationPermission).where(AuthorizationPermission.code == "tenant:user:update")
        )
        db.add(
            AuthorizationRolePermission(
                role_id=custom.id, permission_id=permission.id, is_protected=False, created_at=stamp, updated_at=stamp
            )
        )
        actor, token = native_user(db, password_hash)
        member(db, actor, (custom.code,))
        db.commit()
    headers = {"Authorization": f"Bearer {token}", "X-Tenant-ID": tenant_uuid(1)}
    url = f"/api/tenants/{tenant_uuid(1)}/users/{membership_uuid(scenario['membership_id'])}"
    assert scenario["client"].delete(url, headers=headers).status_code == 403
    assert scenario["client"].post(url + "/deactivate", headers=headers).status_code == 403


def test_governance_contract_and_protected_catalog(scenario):
    from app.core.security import _resolve_context
    from app.main import app
    from app.services.authorization_catalog_service import CatalogProblem, replace_role_permissions

    from tests.phase6_helpers import identity_claims

    contract = app.openapi()
    path = "/api/platform/tenants/{tenant_id}/administrators/{membership_id}/revoke"
    operation = contract["paths"][path]["post"]
    for parameter in operation["parameters"]:
        if parameter["name"] in {"tenant_id", "membership_id"}:
            assert parameter["schema"]["format"] == "uuid"
    response = contract["components"]["schemas"]["TenantAdministratorGovernanceResponse"]
    for field in ("tenant_id", "membership_id", "user_id"):
        assert response["properties"][field]["format"] == "uuid"
    detail = scenario["client"].get(f"/api/platform/tenants/{tenant_uuid(1)}", headers=scenario["headers"])
    assert detail.status_code == 200, detail.text
    admin = next(
        item for item in detail.json()["current_administrators"] if item["user_id"] == user_uuid(scenario["target_id"])
    )
    assert admin["membership_id"] == membership_uuid(scenario["membership_id"])
    assert admin["role_assignment_version"] == 1
    with SessionLocal() as db:
        actor = db.get(IAMUser, scenario["actor_id"])
        context = _resolve_context(db, identity_claims(actor), None, allow_platform_context=True)
        platform_role = db.scalar(select(AuthorizationRole).where(AuthorizationRole.code == "PLATFORM_ADMIN"))
        with pytest.raises(CatalogProblem) as caught:
            replace_role_permissions(
                db,
                platform_role.id,
                permission_codes=sorted(PLATFORM_ADMIN_PERMISSIONS_V6 - {TENANT_ADMIN_GOVERNANCE_PERMISSION}),
                expected_version=platform_role.version,
                reason="protected mapping test",
                context=context,
                request=None,
            )
        assert caught.value.status_code == 409


def test_two_requests_for_same_role_version_have_one_winner(scenario):
    from app.main import app
    from fastapi.testclient import TestClient

    barrier = Barrier(2)

    def attempt(_index):
        with TestClient(app) as api:
            barrier.wait(timeout=10)
            return mutate({**scenario, "client": api}, "revoke").status_code

    with ThreadPoolExecutor(max_workers=2) as pool:
        result = list(pool.map(attempt, range(2)))
    assert sorted(result) == [200, 409]

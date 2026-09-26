"""Phase 3 lifecycle uses real PostgreSQL, existing RBAC and native JWTs."""

from dataclasses import replace
from datetime import UTC, datetime

import pytest
from app.core.security import _resolve_context, get_current_tenant_context
from app.db import SessionLocal
from app.models import AuthorizationAuditLog, IAMUser, NativeUserCredential, Tenant, TenantUser
from app.routers.native_auth import router as native_router
from app.routers.platform import router as platform_router
from app.routers.tenants import router as tenant_router
from app.services import audit_service
from app.services import native_auth_service as auth
from app.services import native_enrollment_service as enrollment
from app.services import native_jwt_service as tokens
from app.services import user_management_service as management
from fastapi import FastAPI, HTTPException
from fastapi.testclient import TestClient
from sqlalchemy import func, select

from tests.phase6_helpers import seed_platform_grant, seed_user
from tests.phase9_helpers import seed_role_membership
from tests.test_native_iam_phase2 import PASSWORD, context, credential, enrolled
from tests.test_native_iam_phase2 import native_config as native_config


@pytest.fixture
def setup(native_config):
    with SessionLocal() as db:
        target = enrolled(db)
        actor = context(db)
        actor = replace(
            actor,
            permissions=actor.permissions
            | frozenset({"platform:user:read", "platform:user:write", "tenant:user:read", "tenant:user:update"}),
        )
        now = datetime.now(UTC)
        db.add(Tenant(id=2, name="Hospital B", slug="hospital-b", status="ACTIVE", created_at=now, updated_at=now))
        db.flush()
        enrollment.add_membership(db, actor, 2, target.id, ["VIEWER"])
        db.commit()
        token = auth.login(db, target.email, PASSWORD)
        db.commit()
        members = {m.tenant_id: m.id for m in db.scalars(select(TenantUser).where(TenantUser.user_id == target.id))}
        target_id = target.id
    api = FastAPI()
    api.include_router(platform_router)
    api.include_router(tenant_router)
    api.include_router(native_router)
    current = {"actor": actor}
    api.dependency_overrides[get_current_tenant_context] = lambda: current["actor"]
    with TestClient(api) as client:
        yield client, current, target_id, members, token


def tenant_actor(current, tenant_id=1):
    current["actor"] = replace(
        current["actor"],
        tenant_id=tenant_id,
        is_platform_admin=False,
        roles=frozenset({"TENANT_ADMIN"}),
        permissions=frozenset({"tenant:user:read", "tenant:user:update", "tenant:user:invite"}),
    )


def test_platform_list_filters_detail_and_redaction(setup):
    client, actor, uid, members, token = setup
    for query in [
        "search=john",
        "role=SECURITY_ANALYST",
        "tenant_id=2&role=VIEWER",
        "provider=NATIVE",
        "local_status=ACTIVE&search=john",
    ]:
        response = client.get("/api/platform/users?" + query)
        assert response.status_code == 200, response.text
        assert any(u["id"] == uid for u in response.json()["items"])
    assert client.get("/api/platform/users?tenant_id=2&role=SECURITY_ANALYST").json()["total"] == 0
    page = client.get("/api/platform/users?page_size=1&sort_by=name&sort_order=asc").json()
    assert len(page["items"]) == 1 and page["total"] >= 2
    detail = client.get(f"/api/platform/users/{uid}")
    assert detail.status_code == 200, detail.text
    data = detail.json()
    assert len(data["tenant_memberships"]) == 2 and data["providers"] == ["NATIVE"]
    assert data["last_login_at"] and data["security"]["failed_login_count"] == 0
    assert set(data["tenant_memberships"][0]["roles"]) or set(data["tenant_memberships"][1]["roles"])
    for secret in [
        "password_hash",
        "security_version",
        "provider_identifier",
        "token_hash",
        "private_key",
        "access_token",
    ]:
        assert secret not in detail.text


def test_tenant_list_detail_search_and_audit_private(setup):
    client, current, uid, members, token = setup
    with SessionLocal() as db:
        outsider = seed_user(db, email="outsider@example.test")
        outsider_id = outsider.id
        audit_service.write_authorization_audit(db, action="ONLY_B", target_user_id=uid, tenant_id=2)
        audit_service.write_authorization_audit(db, action="ONLY_A", target_user_id=uid, tenant_id=1)
        db.commit()
    tenant_actor(current)
    page = client.get("/api/tenants/1/users?page=1&search=john&role=DEVELOPER").json()
    assert page["total"] == 1 and page["items"][0]["user_id"] == uid
    assert client.get("/api/tenants/1/users?page=1&search=outsider").json()["total"] == 0
    detail = client.get(f"/api/tenants/1/users/{members[1]}")
    assert detail.status_code == 200, detail.text
    assert "Hospital B" not in detail.text and "security" not in detail.json()
    assert "ONLY_A" in detail.text and "ONLY_B" not in detail.text
    assert client.get(f"/api/tenants/1/users/{members[2]}").status_code == 404
    assert client.get(f"/api/tenants/2/users/{members[2]}").status_code == 404
    assert client.get(f"/api/platform/users/{outsider_id}").status_code == 403
    assert "outsider" not in client.get("/api/tenants/1/user-candidates?q=outsider").text


@pytest.mark.parametrize(
    "field,value",
    [
        ("email", "changed@example.test"),
        ("provider_identifier", "bad"),
        ("security_version", 99),
        ("email_verified", True),
        ("external_subject", "bad"),
        ("first_name", "\n"),
    ],
)
def test_profile_rejects_sensitive_or_invalid_fields(setup, field, value):
    client, _, uid, _, _ = setup
    assert client.patch(f"/api/platform/users/{uid}/profile", json={field: value}).status_code == 422


def test_profile_update_scope_and_audit(setup):
    client, current, uid, members, _ = setup
    tenant_actor(current)
    response = client.patch(
        f"/api/tenants/1/users/{members[1]}/profile",
        json={"first_name": "Jane", "last_name": "Jones", "phone": "+91 123456789"},
    )
    assert response.status_code == 200, response.text
    assert response.json()["display_name"] == "Jane Jones"
    assert client.patch(f"/api/tenants/1/users/{members[2]}/profile", json={"first_name": "Eve"}).status_code == 404
    with SessionLocal() as db:
        row = db.scalar(select(AuthorizationAuditLog).where(AuthorizationAuditLog.action == "USER_UPDATED"))
        assert row.tenant_id == 1 and row.old_value["first_name"] == "John" and row.new_value["first_name"] == "Jane"


def test_membership_deactivate_preserves_global_and_other_tenant(setup):
    client, current, uid, members, token = setup
    tenant_actor(current)
    response = client.post(f"/api/tenants/1/users/{members[1]}/deactivate")
    assert response.status_code == 200, response.text
    with SessionLocal() as db:
        assert db.get(IAMUser, uid).status == "ACTIVE"
        claims = tokens.validate_token(token)
        with pytest.raises(HTTPException):
            _resolve_context(db, claims, "1")
        assert _resolve_context(db, claims, "2").roles == frozenset({"VIEWER"})
    response = client.post(f"/api/tenants/1/users/{members[1]}/activate")
    assert response.status_code == 200, response.text
    with SessionLocal() as db:
        assert "analysis:run" in _resolve_context(db, tokens.validate_token(token), "1").permissions


def test_global_disable_and_reenable_preserve_memberships(setup):
    client, current, uid, members, token = setup
    client.post(f"/api/tenants/1/users/{members[1]}/deactivate")
    response = client.patch(f"/api/platform/users/{uid}/status", json={"status": "DISABLED"})
    assert response.status_code == 200, response.text
    with SessionLocal() as db:
        assert db.scalar(select(func.count(TenantUser.id)).where(TenantUser.user_id == uid)) == 2
        for tid in ["1", "2"]:
            with pytest.raises(HTTPException):
                _resolve_context(db, tokens.validate_token(token), tid)
    assert client.patch(f"/api/platform/users/{uid}/status", json={"status": "ACTIVE"}).status_code == 200
    with SessionLocal() as db:
        assert db.get(TenantUser, members[1]).status == "DISABLED"
        assert db.get(TenantUser, members[2]).status == "ACTIVE"
        with pytest.raises(HTTPException):
            tokens.resolve_user(db, tokens.validate_token(token))
        actions = set(db.scalars(select(AuthorizationAuditLog.action)))
        assert {"USER_DISABLED", "USER_ENABLED"} <= actions


def test_unlock_and_force_change(setup):
    client, current, uid, members, token = setup
    with SessionLocal() as db:
        user = db.get(IAMUser, uid)
        for _ in range(5):
            auth.login(db, user.email, "wrong")
            db.commit()
    response = client.post(f"/api/platform/users/{uid}/unlock")
    assert response.status_code == 200, response.text
    with SessionLocal() as db:
        c = credential(db, db.get(IAMUser, uid))
        assert c.failed_login_count == 0 and c.locked_until is None and c.locked_at is None
    response = client.post(f"/api/platform/users/{uid}/force-password-change")
    assert response.status_code == 200, response.text
    with SessionLocal() as db:
        assert db.get(IAMUser, uid).status == "FORCE_PASSWORD_CHANGE"
        with pytest.raises(HTTPException):
            tokens.resolve_user(db, tokens.validate_token(token))
        assert {"USER_UNLOCKED", "FORCE_PASSWORD_CHANGE_SET"} <= set(db.scalars(select(AuthorizationAuditLog.action)))
    assert client.patch(f"/api/platform/users/{uid}/status", json={"status": "ACTIVE"}).status_code == 409
    assert client.patch(f"/api/platform/users/{uid}/status", json={"status": "DISABLED"}).status_code == 200
    assert client.patch(f"/api/platform/users/{uid}/status", json={"status": "ACTIVE"}).status_code == 409


@pytest.mark.parametrize(
    "path,method,body",
    [
        ("unlock", "post", None),
        ("force-password-change", "post", None),
        ("status", "patch", {"status": "DISABLED"}),
        ("status", "patch", {"status": "ACTIVE"}),
    ],
)
def test_tenant_admin_cannot_change_global_state(setup, path, method, body):
    client, current, uid, _, _ = setup
    tenant_actor(current)
    response = getattr(client, method)(f"/api/platform/users/{uid}/{path}", **({"json": body} if body else {}))
    assert response.status_code == 403


def test_roles_version_and_same_jwt(setup):
    client, current, uid, members, token = setup
    tenant_actor(current)
    response = client.put(
        f"/api/tenants/1/users/{uid}/roles",
        json={"role_codes": ["VIEWER"], "primary_role_code": "VIEWER", "expected_version": 1},
    )
    assert response.status_code == 200, response.text
    with SessionLocal() as db:
        assert "analysis:run" not in _resolve_context(db, tokens.validate_token(token), "1").permissions
    assert (
        client.put(
            f"/api/tenants/1/users/{uid}/roles", json={"role_codes": ["DEVELOPER"], "expected_version": 1}
        ).status_code
        == 409
    )
    for role, expected in [("TENANT_ADMIN", 403), ("PLATFORM_ADMIN", 422)]:
        assert (
            client.post(
                f"/api/tenants/1/users/{uid}/roles", json={"role_code": role, "expected_version": 2}
            ).status_code
            == expected
        )
    assert (
        client.post(
            f"/api/tenants/2/users/{uid}/roles", json={"role_code": "DEVELOPER", "expected_version": 1}
        ).status_code
        == 404
    )


def test_hcl_membership_lifecycle_no_native_credentials(setup):
    client, current, _, _, _ = setup
    with SessionLocal() as db:
        user, member, _ = seed_role_membership(db)
        uid, mid = user.id, member.id
    response = client.post(f"/api/platform/users/{uid}/force-password-change")
    assert response.status_code == 409
    assert client.post(f"/api/tenants/1/users/{mid}/deactivate").status_code == 200
    assert client.post(f"/api/tenants/1/users/{mid}/activate").status_code == 200
    assert client.patch(f"/api/platform/users/{uid}/status", json={"status": "DISABLED"}).status_code == 200
    assert client.patch(f"/api/platform/users/{uid}/status", json={"status": "ACTIVE"}).status_code == 200
    with SessionLocal() as db:
        assert db.scalar(select(NativeUserCredential.id).where(NativeUserCredential.user_id == uid)) is None


def test_final_platform_admin_protected(setup):
    client, _, uid, _, _ = setup
    with SessionLocal() as db:
        seed_platform_grant(db, db.get(IAMUser, uid))
        db.commit()
    assert client.patch(f"/api/platform/users/{uid}/status", json={"status": "DISABLED"}).status_code == 409


def test_profile_audit_failure_rollback(setup, monkeypatch):
    _, current, uid, _, _ = setup

    def fail(*args, **kwargs):
        raise RuntimeError("audit unavailable")

    monkeypatch.setattr(audit_service, "write_authorization_audit", fail)
    with SessionLocal() as db:
        with pytest.raises(RuntimeError):
            management.update_profile(db, uid, {"first_name": "Unsafe"}, actor_user_id=current["actor"].user_id)
        db.commit()
        assert db.get(IAMUser, uid).first_name == "John"


def race(*operations):
    from concurrent.futures import ThreadPoolExecutor
    from threading import Barrier

    barrier = Barrier(len(operations))

    def execute(operation):
        barrier.wait(timeout=10)
        return operation()

    with ThreadPoolExecutor(max_workers=len(operations)) as executor:
        return list(executor.map(execute, operations))


def attempt_login(uid):
    with SessionLocal() as db:
        email = db.get(IAMUser, uid).email
        try:
            result = auth.login(db, email, PASSWORD)
            db.commit()
            return result
        except HTTPException:
            db.commit()
            return None


def test_concurrent_disable_vs_login(setup):
    client, current, uid, members, token = setup
    disabled, issued = race(
        lambda: client.patch(f"/api/platform/users/{uid}/status", json={"status": "DISABLED"}),
        lambda: attempt_login(uid),
    )
    assert disabled.status_code == 200, disabled.text
    with SessionLocal() as db:
        assert db.get(IAMUser, uid).status == "DISABLED"
        for jwt_value in [token, issued]:
            if jwt_value:
                with pytest.raises(HTTPException):
                    _resolve_context(db, tokens.validate_token(jwt_value), "2")
        assert (
            db.scalar(
                select(func.count())
                .select_from(AuthorizationAuditLog)
                .where(AuthorizationAuditLog.target_user_id == uid, AuthorizationAuditLog.action == "USER_DISABLED")
            )
            == 1
        )


def test_concurrent_membership_disable_vs_authorization(setup):
    client, current, uid, members, token = setup
    tenant_actor(current)

    def request_context():
        with SessionLocal() as db:
            try:
                return _resolve_context(db, tokens.validate_token(token), "1").tenant_id
            except HTTPException:
                return None

    changed, result = race(lambda: client.post(f"/api/tenants/1/users/{members[1]}/deactivate"), request_context)
    assert changed.status_code == 200
    assert result in (None, 1)  # An already-running request may precede commit.
    assert request_context() is None
    with SessionLocal() as db:
        assert _resolve_context(db, tokens.validate_token(token), "2").tenant_id == 2
        assert db.get(IAMUser, uid).status == "ACTIVE"


def test_concurrent_role_replace_vs_grant(setup):
    client, current, uid, members, token = setup
    tenant_actor(current)
    results = race(
        lambda: client.put(f"/api/tenants/1/users/{uid}/roles", json={"role_codes": ["VIEWER"], "expected_version": 1}),
        lambda: client.post(f"/api/tenants/1/users/{uid}/roles", json={"role_code": "VIEWER", "expected_version": 1}),
    )
    assert sorted(r.status_code for r in results) == [200, 409]
    with SessionLocal() as db:
        assert db.get(TenantUser, members[1]).role_assignment_version == 2


def test_concurrent_enable_vs_disable(setup):
    client, current, uid, members, token = setup
    assert client.patch(f"/api/platform/users/{uid}/status", json={"status": "DISABLED"}).status_code == 200
    results = race(
        *[
            lambda status=status: client.patch(f"/api/platform/users/{uid}/status", json={"status": status})
            for status in ("ACTIVE", "DISABLED")
        ]
    )
    assert all(r.status_code == 200 for r in results), [r.text for r in results]
    with SessionLocal() as db:
        assert db.get(IAMUser, uid).status in ("ACTIVE", "DISABLED")
        with pytest.raises(HTTPException):
            _resolve_context(db, tokens.validate_token(token), "2")
        assert db.get(TenantUser, members[2]).status == "ACTIVE"


def test_concurrent_unlock_vs_login(setup):
    client, current, uid, members, token = setup
    with SessionLocal() as db:
        user = db.get(IAMUser, uid)
        user.status = "LOCKED"
        cred = credential(db, db.get(IAMUser, uid))
        cred.failed_login_count = 5
        cred.locked_at = datetime.now(UTC)
        cred.security_version += 1
        db.commit()
    unlocked, issued = race(lambda: client.post(f"/api/platform/users/{uid}/unlock"), lambda: attempt_login(uid))
    assert unlocked.status_code == 200, unlocked.text
    with SessionLocal() as db:
        assert db.get(IAMUser, uid).status == "ACTIVE"
        cred = credential(db, db.get(IAMUser, uid))
        assert cred.failed_login_count == 0 and cred.locked_at is None and cred.locked_until is None
        assert (
            db.scalar(
                select(func.count())
                .select_from(AuthorizationAuditLog)
                .where(AuthorizationAuditLog.target_user_id == uid, AuthorizationAuditLog.action == "USER_UNLOCKED")
            )
            == 1
        )
        with pytest.raises(HTTPException):
            _resolve_context(db, tokens.validate_token(token), "2")


def test_platform_assigns_admin_tenant_cannot_remove_it(setup):
    client, current, uid, members, token = setup
    response = client.post(
        f"/api/tenants/1/users/{uid}/roles", json={"role_code": "TENANT_ADMIN", "expected_version": 1}
    )
    assert response.status_code == 200, response.text
    tenant_actor(current)
    response = client.put(f"/api/tenants/1/users/{uid}/roles", json={"role_codes": ["VIEWER"], "expected_version": 2})
    assert response.status_code == 403, response.text
    with SessionLocal() as db:
        assert "TENANT_ADMIN" in _resolve_context(db, tokens.validate_token(token), "1").roles
        assert _resolve_context(db, tokens.validate_token(token), "2").roles == frozenset({"VIEWER"})


def test_profile_payload_scope_and_role_assignment_tampering(setup):
    client, current, uid, members, token = setup
    tenant_actor(current)
    assert (
        client.patch(
            f"/api/tenants/1/users/{members[1]}/profile", json={"tenant_id": 2, "first_name": "Wrong"}
        ).status_code
        == 422
    )
    assert (
        client.patch(
            f"/api/tenants/2/users/{members[2]}/profile", headers={"X-Tenant-ID": "1"}, json={"first_name": "Wrong"}
        ).status_code
        == 404
    )
    assert client.post(f"/api/tenants/1/users/{members[2]}/deactivate").status_code == 404
    assert client.get(f"/api/tenants/1/users/{members[2]}/audit").status_code == 404
    assert client.post(f"/api/tenants/2/native-users/{uid}/resend-activation").status_code == 403
    assert client.post(f"/api/tenants/1/native-users/{uid}/resend-activation").status_code == 404


def test_hcl_same_principal_obeys_membership_roles_and_global_status(setup):
    client, current, _, _, _ = setup
    with SessionLocal() as db:
        user, a, _ = seed_role_membership(db, role="DEVELOPER")
        user, b, _ = seed_role_membership(db, tenant_id=2, user=user)
        uid, aid = user.id, a.id
        claims = {
            "iss": user.external_issuer,
            "sub": user.external_subject,
            "email": user.email,
            "name": user.display_name,
            "preferred_username": user.user_principal_name,
            "employee_id": user.employee_id,
        }
        assert "remediation:write" in _resolve_context(db, claims, "1").permissions
        assert _resolve_context(db, claims, "2").roles == frozenset({"VIEWER"})
    tenant_actor(current)
    assert client.post(f"/api/tenants/1/users/{aid}/deactivate").status_code == 200
    with SessionLocal() as db:
        with pytest.raises(HTTPException):
            _resolve_context(db, claims, "1")
        assert _resolve_context(db, claims, "2").tenant_id == 2
    current["actor"] = replace(
        current["actor"], is_platform_admin=True, permissions=frozenset({"platform:user:manage_status"})
    )
    assert client.patch(f"/api/platform/users/{uid}/status", json={"status": "DISABLED"}).status_code == 200
    with SessionLocal() as db:
        for tenant_id in ["1", "2"]:
            with pytest.raises(HTTPException):
                _resolve_context(db, claims, tenant_id)
        assert db.scalar(select(NativeUserCredential.id).where(NativeUserCredential.user_id == uid)) is None


def test_global_transition_audit_failure_is_atomic(setup, monkeypatch):
    from app.services.account_state_service import transition_account

    client, current, uid, members, token = setup

    def fail(*args, **kwargs):
        raise RuntimeError("audit unavailable")

    monkeypatch.setattr(audit_service, "write_authorization_audit", fail)
    with SessionLocal() as db:
        with pytest.raises(RuntimeError):
            transition_account(db, uid, "DISABLED", actor_user_id=current["actor"].user_id, explicitly_authorized=True)
        db.commit()
        assert db.get(IAMUser, uid).status == "ACTIVE"
        assert _resolve_context(db, tokens.validate_token(token), "2").tenant_id == 2


def test_add_existing_member_reuses_identity_and_rejects_duplicate(setup):
    client, current, uid, members, token = setup
    with SessionLocal() as db:
        now = datetime.now(UTC)
        db.add(Tenant(id=3, name="Medical C", slug="medical-c", status="ACTIVE", created_at=now, updated_at=now))
        db.commit()
    response = client.post(
        "/api/tenants/3/memberships", json={"user_id": uid, "role_codes": ["TENANT_ADMIN", "VIEWER"]}
    )
    assert response.status_code == 201, response.text
    assert response.json()["user_id"] == uid
    assert client.post("/api/tenants/3/memberships", json={"user_id": uid, "role_codes": ["VIEWER"]}).status_code == 409
    with SessionLocal() as db:
        assert db.scalar(select(func.count()).select_from(TenantUser).where(TenantUser.user_id == uid)) == 3
        assert _resolve_context(db, tokens.validate_token(token), "3").roles == frozenset({"TENANT_ADMIN", "VIEWER"})
    tenant_actor(current)
    assert client.post("/api/tenants/3/memberships", json={"user_id": uid, "role_codes": ["VIEWER"]}).status_code == 403


def test_two_administrators_cannot_silently_overwrite_role_replacement(setup):
    from app.services import tenant_role_assignment_service as roles

    client, current, uid, members, token = setup
    with SessionLocal() as db:
        first, _, _ = seed_role_membership(db, role="TENANT_ADMIN")
        first_id = first.id
        second, _, _ = seed_role_membership(db, role="TENANT_ADMIN")
        second_id = second.id

    def replace_as(actor_id, code):
        with SessionLocal() as db:
            try:
                roles.replace_roles(
                    db,
                    1,
                    uid,
                    role_codes=[code],
                    primary_role_code=code,
                    expected_version=1,
                    reason="Concurrent administrators",
                    actor_user_id=actor_id,
                    is_platform_admin=False,
                )
                return "SUCCESS"
            except roles.AssignmentProblem as exc:
                return exc.code.value

    results = race(lambda: replace_as(first_id, "VIEWER"), lambda: replace_as(second_id, "DEVELOPER"))
    assert sorted(results) == ["IAM_TENANT_ROLE_VERSION_CONFLICT", "SUCCESS"]
    with SessionLocal() as db:
        assert db.get(TenantUser, members[1]).role_assignment_version == 2

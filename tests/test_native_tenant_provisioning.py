"""Provisioning transactions and direct HTTP authorization against PostgreSQL."""

import base64

import pytest
from app.core.security import get_current_claims
from app.db import SessionLocal
from app.models import AccountActionToken, IAMUser, SecurityMailOutbox, Tenant, TenantUser, UserIdentity
from app.services import native_auth_service, security_mail_outbox
from app.services.tenant_role_assignment_service import effective_role_codes
from app.settings import get_settings
from sqlalchemy import func, select

from tests.phase6_helpers import identity_claims, seed_user
from tests.phase7_helpers import seed_requester
from tests.phase9_helpers import seed_role_membership


@pytest.fixture
def provisioning(client, monkeypatch):
    settings = get_settings()
    monkeypatch.setattr(settings, "native_user_creation_enabled", True)
    monkeypatch.setattr(settings, "native_security_outbox_enabled", True)
    monkeypatch.setattr(settings, "native_security_outbox_key", base64.b64encode(b"p" * 32).decode())
    with SessionLocal() as db:
        actor = seed_requester(db)
        actor_id = actor.id
    return client, actor_id


def payload(slug="olympus", email="ajmer@example.test"):
    return {"name": "Olympus Healthcare", "slug": slug, "initial_admin_invitation": {
        "first_name": "Ajmer", "last_name": "Khan", "email": email,
    }}


def activation_secret(db, user_id):
    row = db.scalar(select(SecurityMailOutbox).where(SecurityMailOutbox.user_id == user_id,
                                                   SecurityMailOutbox.status == "PENDING"))
    return security_mail_outbox.cipher().decrypt(
        row.payload[:12], row.payload[12:], security_mail_outbox.aad(row.token_id, row.purpose, row.recipient),
    ).decode()


def test_invited_admin_pending_atomic_outbox_then_activation(provisioning):
    client, actor_id = provisioning
    response = client.post("/api/tenants", json=payload())
    assert response.status_code == 201, response.text
    result = response.json()
    tid, uid = result["tenant"]["id"], result["initial_administrator"]["user_id"]
    assert result["tenant"]["status"] == "PENDING"
    with SessionLocal() as db:
        assert db.scalar(select(TenantUser.id).where(TenantUser.tenant_id == tid, TenantUser.user_id == actor_id)) is None
        member = db.scalar(select(TenantUser).where(TenantUser.tenant_id == tid, TenantUser.user_id == uid))
        assert effective_role_codes(db, member) == {"TENANT_ADMIN"}
        assert db.get(IAMUser, uid).status == "PENDING_EMAIL_VERIFICATION"
        raw = activation_secret(db, uid)
        assert raw not in response.text
        native_auth_service.activate(db, raw, "a long native test passphrase")
        db.commit()
        assert db.get(Tenant, tid).status == "ACTIVE"
        assert db.get(IAMUser, uid).email_verified


def test_outbox_failure_rolls_back_every_provisioned_row(provisioning, monkeypatch):
    client, _ = provisioning
    # Authentication may mirror the requester's HCL identity independently of provisioning.
    assert client.get("/api/platform/tenants").status_code == 200
    with SessionLocal() as db:
        before = {model: db.scalar(select(func.count()).select_from(model)) for model in
                  (Tenant, IAMUser, TenantUser, UserIdentity, AccountActionToken, SecurityMailOutbox)}
    def fail(*args, **kwargs):
        raise RuntimeError("simulated outbox failure")
    monkeypatch.setattr(security_mail_outbox, "enqueue", fail)
    response = client.post("/api/tenants", json=payload())
    assert response.status_code == 500
    with SessionLocal() as db:
        for model, count in before.items():
            assert db.scalar(select(func.count()).select_from(model)) == count


def test_reuse_native_identity_across_tenants_without_hcl_linking(provisioning):
    client, _ = provisioning
    with SessionLocal() as db:
        hcl = seed_user(db, email="ajmer@example.test")
        hcl_id = hcl.id
        db.commit()
    first = client.post("/api/tenants", json=payload()).json()
    uid = first["initial_administrator"]["user_id"]
    assert uid != hcl_id
    with SessionLocal() as db:
        native_auth_service.activate(db, activation_secret(db, uid), "a long native test passphrase")
        db.commit()
    second_response = client.post("/api/tenants", json=payload("medtech"))
    assert second_response.status_code == 201, second_response.text
    second = second_response.json()
    assert second["initial_administrator"]["user_id"] == uid
    assert second["tenant"]["status"] == "ACTIVE"
    with SessionLocal() as db:
        assert db.scalar(select(func.count(UserIdentity.id)).where(UserIdentity.provider_type == "NATIVE")) == 1
        assert db.scalar(select(func.count(TenantUser.id)).where(TenantUser.user_id == uid)) == 2
    duplicate = client.post("/api/platform/native-users", json={
        **payload()["initial_admin_invitation"], "tenant_id": second["tenant"]["id"], "role_codes": ["VIEWER"],
    })
    # Ordinary Platform Admin is no longer a generic tenant-user administrator.
    assert duplicate.status_code == 403


def test_pending_tenant_cannot_be_enabled_without_effective_admin(provisioning):
    client, _ = provisioning
    tid = client.post("/api/tenants", json=payload()).json()["tenant"]["id"]
    assert client.patch(f"/api/platform/tenants/{tid}", json={"status": "ACTIVE"}).status_code == 409
    assert client.patch(f"/api/platform/tenants/{tid}", json={"status": "DISABLED"}).status_code == 200
    with SessionLocal() as db:
        uid = db.scalar(select(TenantUser.user_id).where(TenantUser.tenant_id == tid))
        native_auth_service.activate(db, activation_secret(db, uid), "a long native test passphrase")
        db.commit()
        assert db.get(Tenant, tid).status == "DISABLED"


def test_platform_can_resend_pending_tenant_activation_without_tenant_context(provisioning, monkeypatch):
    client, _ = provisioning
    monkeypatch.setattr(get_settings(), "email_verification_resend_cooldown_seconds", 0)
    created = client.post("/api/tenants", json=payload()).json()
    tid = created["tenant"]["id"]
    uid = created["initial_administrator"]["user_id"]
    response = client.post(f"/api/platform/tenants/{tid}/native-users/{uid}/resend-activation")
    assert response.status_code == 200, response.text
    assert response.json()["delivery"]["status"] == "PENDING"
    assert client.get(f"/api/platform/tenants/{tid}").json()["status"] == "PENDING"


@pytest.mark.parametrize("query", ["olympus", "Healthcare"])
def test_platform_tenant_search(provisioning, query):
    client, _ = provisioning
    assert client.post("/api/tenants", json=payload()).status_code == 201
    result = client.get("/api/platform/tenants", params={"q": query, "page_size": 1})
    assert result.status_code == 200
    assert result.json()[0]["slug"] == "olympus"
    assert client.get("/api/platform/tenants", params={"q": query, "page_size": 1, "page": 2}).json() == []


@pytest.mark.parametrize("query", ["ajmer@example.test", "Ajmer", "Khan"])
def test_platform_user_search_business_fields(provisioning, query):
    client, _ = provisioning
    created = client.post("/api/tenants", json=payload())
    assert created.status_code == 201
    with SessionLocal() as db:
        uid = created.json()['initial_administrator']['user_id']
        native_auth_service.activate(db, activation_secret(db, uid), "a long native test passphrase")
        db.commit()
    result = client.get("/api/platform/tenant-admin-candidates", params={"q": query, "page_size": 1})
    assert result.status_code == 200
    assert result.json()["items"][0]["email"] == "ajmer@example.test"


@pytest.mark.parametrize("role,expected", [("VIEWER", 201), ("DEVELOPER", 201), ("SECURITY_ANALYST", 201),
                                          ("TENANT_ADMIN", 403), ("PLATFORM_ADMIN", 403)])
def test_tenant_admin_http_scope_and_delegation(provisioning, role, expected):
    client, _ = provisioning
    with SessionLocal() as db:
        actor, member, _ = seed_role_membership(db, role="TENANT_ADMIN")
        member_id = member.id
        claims = identity_claims(actor)
    client.app.dependency_overrides[get_current_claims] = lambda: claims
    try:
        invitation = {**payload()["initial_admin_invitation"], "tenant_id": 1, "role_codes": [role]}
        response = client.post("/api/tenants/1/native-users", json=invitation, headers={"X-Tenant-ID": "1"})
        assert response.status_code == expected, response.text
        invitation["tenant_id"] = 2
        assert client.post("/api/tenants/2/native-users", json=invitation, headers={"X-Tenant-ID": "1"}).status_code == 403
        assert client.post("/api/tenants", json=payload()).status_code == 403
        assert client.get("/api/platform/users/search?q=ajmer").status_code == 403
        with SessionLocal() as db:
            db.get(TenantUser, member_id).status = "DISABLED"
            db.commit()
        invitation["tenant_id"] = 1
        assert client.post("/api/tenants/1/native-users", json=invitation, headers={"X-Tenant-ID": "1"}).status_code == 403
    finally:
        client.app.dependency_overrides.pop(get_current_claims, None)

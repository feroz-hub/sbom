"""Platform directory reads stay global without synthesizing membership."""

import pytest
from app.core.security import get_current_claims
from app.db import SessionLocal
from app.models import Tenant, TenantUser, UserIdentity
from sqlalchemy import select

from tests.phase6_helpers import identity_claims, now, seed_membership, seed_platform_grant, seed_user


@pytest.fixture
def directory(client):
    with SessionLocal() as db:
        admin = seed_user(db, display_name="Platform Admin")
        seed_platform_grant(db, admin)
        first = seed_user(db, display_name="One membership")
        second = seed_user(db, display_name="Two memberships")
        tenant_admin = seed_user(db, display_name="Tenant Admin")
        tenant = Tenant(name="Other tenant", slug="other", status="ACTIVE", created_at=now(), updated_at=now())
        db.add(tenant)
        db.flush()
        for person in (first, second, tenant_admin):
            seed_membership(db, person, role="TENANT_ADMIN" if person == tenant_admin else "VIEWER")
        seed_membership(db, second, tenant_id=tenant.id, role="DEVELOPER")
        db.add(UserIdentity(user_id=first.id, provider_type="NATIVE", provider_identifier=first.email,
                            created_at=now(), updated_at=now()))
        # A Native identity need not have legacy HCL identity metadata.
        first.external_issuer = first.external_subject = first.external_iam_user_id = None
        db.commit()
        ids = {"admin": admin.id, "one": first.id, "two": second.id, "tenant": tenant.id}
        admin_claims, tenant_claims = identity_claims(admin), identity_claims(tenant_admin)
        assert db.scalar(select(TenantUser.id).where(TenantUser.user_id == admin.id)) is None
    client.app.dependency_overrides[get_current_claims] = lambda: admin_claims
    yield client, ids, tenant_claims
    client.app.dependency_overrides.pop(get_current_claims, None)


def test_exact_directory_query_omits_empty_search(directory):
    client, ids, _ = directory
    failed = client.get("/api/platform/users?page=1&page_size=20&search=&sort_by=name")
    assert failed.status_code == 422
    assert failed.json()["detail"][0]["loc"] == ["query", "search"]
    response = client.get("/api/platform/users?page=1&page_size=20&sort_by=name")
    assert response.status_code == 200, response.text
    users = {user["id"]: user for user in response.json()["items"]}
    assert users[ids["admin"]]["is_platform_admin"]
    assert [users[ids[key]]["active_tenant_count"] for key in ("admin", "one", "two")] == [0, 1, 2]
    details = client.get(f'/api/platform/users/{ids["two"]}').json()
    assert {member["tenant_id"] for member in details["tenant_memberships"]} == {1, ids["tenant"]}


def test_platform_filters_remain_authorized(directory):
    client, ids, _ = directory
    result = client.get("/api/platform/users", params={"tenant_id": ids["tenant"]})
    assert result.status_code == 200
    assert [user["id"] for user in result.json()["items"]] == [ids["two"]]
    native = client.get("/api/platform/users?provider=NATIVE").json()
    assert [user["id"] for user in native["items"]] == [ids["one"]]
    hcl = client.get("/api/platform/users?provider=HCL_CS").json()
    assert ids["two"] in {user["id"] for user in hcl["items"]}
    assert ids["one"] not in {user["id"] for user in hcl["items"]}
    assert client.get("/api/platform/users?search=no-such-user").json()["total"] == 0


def test_tenant_admin_cannot_read_global_or_unrelated_projection(directory):
    client, ids, tenant_claims = directory
    client.app.dependency_overrides[get_current_claims] = lambda: tenant_claims
    headers = {"X-Tenant-ID": "1"}
    for path in ("/api/platform/users", f'/api/platform/users/{ids["admin"]}', "/api/platform/tenants", "/api/platform/administrators"):
        assert client.get(path, headers=headers).status_code == 403
    assert client.get(f'/api/tenants/{ids["tenant"]}/users', headers=headers).status_code in {403, 404}
    result = client.get("/api/tenants/1/users?page=1&page_size=20", headers=headers)
    assert result.status_code == 200, result.text
    assert ids["admin"] not in {user["user_id"] for user in result.json()["items"]}
    for user in result.json()["items"]:
        assert "tenant_memberships" not in user

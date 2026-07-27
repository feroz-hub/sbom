from app.db import SessionLocal

from .phase9_helpers import seed_role_membership


def test_role_assignment_api_grant_list_replace_and_revoke(client):
    with SessionLocal() as db:
        target, _membership, _ = seed_role_membership(db)
        target_id = target.id

    grant = client.post(
        f"/api/tenants/1/users/{target_id}/roles",
        json={
            "role_code": "DEVELOPER",
            "expected_version": 1,
            "make_primary": False,
            "reason": "API test",
        },
        headers={"X-Tenant-ID": "1"},
    )
    assert grant.status_code == 200, grant.text
    assert {item["role_code"] for item in grant.json()["roles"] if item["assignment_status"] == "ACTIVE"} == {
        "VIEWER",
        "DEVELOPER",
    }

    replace = client.put(
        f"/api/tenants/1/users/{target_id}/roles",
        json={
            "role_codes": ["DEVELOPER", "SECURITY_ANALYST"],
            "primary_role_code": "SECURITY_ANALYST",
            "expected_version": 2,
            "reason": "replace",
        },
        headers={"X-Tenant-ID": "1"},
    )
    assert replace.status_code == 200, replace.text
    assert replace.json()["primary_role"] == "SECURITY_ANALYST"

    revoke = client.request(
        "DELETE",
        f"/api/tenants/1/users/{target_id}/roles/DEVELOPER",
        json={"expected_version": 3, "reason": "revoke"},
        headers={"X-Tenant-ID": "1"},
    )
    assert revoke.status_code == 200, revoke.text
    assert revoke.json()["role_assignment_version"] == 4

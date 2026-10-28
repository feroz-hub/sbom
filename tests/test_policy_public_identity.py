"""SBO-76: policy history integers must never resolve as SBOM identities."""

import pytest

from tests import test_component_advisor_policies_api as policies
from tests import test_scoped_configuration as scoped

configured_actors = scoped.configured_actors

db = policies.db
seeded = policies.seeded
reset_overrides = policies.reset_overrides


@pytest.mark.parametrize("kind", ["trust", "accepted-risk", "scoring"])
def test_history_without_any_sbom_never_resolves_an_sbom(client, db, reset_overrides, kind):
    policies.as_role(client, "TENANT_ADMIN")
    saved = policies.publish(client, kind, status="DISABLED")
    assert saved.status_code == 201, saved.text
    response = client.get(f"{policies.BASE}/policies/{kind}/versions")
    assert response.status_code == 200, response.text
    item = response.json()["items"][0]
    assert item["id"] == saved.json()["version"]["id"]
    assert isinstance(item["id"], int)


@pytest.mark.parametrize("kind", ["trust", "accepted-risk", "scoring"])
def test_tenant_history_preserves_policy_identity_with_sbom_collision(client, seeded, kind):
    path = f"{policies.BASE}/policies/{kind}/versions"
    empty = client.get(path)
    assert empty.status_code == 200
    assert empty.json() == {"total": 0, "items": []}
    published = policies.publish(client, kind, status="DISABLED")
    assert published.status_code == 201, published.text
    version = published.json()["version"]
    # The first policy version and first SBOM deliberately share integer 1.
    assert version["id"] == seeded["sboms"][0].id
    history = client.get(path)
    assert history.status_code == 200, history.text
    assert history.json()["total"] == 1
    item = history.json()["items"][0]
    assert {key: item[key] for key in version} == version
    assert item["reason"] == "test"
    assert "created_by" in item
    assert isinstance(history.json()["items"][0]["id"], int)
    conflict = policies.publish(client, kind, status="DISABLED")
    assert conflict.status_code == 409
    assert client.get(path).json() == history.json()


@pytest.mark.parametrize("kind", ["trust", "accepted-risk", "scoring"])
def test_platform_history_is_platform_scoped_and_numeric(configured_actors, kind):
    call = configured_actors
    path = f"/api/platform/configuration/advisor-policies/{kind}/versions"
    assert call("platform", "GET", path).json() == {"total": 0, "items": []}
    saved = call("platform", "POST", path, json={
        "status": "DISABLED", "rules": None, "row_version": 0, "reason": "SBO-76 regression",
    })
    assert saved.status_code == 201, saved.text
    history = call("platform", "GET", path)
    assert history.status_code == 200, history.text
    version = saved.json()["version"]
    item = history.json()["items"][0]
    assert {key: item[key] for key in version} == version
    assert item["reason"] == "SBO-76 regression"
    assert "created_by" in item
    for role in ("olympus", "astra", "analyst", "developer", "viewer"):
        assert call(role, "GET", path).status_code == 403
    for role, status in (("olympus", 200), ("astra", 200), ("analyst", 200), ("developer", 403), ("viewer", 403)):
        tenant = call(role, "GET", f"{policies.BASE}/policies/{kind}/versions")
        assert tenant.status_code == status
        if status == 200:
            assert tenant.json()["items"] == []


def test_sbom_versions_still_have_public_uuid_identities(client, seeded):
    from app.public_api import route_entity

    assert route_entity("/api/logical-sboms/{logical_id}/versions") == "sbom_source"
    assert route_entity("/api/component-advisor/policies/{kind}/versions") is None
    assert route_entity("/api/platform/configuration/advisor-policies/{kind}/versions") is None
    sbom = seeded["sboms"][0]
    response = client.get(f"/api/sboms/{sbom.public_id}")
    assert response.status_code == 200, response.text
    assert response.json()["id"] == str(sbom.public_id)
    versions = client.get(f"/api/sboms/{sbom.public_id}/versions")
    assert versions.status_code == 200
    assert versions.json()[0]["id"] == str(sbom.public_id)
    picker = client.get("/api/vex/investigations/versions")
    assert picker.status_code == 200
    assert {row["id"] for row in picker.json()["items"]} == {str(row.public_id) for row in seeded["sboms"]}
    # Restore keeps its explicit SBOM version identity contract.
    rejected = client.post(f"/api/sboms/{sbom.public_id}/restore/{sbom.id}")
    assert rejected.status_code == 422

from __future__ import annotations

import json
import uuid

from app.db import SessionLocal
from app.models import AnalysisRun, Product, Projects, SBOMSource
from app.services.analysis_service import persist_analysis_run
from scripts.backfill_products_for_existing_sboms import run_backfill


def _name(prefix: str) -> str:
    return f"{prefix}-{uuid.uuid4().hex[:8]}"


def _project(client, name: str | None = None) -> dict:
    response = client.post("/api/projects", json={"project_name": name or _name("project")})
    assert response.status_code == 201, response.text
    return response.json()


def _product(client, project_id: int, name: str | None = None) -> dict:
    response = client.post(f"/api/projects/{project_id}/products", json={"name": name or _name("product")})
    assert response.status_code == 201, response.text
    return response.json()


def _upload(
    client,
    *,
    project_id: int | None = None,
    product_id: int | None = None,
    name: str | None = None,
    set_as_current: bool | None = None,
) -> dict:
    sbom = {
        "bomFormat": "CycloneDX",
        "specVersion": "1.5",
        "metadata": {"component": {"type": "application", "name": "demo", "version": "1.0.0"}},
        "components": [],
    }
    data: dict[str, str] = {"sbom_name": name or _name("sbom")}
    if project_id is not None:
        data["project_id"] = str(project_id)
    if product_id is not None:
        data["product_id"] = str(product_id)
    if set_as_current is not None:
        data["set_as_current"] = "true" if set_as_current else "false"
    response = client.post(
        "/api/sboms/upload",
        data=data,
        files={"file": ("sbom.cdx.json", json.dumps(sbom), "application/json")},
    )
    assert response.status_code == 202, response.text
    return response.json()


def test_create_and_list_products_unique_within_project(client):
    project_a = _project(client)
    project_b = _project(client)
    created = _product(client, project_a["id"], "Authorization Server")

    duplicate = client.post(f"/api/projects/{project_a['id']}/products", json={"name": "authorization   server"})
    assert duplicate.status_code == 409

    same_name_other_project = client.post(
        f"/api/projects/{project_b['id']}/products",
        json={"name": "Authorization Server"},
    )
    assert same_name_other_project.status_code == 201, same_name_other_project.text

    listed = client.get(f"/api/projects/{project_a['id']}/products")
    assert listed.status_code == 200
    assert listed.json()["total"] >= 1
    assert any(item["id"] == created["id"] for item in listed.json()["items"])


def test_product_create_and_update_accept_custom_category_strings(client):
    project = _project(client)
    created = client.post(
        f"/api/projects/{project['id']}/products",
        json={"name": _name("categorized-product"), "category": "Healthcare Integration Appliance"},
    )
    assert created.status_code == 201, created.text
    assert created.json()["category"] == "Healthcare Integration Appliance"

    updated = client.patch(
        f"/api/products/{created.json()['id']}",
        json={"category": "Legacy Healthcare Platform"},
    )
    assert updated.status_code == 200, updated.text
    assert updated.json()["category"] == "Legacy Healthcare Platform"


def test_upload_requires_matching_project_product_and_returns_product(client):
    project_a = _project(client)
    project_b = _project(client)
    product_a = _product(client, project_a["id"], "Certificate API")
    product_b = _product(client, project_b["id"], "WPF Client")

    accepted = _upload(client, project_id=project_a["id"], product_id=product_a["id"])
    assert accepted["project_id"] == project_a["id"]
    assert accepted["product_id"] == product_a["id"]
    assert accepted["product_name"] == "Certificate API"

    mismatch = client.post(
        "/api/sboms/upload",
        data={"sbom_name": _name("bad"), "project_id": str(project_a["id"]), "product_id": str(product_b["id"])},
        files={"file": ("sbom.cdx.json", json.dumps({"bomFormat": "CycloneDX", "specVersion": "1.5"}), "application/json")},
    )
    assert mismatch.status_code == 409


def test_upload_current_sbom_selection_is_explicit_and_first_upload_is_safe_default(client):
    project = _project(client)
    product = _product(client, project["id"], "Versioned Controller")

    first = _upload(client, project_id=project["id"], product_id=product["id"], set_as_current=False)
    assert first["is_current"] is True
    assert client.get(f"/api/products/{product['id']}").json()["current_sbom_id"] == first["sbom_id"]

    historical = _upload(client, project_id=project["id"], product_id=product["id"], set_as_current=False)
    assert historical["is_current"] is False
    assert client.get(f"/api/products/{product['id']}").json()["current_sbom_id"] == first["sbom_id"]

    replacement = _upload(client, project_id=project["id"], product_id=product["id"], set_as_current=True)
    assert replacement["is_current"] is True
    detail = client.get(f"/api/products/{product['id']}").json()
    assert detail["current_sbom_id"] == replacement["sbom_id"]


def test_soft_deleting_current_sbom_clears_product_pointer(client):
    project = _project(client)
    product = _product(client, project["id"], "Delete Current")
    uploaded = _upload(client, project_id=project["id"], product_id=product["id"])
    assert client.get(f"/api/products/{product['id']}").json()["current_sbom_id"] == uploaded["sbom_id"]

    deleted = client.delete(f"/api/sboms/{uploaded['sbom_id']}?confirm=yes")
    assert deleted.status_code == 200, deleted.text
    assert client.get(f"/api/products/{product['id']}").json()["current_sbom_id"] is None


def test_legacy_upload_with_only_project_uses_default_product(client):
    project = _project(client)
    accepted = _upload(client, project_id=project["id"])
    assert accepted["project_id"] == project["id"]
    assert accepted["product_id"] is not None
    assert accepted["product_name"] == "Legacy / Unassigned Product"
    assert "product_id will become required" in accepted.get("message", "") or accepted["status"]


def test_patch_sbom_changes_product_and_rejects_mismatch(client):
    project_a = _project(client)
    project_b = _project(client)
    product_a = _product(client, project_a["id"], "API A")
    product_b = _product(client, project_b["id"], "API B")
    accepted = _upload(client, project_id=project_a["id"], product_id=product_a["id"])
    sbom_id = accepted["sbom_id"]

    moved = client.patch(f"/api/sboms/{sbom_id}", json={"product_id": product_b["id"], "change_reason": "move"})
    assert moved.status_code == 200, moved.text
    assert moved.json()["project_id"] == project_b["id"]
    assert moved.json()["product_id"] == product_b["id"]
    assert client.get(f"/api/products/{product_a['id']}").json()["current_sbom_id"] is None

    mismatch = client.patch(
        f"/api/sboms/{sbom_id}",
        json={"project_id": project_a["id"], "product_id": product_b["id"]},
    )
    assert mismatch.status_code == 409


def test_analysis_run_inherits_product_id(client):
    project = _project(client)
    product = _product(client, project["id"], "Run Product")
    accepted = _upload(client, project_id=project["id"], product_id=product["id"])
    with SessionLocal() as db:
        sbom = db.get(SBOMSource, accepted["sbom_id"])
        run = persist_analysis_run(
            db,
            sbom,
            {"total_components": 0, "total_findings": 0, "findings": [], "query_errors": []},
            [],
            "OK",
            "NVD",
            "2026-07-03T00:00:00Z",
            "2026-07-03T00:00:01Z",
            1,
        )
        db.commit()
        assert run.product_id == product["id"]


def test_product_sbom_list_carries_latest_analysis(client):
    """The product screen renders the same analysis badge as /api/sboms.

    Returning bare ORM rows left ``latest_analysis`` unset, so every row on
    the product screen read "not_run" no matter how many runs the SBOM had.
    """
    project = _project(client)
    product = _product(client, project["id"], "Analysed Product")
    accepted = _upload(client, project_id=project["id"], product_id=product["id"])
    sbom_id = accepted["sbom_id"]

    listed = client.get(f"/api/products/{product['id']}/sboms")
    assert listed.status_code == 200, listed.text
    assert listed.json()[0]["latest_analysis"] is None

    with SessionLocal() as db:
        sbom = db.get(SBOMSource, sbom_id)
        run = AnalysisRun(
            sbom_id=sbom.id,
            project_id=sbom.projectid,
            product_id=sbom.product_id,
            tenant_id=sbom.tenant_id,
            run_status="FINDINGS",
            source="NVD",
            started_on="2026-07-03T00:00:00Z",
            completed_on="2026-07-03T00:00:01Z",
            total_findings=2,
            critical_count=1,
            high_count=1,
            raw_report=json.dumps({}),
        )
        db.add(run)
        db.commit()
        run_id = run.id

    listed = client.get(f"/api/products/{product['id']}/sboms")
    assert listed.status_code == 200, listed.text
    latest = listed.json()[0]["latest_analysis"]
    assert latest is not None
    assert latest["run_id"] == run_id
    assert latest["status"] == "completed"
    assert latest["result"] == "findings"
    assert latest["finding_count"] == 2
    assert latest["critical_count"] == 1


def test_product_sbom_list_delete_policy_and_backfill_idempotent(client):
    project = _project(client)
    product = _product(client, project["id"], "Listed Product")
    accepted = _upload(client, project_id=project["id"], product_id=product["id"])

    listed = client.get(f"/api/products/{product['id']}/sboms")
    assert listed.status_code == 200
    assert [row["id"] for row in listed.json()] == [accepted["sbom_id"]]

    delete_blocked = client.delete(f"/api/products/{product['id']}")
    assert delete_blocked.status_code == 409

    with SessionLocal() as db:
        legacy_project = Projects(
            tenant_id=1,
            project_name=_name("legacy-project"),
            project_status=1,
            created_on="2026-07-03T00:00:00Z",
        )
        db.add(legacy_project)
        db.flush()
        legacy = SBOMSource(
            tenant_id=1,
            sbom_name=_name("legacy-sbom"),
            sbom_data="{}",
            projectid=legacy_project.id,
            status="validated",
        )
        db.add(legacy)
        db.commit()
        legacy_id = legacy.id
        legacy_project_id = legacy_project.id

    first = run_backfill(apply=True)
    second = run_backfill(apply=True)
    assert first.sboms_linked >= 1
    assert second.sboms_linked == 0
    with SessionLocal() as db:
        legacy = db.get(SBOMSource, legacy_id)
        assert legacy.projectid == legacy_project_id
        assert legacy.product_id is not None
        assert db.get(Product, legacy.product_id).name == "Legacy / Unassigned Product"

"""Multiple independently versioned SBOMs per Product, with stable evidence IDs."""

import json

from app.db import SessionLocal
from app.models import AnalysisRun, SBOMComponent, SBOMSource
from sqlalchemy import select

from tests.test_sbom_upload_version_lineage import _product, _project


def upload(
    client,
    project,
    product,
    version,
    name="Backend SBOM",
    logical_id=None,
    product_version="3.2.0",
    component="package-a",
):
    data = {
        "project_id": str(project["id"]),
        "product_id": str(product["id"]),
        "sbom_name": name,
        "sbom_version": version,
        "product_version": product_version,
    }
    if logical_id is not None:
        data["logical_sbom_id"] = str(logical_id)
    else:
        data["create_new_logical_sbom"] = "true"
    document = {
        "bomFormat": "CycloneDX",
        "specVersion": "1.5",
        "version": 1,
        "metadata": {"component": {"type": "application", "name": "demo", "version": product_version}},
        "components": [{"type": "library", "name": component, "version": "1.0", "bom-ref": component}],
    }
    return client.post(
        "/api/sboms/upload", data=data, files={"file": ("bom.json", json.dumps(document), "application/json")}
    )


def test_multiple_masters_independent_revisions_and_duplicate_rejection(client):
    project = _project(client)
    product = _product(client, project["id"])
    first = upload(client, project, product, "1.0")
    assert first.status_code == 202, first.text
    master = first.json()["logical_sbom_id"]
    ids = [first.json()["sbom_id"]]
    for label in ("1.1", "1.2"):
        result = upload(client, project, product, label, logical_id=master)
        assert result.status_code == 202, result.text
        assert result.json()["logical_sbom_id"] == master
        ids.append(result.json()["sbom_id"])
    duplicate = upload(client, project, product, "1.2", logical_id=master)
    assert duplicate.status_code == 409
    assert duplicate.json()["detail"]["code"] == "duplicate_sbom_version"
    frontend = upload(client, project, product, "1.0", name="Frontend SBOM")
    assert frontend.status_code == 202, frontend.text
    assert frontend.json()["logical_sbom_id"] != master
    listing = client.get(f"/api/products/{product['id']}/logical-sboms").json()
    assert listing["total"] == 2
    backend = next(item for item in listing["items"] if item["id"] == master)
    assert backend["version_count"] == 3
    assert backend["latest_version"]["sbom_version"] == "1.2"
    history = client.get(f"/api/logical-sboms/{master}/versions").json()
    assert [v["sbom_version"] for v in history] == ["1.2", "1.1", "1.0"]
    assert all(v["product_version"] == "3.2.0" for v in history)
    assert all(v["logical_sbom_id"] == master for v in history)
    assert {v["id"] for v in history} == set(ids)
    for sbom_id in ids:
        detail = client.get(f"/api/sboms/{sbom_id}").json()
        assert detail["logical_sbom_id"] == master
    legacy_history = client.get(f"/api/sboms/{ids[0]}/versions").json()
    assert {v["id"] for v in legacy_history} == set(ids)


def test_latest_revision_uses_numeric_order_and_arbitrary_labels_use_upload_order(client):
    project = _project(client)
    product = _product(client, project["id"])
    first = upload(client, project, product, "1.9").json()
    master = first["logical_sbom_id"]
    for label in ("1.10", "1.2"):
        assert upload(client, project, product, label, logical_id=master).status_code == 202
    assert client.get(f"/api/logical-sboms/{master}").json()["latest_version"]["sbom_version"] == "1.10"
    assert [v["sbom_version"] for v in client.get(f"/api/logical-sboms/{master}/versions").json()] == [
        "1.10",
        "1.9",
        "1.2",
    ]
    assert upload(client, project, product, "release-A", logical_id=master).status_code == 202
    assert client.get(f"/api/logical-sboms/{master}").json()["latest_version"]["sbom_version"] == "release-A"


def test_versions_keep_distinct_components_and_analysis_results(client, mock_external_sources):
    project = _project(client)
    product = _product(client, project["id"])
    first = upload(client, project, product, "1.0", component="alpha").json()
    second = upload(client, project, product, "1.1", logical_id=first["logical_sbom_id"], component="beta").json()
    for value in (first, second):
        analyzed = client.post(f"/api/sboms/{value['sbom_id']}/analyze")
        assert analyzed.status_code in (200, 201), analyzed.text
    with SessionLocal() as db:
        assert {c.name for c in db.scalars(select(SBOMComponent).where(SBOMComponent.sbom_id == first["sbom_id"]))} == {
            "alpha"
        }
        assert {
            c.name for c in db.scalars(select(SBOMComponent).where(SBOMComponent.sbom_id == second["sbom_id"]))
        } == {"beta"}
        for value in (first, second):
            assert db.scalar(select(AnalysisRun.id).where(AnalysisRun.sbom_id == value["sbom_id"]))


def test_empty_master_first_upload_and_other_product_cannot_reuse_it(client):
    project = _project(client)
    product = _product(client, project["id"])
    created = client.post(f"/api/products/{product['id']}/logical-sboms", json={"name": "Firmware SBOM"})
    assert created.status_code == 201, created.text
    master = created.json()["id"]
    assert created.json()["version_count"] == 0
    result = upload(client, project, product, "2.0", logical_id=master)
    assert result.status_code == 202, result.text
    assert result.json()["sbom_name"] == "Firmware SBOM"
    other_product = _product(client, project["id"])
    assert upload(client, project, other_product, "2.1", logical_id=master).status_code == 404


def test_database_constraint_enforces_duplicates_even_when_bypassing_api(client):
    import pytest
    from sqlalchemy.exc import IntegrityError

    project = _project(client)
    product = _product(client, project["id"])
    first = upload(client, project, product, "1.0").json()
    with SessionLocal() as db:
        original = db.get(SBOMSource, first["sbom_id"])
        db.add(
            SBOMSource(
                tenant_id=original.tenant_id,
                logical_sbom_id=original.logical_sbom_id,
                sbom_name="different-label",
                sbom_version="1.0",
                product_id=original.product_id,
                projectid=original.projectid,
            )
        )
        with pytest.raises(IntegrityError):
            db.flush()
        db.rollback()


from tests.test_scoped_configuration import configured_actors as configured_actors


def test_logical_version_tenant_isolation_and_read_only_permissions(configured_actors):
    call = configured_actors
    project_a = call("olympus", "POST", "/api/projects", json={"project_name": "Versioned A"}).json()
    product_a = call(
        "olympus", "POST", f"/api/projects/{project_a['id']}/products", json={"name": "Application A"}
    ).json()
    master = call(
        "olympus", "POST", f"/api/products/{product_a['id']}/logical-sboms", json={"name": "Backend SBOM"}
    ).json()
    project_b = call("astra", "POST", "/api/projects", json={"project_name": "Versioned B"}).json()
    product_b = call(
        "astra", "POST", f"/api/projects/{project_b['id']}/products", json={"name": "Application B"}
    ).json()
    assert call("astra", "GET", f"/api/logical-sboms/{master['id']}").status_code == 404
    assert call("astra", "GET", f"/api/logical-sboms/{master['id']}/versions").status_code == 404
    assert call("astra", "GET", f"/api/products/{product_a['id']}/logical-sboms").status_code == 404
    document = {"bomFormat": "CycloneDX", "specVersion": "1.5", "components": []}
    data = {
        "sbom_name": "Backend",
        "project_id": str(project_b["id"]),
        "product_id": str(product_b["id"]),
        "logical_sbom_id": str(master["id"]),
        "sbom_version": "1.0",
    }
    assert (
        call(
            "astra",
            "POST",
            "/api/sboms/upload",
            data=data,
            files={"file": ("bom.json", json.dumps(document), "application/json")},
        ).status_code
        == 404
    )
    assert call("viewer", "GET", f"/api/logical-sboms/{master['id']}").status_code == 200
    assert (
        call(
            "viewer", "POST", f"/api/products/{product_a['id']}/logical-sboms", json={"name": "Unauthorized"}
        ).status_code
        == 403
    )
    data.update(project_id=str(project_a["id"]), product_id=str(product_a["id"]))
    assert (
        call(
            "viewer",
            "POST",
            "/api/sboms/upload",
            data=data,
            files={"file": ("bom.json", json.dumps(document), "application/json")},
        ).status_code
        == 403
    )


def test_inactive_revision_remains_in_history_and_analysis_is_blocked(client):
    project = _project(client)
    product = _product(client, project["id"])
    first = upload(client, project, product, "1.0").json()
    second = upload(client, project, product, "1.1", logical_id=first["logical_sbom_id"]).json()
    changed = client.post(
        f"/api/sboms/{first['sbom_id']}/lifecycle", json={"status": "INACTIVE", "reason": "Retired revision"}
    )
    assert changed.status_code == 200, changed.text
    history = client.get(f"/api/logical-sboms/{first['logical_sbom_id']}/versions").json()
    assert len(history) == 2
    assert next(v for v in history if v["id"] == first["sbom_id"])["lifecycle_status"] == "INACTIVE"
    assert client.post(f"/api/sboms/{first['sbom_id']}/analyze").status_code == 409
    assert client.get(f"/api/sboms/{second['sbom_id']}").json()["lifecycle_status"] == "ACTIVE"


def test_metadata_update_cannot_duplicate_a_sibling_revision(client):
    project = _project(client)
    product = _product(client, project["id"])
    first = upload(client, project, product, "1.0").json()
    second = upload(client, project, product, "1.1", logical_id=first["logical_sbom_id"]).json()
    response = client.patch(f"/api/sboms/{second['sbom_id']}", json={"sbom_version": "1.0"})
    assert response.status_code == 409, response.text
    assert client.get(f"/api/sboms/{second['sbom_id']}").json()["sbom_version"] == "1.1"


def test_repair_import_preserves_selected_master_and_version_metadata(client):
    project = _project(client)
    product = _product(client, project["id"])
    first = upload(client, project, product, "1.0").json()
    document = {
        "bomFormat": "CycloneDX",
        "specVersion": "1.5",
        "components": [{"type": "library", "name": "package-a", "version": "1.0", "purl": "not-a-purl"}],
    }
    failed = client.post(
        "/api/sboms/upload",
        data={
            "project_id": str(project["id"]),
            "product_id": str(product["id"]),
            "sbom_name": "Backend SBOM",
            "logical_sbom_id": str(first["logical_sbom_id"]),
            "sbom_version": "1.1",
            "product_version": "3.2.0",
        },
        files={"file": ("bom.json", json.dumps(document), "application/json")},
    )
    assert failed.status_code == 422, failed.text
    workspace_id = failed.json()["detail"]["validation_session_id"]
    patched = client.post(
        f"/api/sbom-validation-sessions/{workspace_id}/apply-patch",
        json={
            "patches": [
                {
                    "target": "/components/0/purl",
                    "operation": "replace",
                    "before": "not-a-purl",
                    "after": "pkg:generic/package-a@1.0",
                    "reason": "Correct purl",
                    "validation_error_codes": ["SBOM_VAL_E052_PURL_INVALID"],
                }
            ]
        },
    )
    assert patched.status_code == 200, patched.text
    imported = client.post(f"/api/sbom-validation-sessions/{workspace_id}/import")
    assert imported.status_code == 200, imported.text
    assert imported.json()["logical_sbom_id"] == first["logical_sbom_id"]
    assert imported.json()["sbom_version"] == "1.1"
    assert imported.json()["product_version"] == "3.2.0"
    assert len(client.get(f"/api/logical-sboms/{first['logical_sbom_id']}/versions").json()) == 2


def test_edit_restore_preserve_master_and_create_fresh_revisions(client):
    project = _project(client)
    product = _product(client, project["id"])
    first = upload(client, project, product, "1.0.0").json()
    master = first["logical_sbom_id"]
    changed = client.post(
        f"/api/sboms/{first['sbom_id']}/edit",
        json={"metadata": {"sbom_version": "1.0.1"}, "change_summary": "Correct document"},
    )
    assert changed.status_code == 200, changed.text
    assert changed.json()["logical_sbom_id"] == master
    again = client.post(f"/api/sboms/{first['sbom_id']}/edit", json={"change_summary": "Edit earlier version"})
    assert again.status_code == 200, again.text
    assert again.json()["sbom_version"] == "1.0.2"
    restored = client.post(f"/api/sboms/{again.json()['id']}/restore/{first['sbom_id']}")
    assert restored.status_code == 200, restored.text
    assert restored.json()["logical_sbom_id"] == master
    assert restored.json()["sbom_version"] == "1.0.3"
    assert len(client.get(f"/api/logical-sboms/{master}/versions").json()) == 4
    other = upload(client, project, product, "1.0", name="Firmware SBOM").json()
    assert client.post(f"/api/sboms/{restored.json()['id']}/restore/{other['sbom_id']}").status_code == 400

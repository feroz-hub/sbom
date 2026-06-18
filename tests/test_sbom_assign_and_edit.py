from __future__ import annotations

import json

from app.db import SessionLocal
from app.models import AnalysisRun, AuditLog, SBOMComponent

CLEAN_CYCLONEDX = {
    "bomFormat": "CycloneDX",
    "specVersion": "1.6",
    "serialNumber": "urn:uuid:99999999-aaaa-bbbb-cccc-dddddddddddd",
    "version": 1,
    "metadata": {"timestamp": "2026-04-30T12:00:00Z"},
    "components": [
        {
            "type": "library",
            "bom-ref": "x",
            "name": "x",
            "version": "1.0.0",
            "purl": "pkg:generic/x@1.0.0",
        }
    ],
    "dependencies": [],
}

BAD_PURL_CYCLONEDX = {
    "bomFormat": "CycloneDX",
    "specVersion": "1.6",
    "serialNumber": "urn:uuid:99999999-aaaa-bbbb-cccc-dddddddddddd",
    "version": 1,
    "metadata": {"timestamp": "2026-04-30T12:00:00Z"},
    "components": [
        {
            "type": "library",
            "bom-ref": "x",
            "name": "x",
            "version": "1.0.0",
            "purl": "not-a-purl",
        }
    ],
    "dependencies": [],
}

def _unique(name: str) -> str:
    import uuid
    return f"{name}-{uuid.uuid4().hex[:8]}"

def _create_project(client, name="test-proj") -> dict:
    resp = client.post("/api/projects", json={"project_name": _unique(name), "project_status": 1})
    assert resp.status_code == 201, resp.text
    return resp.json()

def _create_sbom(client, name="test-sbom", project_id=None) -> dict:
    resp = client.post(
        "/api/sboms",
        json={
            "sbom_name": _unique(name),
            "sbom_data": json.dumps(CLEAN_CYCLONEDX),
            "project_id": project_id,
            "created_by": "test-user"
        }
    )
    assert resp.status_code == 201, resp.text
    return resp.json()

def test_patch_sbom_valid_project_assigns_project(client):
    project = _create_project(client)
    sbom = _create_sbom(client)
    
    # Patch SBOM with project_id
    resp = client.patch(f"/api/sboms/{sbom['id']}", json={"project_id": project["id"]}, params={"user_id": "test-user"})
    assert resp.status_code == 200, resp.text
    body = resp.json()
    assert body["project_id"] == project["id"]
    assert body["projectid"] == project["id"]
    assert body["project_name"] == project["project_name"]

    # Verify generic audit trail
    db = SessionLocal()
    try:
        audit = db.query(AuditLog).filter_by(target_kind="sbom", target_id=sbom["id"], action="sbom.update").first()
        assert audit is not None
        assert audit.metadata_json["old_project_id"] is None
        assert audit.metadata_json["new_project_id"] == project["id"]
    finally:
        db.close()

def test_patch_sbom_invalid_project_returns_400_or_422(client):
    sbom = _create_sbom(client)
    # Patch SBOM with invalid project_id
    resp = client.patch(f"/api/sboms/{sbom['id']}", json={"project_id": 999999}, params={"user_id": "test-user"})
    assert resp.status_code in {400, 422}, resp.text
    
    # Try invalid format
    resp2 = client.patch(f"/api/sboms/{sbom['id']}", json={"project_id": "invalid-id"}, params={"user_id": "test-user"})
    assert resp2.status_code in {400, 422}, resp2.text

def test_patch_sbom_metadata_updates_correctly(client):
    sbom = _create_sbom(client)
    new_name = _unique("renamed-sbom")
    new_product_name = "New Product"
    new_product_version = "v2.0"
    new_sbom_version = "v1.2"
    new_description = "Updated description"
    
    resp = client.patch(
        f"/api/sboms/{sbom['id']}",
        json={
            "name": new_name,
            "product_name": new_product_name,
            "product_version": new_product_version,
            "sbom_version": new_sbom_version,
            "description": new_description,
        },
        params={"user_id": "test-user"}
    )
    assert resp.status_code == 200, resp.text
    body = resp.json()
    assert body["name"] == new_name
    assert body["product_name"] == new_product_name
    assert body["product_version"] == new_product_version
    assert body["sbom_version"] == new_sbom_version
    assert body["description"] == new_description

def test_project_assignment_preserves_components_and_runs(client):
    project = _create_project(client)
    sbom = _create_sbom(client)
    
    # Trigger an analysis to create runs and components
    run_resp = client.post(f"/api/sboms/{sbom['id']}/analyze")
    assert run_resp.status_code in {200, 201}, run_resp.text
    
    db = SessionLocal()
    try:
        comp_count_before = db.query(SBOMComponent).filter_by(sbom_id=sbom["id"]).count()
        runs_count_before = db.query(AnalysisRun).filter_by(sbom_id=sbom["id"]).count()
        assert comp_count_before > 0
        assert runs_count_before > 0
    finally:
        db.close()
        
    # Reassign project
    resp = client.patch(f"/api/sboms/{sbom['id']}", json={"project_id": project["id"]}, params={"user_id": "test-user"})
    assert resp.status_code == 200, resp.text
    
    db = SessionLocal()
    try:
        comp_count_after = db.query(SBOMComponent).filter_by(sbom_id=sbom["id"]).count()
        runs_count_after = db.query(AnalysisRun).filter_by(sbom_id=sbom["id"]).count()
        assert comp_count_after == comp_count_before
        assert runs_count_after == runs_count_before
        
        # Verify AnalysisRuns project_id cascaded
        runs = db.query(AnalysisRun).filter_by(sbom_id=sbom["id"]).all()
        for r in runs:
            assert r.project_id == project["id"]
    finally:
        db.close()

def test_dashboard_and_project_counts_reflect_assignment(client):
    project = _create_project(client)
    
    # Confirm initial project count is 0
    proj_details = client.get(f"/api/projects/{project['id']}").json()
    assert proj_details["sbom_count"] == 0
    
    # Assign SBOM to project
    sbom = _create_sbom(client)
    resp = client.patch(f"/api/sboms/{sbom['id']}", json={"project_id": project["id"]}, params={"user_id": "test-user"})
    assert resp.status_code == 200, resp.text
    
    # Confirm updated project counts
    proj_details = client.get(f"/api/projects/{project['id']}").json()
    assert proj_details["sbom_count"] == 1

def test_validation_repair_import_preserves_selected_project(client):
    project = _create_project(client)
    name = _unique("repair-import-proj")
    
    # Fail upload without project
    resp = client.post(
        "/api/sboms",
        json={
            "sbom_name": name,
            "sbom_data": json.dumps(BAD_PURL_CYCLONEDX),
        }
    )
    assert resp.status_code == 422
    session_id = resp.json()["detail"]["session_id"]
    
    # Update validation session with project_id
    patch_session_resp = client.patch(
        f"/api/sbom-validation-sessions/{session_id}",
        json={"project_id": project["id"]}
    )
    assert patch_session_resp.status_code == 200, patch_session_resp.text
    assert patch_session_resp.json()["project_id"] == project["id"]
    
    # Verify import fails if project required and missing (but here it's present)
    # Let's first apply patch to make validation pass
    patch_resp = client.post(
        f"/api/sbom-validation-sessions/{session_id}/apply-patch",
        json={
            "patches": [
                {
                    "target": "/components/0/purl",
                    "operation": "replace",
                    "before": "not-a-purl",
                    "after": "pkg:generic/x@1.0.0",
                    "reason": "Valid purl",
                    "validation_error_codes": ["SBOM_VAL_E052_PURL_INVALID"],
                }
            ]
        }
    )
    assert patch_resp.status_code == 200
    
    # Import
    imported = client.post(
        f"/api/sbom-validation-sessions/{session_id}/import",
        params={"project_required": True}
    )
    assert imported.status_code == 200, imported.text
    imported_body = imported.json()
    assert imported_body["project_id"] == project["id"]
    assert imported_body["project_name"] == project["project_name"]

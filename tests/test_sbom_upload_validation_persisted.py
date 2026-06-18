"""Validation upload trust boundary and repair session regression tests.

The validation repair workspace changed the failed-upload contract:

* A valid SBOM still creates a row with ``status='validated'`` and a 201.
* An SBOM with NTIA warnings only is ``validated`` with ``warning_count > 0``.
* An SBOM with hard validation errors does not create a trusted SBOM row.
* Safe malformed SBOMs create a validation repair session with the full report.
"""

from __future__ import annotations

import json
import uuid

import pytest
from app.db import SessionLocal
from app.models import SBOMComponent, SBOMSource

_VALID_CYCLONEDX = {
    "bomFormat": "CycloneDX",
    "specVersion": "1.5",
    "serialNumber": "urn:uuid:11111111-2222-3333-4444-555555555555",
    "version": 1,
    "metadata": {
        "timestamp": "2026-04-30T12:00:00Z",
        "component": {
            "type": "application",
            "bom-ref": "pkg:generic/phase2-valid@1.0.0",
            "name": "phase2-valid",
            "version": "1.0.0",
        },
    },
    "components": [
        {
            "type": "library",
            "bom-ref": "pkg:pypi/requests@2.32.0",
            "name": "requests",
            "version": "2.32.0",
            "purl": "pkg:pypi/requests@2.32.0",
        }
    ],
}


_BAD_PURL_CYCLONEDX = {
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


@pytest.fixture
def unique_name(request) -> str:
    """Globally unique SBOM name per test (avoids 409 from prior runs)."""
    import uuid

    return f"phase2-{request.node.name}-{uuid.uuid4().hex[:8]}"


def test_valid_sbom_persists_validated_status(client, unique_name):
    resp = client.post(
        "/api/sboms",
        json={"sbom_name": unique_name, "sbom_data": json.dumps(_VALID_CYCLONEDX)},
    )
    assert resp.status_code == 201, resp.text
    body = resp.json()
    assert body["status"] == "validated"
    assert body["error_count"] == 0
    assert body["failed_stage"] is None
    # Warnings may exist (NTIA) but must not block.
    assert body["warning_count"] >= 0
    # validated_at populated on the success path.
    assert body["validated_at"] is not None


def test_upload_with_project_id_assigns_project_and_syncs_details(client, unique_name):
    project = client.post(
        "/api/projects",
        json={"project_name": f"project-{unique_name}", "project_status": 1},
    )
    assert project.status_code == 201, project.text
    project_id = project.json()["id"]

    resp = client.post(
        "/api/sboms/upload",
        data={"sbom_name": unique_name, "project_id": str(project_id)},
        files={"file": ("valid.json", json.dumps(_VALID_CYCLONEDX), "application/json")},
    )
    assert resp.status_code == 202, resp.text
    accepted = resp.json()
    assert accepted["project_id"] == project_id
    assert accepted["project_name"] == project.json()["project_name"]

    detail = client.get(f"/api/sboms/{accepted['sbom_id']}").json()
    assert detail["projectid"] == project_id
    assert detail["project_id"] == project_id
    assert detail["project_name"] == project.json()["project_name"]
    assert detail["component_count"] >= 1
    assert detail["completeness_score"] is not None

    refreshed_project = client.get(f"/api/projects/{project_id}").json()
    assert refreshed_project["sbom_count"] == 1

    db = SessionLocal()
    try:
        assert db.query(SBOMComponent).filter(SBOMComponent.sbom_id == accepted["sbom_id"]).count() >= 1
    finally:
        db.close()


def test_upload_schedules_background_enrichment_without_inline_provider_calls(client, unique_name, monkeypatch):
    scheduled: list[int] = []

    def fake_background_enrichment(sbom_id: int) -> None:
        scheduled.append(sbom_id)

    monkeypatch.setattr(
        "app.routers.sbom_upload.run_post_upload_enrichment",
        fake_background_enrichment,
    )

    resp = client.post(
        "/api/sboms/upload",
        data={"sbom_name": unique_name},
        files={"file": ("valid.json", json.dumps(_VALID_CYCLONEDX), "application/json")},
    )
    assert resp.status_code == 202, resp.text
    accepted = resp.json()
    assert accepted["enrichment_status"] == "pending"
    assert "background" in accepted["message"].lower()
    assert scheduled == [accepted["sbom_id"]]

    detail = client.get(f"/api/sboms/{accepted['sbom_id']}").json()
    assert detail["status"] == "validated"
    assert detail["component_count"] >= 1
    assert detail["enrichment_status"] == "pending"


def test_post_upload_background_enrichment_updates_status(client, monkeypatch):
    from app.services.sbom_enrichment_service import mark_enrichment_pending, run_post_upload_enrichment

    monkeypatch.setattr(
        "app.services.sbom_enrichment_service.sync_lifecycle_for_sbom",
        lambda db, sbom_id, **kwargs: {"sbom_id": sbom_id, "components_enriched": 1},
    )
    monkeypatch.setattr(
        "app.services.sbom_enrichment_service.process_embedded_vex_for_sbom",
        lambda db, sbom_id: {"documents_processed": 0},
    )
    monkeypatch.setattr(
        "app.services.sbom_enrichment_service.compute_and_save_completeness",
        lambda db, sbom: {"score": 100},
    )

    db = SessionLocal()
    try:
        unique_bg_name = f"background-status-{uuid.uuid4().hex[:8]}"
        sbom = SBOMSource(
            sbom_name=unique_bg_name,
            sbom_data=json.dumps(_VALID_CYCLONEDX),
            status="validated",
        )
        mark_enrichment_pending(sbom)
        db.add(sbom)
        db.commit()
        db.refresh(sbom)

        run_post_upload_enrichment(sbom.id)

        db.refresh(sbom)
        assert sbom.sbom_name == unique_bg_name
        assert sbom.enrichment_status == "completed"
        assert sbom.enrichment_started_at is not None
        assert sbom.enrichment_completed_at is not None
        assert sbom.enrichment_error is None
    finally:
        db.rollback()
        db.close()


def test_upload_with_invalid_project_id_returns_clear_error(client, unique_name):
    resp = client.post(
        "/api/sboms/upload",
        data={"sbom_name": unique_name, "project_id": "999999"},
        files={"file": ("valid.json", json.dumps(_VALID_CYCLONEDX), "application/json")},
    )
    assert resp.status_code == 404
    assert resp.json()["detail"] == "Project not found"


def test_legacy_json_upload_accepts_project_id_alias(client, unique_name):
    project = client.post(
        "/api/projects",
        json={"project_name": f"alias-project-{unique_name}", "project_status": 1},
    )
    assert project.status_code == 201, project.text
    project_id = project.json()["id"]

    resp = client.post(
        "/api/sboms",
        json={
            "sbom_name": unique_name,
            "sbom_data": json.dumps(_VALID_CYCLONEDX),
            "project_id": project_id,
        },
    )
    assert resp.status_code == 201, resp.text
    body = resp.json()
    assert body["projectid"] == project_id
    assert body["project_id"] == project_id
    assert body["project_name"] == project.json()["project_name"]


def test_invalid_purl_creates_repair_session_not_trusted_sbom(client, unique_name):
    resp = client.post(
        "/api/sboms",
        json={"sbom_name": unique_name, "sbom_data": json.dumps(_BAD_PURL_CYCLONEDX)},
    )
    # Semantic-stage errors are 422 (not structural). The frontend keys on
    # this status to render the inline rejection banner.
    assert resp.status_code == 422, resp.text

    detail = resp.json()["detail"]
    assert detail["code"] == "sbom_validation_failed"
    assert detail["status"] == "validation_failed"
    assert detail["failed_stage"] == "semantic"
    assert detail["error_count"] >= 1
    assert detail["can_edit"] is True
    assert detail["can_ai_fix"] is True
    assert isinstance(detail["entries"], list) and detail["entries"], detail
    assert detail["sbom_id"] is None
    session_id = detail["session_id"]
    assert isinstance(session_id, str) and session_id

    # The first entry must mention the malformed PURL with its full
    # structured shape — no information loss between validator and API.
    first = detail["entries"][0]
    assert {"code", "severity", "stage", "path", "message", "remediation"}.issubset(first.keys())
    assert first["severity"] == "error"

    session = client.get(f"/api/sbom-validation-sessions/{session_id}").json()
    assert session["validation_status"] == "failed"
    assert session["current_content"] == json.dumps(_BAD_PURL_CYCLONEDX)
    assert session["latest_error_report"]["error_count"] == detail["error_count"]

    from app.db import SessionLocal
    from app.models import SBOMSource

    db = SessionLocal()
    try:
        assert db.query(SBOMSource).filter(SBOMSource.sbom_name == unique_name).first() is None
    finally:
        db.close()


def test_repair_session_survives_get_after_failure(client, unique_name):
    """Page-refresh equivalent: after rejection, the repair session remains
    reachable but no trusted SBOM row exists."""
    resp = client.post(
        "/api/sboms",
        json={"sbom_name": unique_name, "sbom_data": json.dumps(_BAD_PURL_CYCLONEDX)},
    )
    assert resp.status_code == 422, resp.text
    session_id = resp.json()["detail"]["session_id"]

    # Two reads — assert idempotent shape (no in-flight state)
    a = client.get(f"/api/sbom-validation-sessions/{session_id}").json()
    b = client.get(f"/api/sbom-validation-sessions/{session_id}").json()
    assert a == b
    assert a["validation_status"] == "failed"
    assert a["latest_error_report"]["entries"]
    assert a["latest_error_report"]["entries"][0]["severity"] == "error"

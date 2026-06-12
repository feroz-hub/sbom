from __future__ import annotations

import json
from pathlib import Path

from app.models import SBOMSource, SBOMValidationSession, SBOMValidationSessionEvent

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


def _create_failed_session(client, name: str | None = None) -> tuple[str, dict]:
    resp = client.post(
        "/api/sboms",
        json={"sbom_name": name or _unique("repair"), "sbom_data": json.dumps(BAD_PURL_CYCLONEDX)},
    )
    assert resp.status_code == 422, resp.text
    detail = resp.json()["detail"]
    assert detail["session_id"]
    return detail["session_id"], detail


def _create_project(client, prefix: str = "repair-project") -> dict:
    resp = client.post(
        "/api/projects",
        json={"project_name": _unique(prefix), "project_status": 1},
    )
    assert resp.status_code == 201, resp.text
    return resp.json()


def test_upload_invalid_sbom_creates_validation_session_not_normal_sbom(client):
    name = _unique("invalid")
    session_id, detail = _create_failed_session(client, name)

    assert detail["status"] == "validation_failed"
    assert detail["sbom_id"] is None
    assert detail["can_edit"] is True
    assert detail["can_ai_fix"] is True

    from app.db import SessionLocal

    db = SessionLocal()
    try:
        assert db.query(SBOMSource).filter(SBOMSource.sbom_name == name).first() is None
        session = db.get(SBOMValidationSession, session_id)
        assert session is not None
        assert session.validation_status == "failed"
        assert session.imported_sbom_id is None
        assert db.query(SBOMValidationSessionEvent).filter_by(session_id=session_id, event_type="created").count() == 1
    finally:
        db.close()


def test_upload_security_blocked_payload_does_not_create_editable_session(client):
    attack = (Path(__file__).parent / "fixtures" / "sboms" / "attack" / "json_depth_bomb.json").read_text()
    resp = client.post("/api/sboms", json={"sbom_name": _unique("blocked"), "sbom_data": attack})
    assert resp.status_code in {400, 413}, resp.text
    detail = resp.json()["detail"]
    assert detail["status"] == "validation_failed"
    assert detail["session_id"] is None
    assert detail["can_edit"] is False
    assert detail["can_ai_fix"] is False
    assert detail["reason"] == "Payload blocked by security validation"


def test_get_patch_and_history_records_manual_edit(client):
    session_id, _ = _create_failed_session(client)
    edited = json.dumps({**BAD_PURL_CYCLONEDX, "version": 2})
    resp = client.patch(f"/api/sbom-validation-sessions/{session_id}", json={"current_content": edited})
    assert resp.status_code == 200, resp.text
    assert resp.json()["current_content"] == edited
    assert resp.json()["validation_status"] == "edited"

    history = client.get(f"/api/sbom-validation-sessions/{session_id}/history")
    assert history.status_code == 200
    event_types = [event["event_type"] for event in history.json()]
    assert event_types == ["created", "manual_edit"]


def test_revalidate_session_updates_report(client):
    session_id, _ = _create_failed_session(client)
    resp = client.post(f"/api/sbom-validation-sessions/{session_id}/validate")
    assert resp.status_code == 200, resp.text
    body = resp.json()
    assert body["validation_status"] == "failed"
    assert body["latest_error_report"]["failed_stage"] == "semantic"
    assert body["latest_error_report"]["error_count"] >= 1


def test_import_blocked_until_validation_passes_then_succeeds_after_patch(client):
    name = _unique("import-after-repair")
    session_id, _ = _create_failed_session(client, name)

    blocked = client.post(f"/api/sbom-validation-sessions/{session_id}/import")
    assert blocked.status_code == 422

    patch_resp = client.post(
        f"/api/sbom-validation-sessions/{session_id}/apply-patch",
        json={
            "patches": [
                {
                    "target": "/components/0/purl",
                    "operation": "replace",
                    "before": "not-a-purl",
                    "after": "pkg:generic/x@1.0.0",
                    "reason": "Replace malformed package URL with a valid purl.",
                    "validation_error_codes": ["SBOM_VAL_E052_PURL_INVALID"],
                }
            ]
        },
    )
    assert patch_resp.status_code == 200, patch_resp.text
    assert patch_resp.json()["validation_status"] == "passed"

    imported = client.post(f"/api/sbom-validation-sessions/{session_id}/import")
    assert imported.status_code == 200, imported.text
    body = imported.json()
    assert body["sbom_name"] == name
    assert body["status"] == "validated"

    session = client.get(f"/api/sbom-validation-sessions/{session_id}").json()
    assert session["imported_sbom_id"] == body["id"]
    assert session["validation_status"] == "imported"


def test_failed_upload_session_and_repair_import_preserve_project_id(client):
    project = _create_project(client)
    name = _unique("project-repair")
    resp = client.post(
        "/api/sboms",
        json={
            "sbom_name": name,
            "sbom_data": json.dumps(BAD_PURL_CYCLONEDX),
            "project_id": project["id"],
        },
    )
    assert resp.status_code == 422, resp.text
    session_id = resp.json()["detail"]["session_id"]

    session = client.get(f"/api/sbom-validation-sessions/{session_id}").json()
    assert session["project_id"] == project["id"]

    patch_resp = client.post(
        f"/api/sbom-validation-sessions/{session_id}/apply-patch",
        json={
            "patches": [
                {
                    "target": "/components/0/purl",
                    "operation": "replace",
                    "before": "not-a-purl",
                    "after": "pkg:generic/x@1.0.0",
                    "reason": "Replace malformed package URL with a valid purl.",
                    "validation_error_codes": ["SBOM_VAL_E052_PURL_INVALID"],
                }
            ]
        },
    )
    assert patch_resp.status_code == 200, patch_resp.text
    assert patch_resp.json()["validation_status"] == "passed"

    imported = client.post(f"/api/sbom-validation-sessions/{session_id}/import")
    assert imported.status_code == 200, imported.text
    body = imported.json()
    assert body["projectid"] == project["id"]
    assert body["project_id"] == project["id"]
    assert body["project_name"] == project["project_name"]

    refreshed_project = client.get(f"/api/projects/{project['id']}").json()
    assert refreshed_project["sbom_count"] == 1


def test_apply_patch_revalidates_and_rejects_signature_fake_fix(client):
    session_id, _ = _create_failed_session(client)
    resp = client.post(
        f"/api/sbom-validation-sessions/{session_id}/apply-patch",
        json={
            "patches": [
                {
                    "target": "/signature",
                    "operation": "add",
                    "after": {"algorithm": "fake"},
                    "reason": "fake signature",
                    "validation_error_codes": ["SBOM_VAL_E110_SIGNATURE_INVALID"],
                }
            ]
        },
    )
    assert resp.status_code == 422


def test_ai_suggestion_endpoint_returns_structured_suggestions_and_history(client, monkeypatch):
    session_id, _ = _create_failed_session(client)

    async def fake_call(self, session, *, user_instruction=None):
        from app.services.validation_repair_service import AiRepairSuggestion

        return AiRepairSuggestion(
            summary="Fix malformed purl",
            risk="low",
            patches=[
                {
                    "target": "/components/0/purl",
                    "operation": "replace",
                    "before": "not-a-purl",
                    "after": "pkg:generic/x@1.0.0",
                    "reason": "Valid purl format",
                    "validation_error_codes": ["SBOM_VAL_E052_PURL_INVALID"],
                }
            ],
            requires_user_review=True,
        )

    monkeypatch.setattr(
        "app.services.validation_repair_service.ValidationRepairService._call_ai_for_suggestion",
        fake_call,
    )
    resp = client.post(
        f"/api/sbom-validation-sessions/{session_id}/ai/suggest-fixes",
        json={"user_instruction": "fix safe fields only"},
    )
    assert resp.status_code == 200, resp.text
    body = resp.json()
    assert body["requires_user_review"] is True
    assert body["patches"][0]["target"] == "/components/0/purl"

    history = client.get(f"/api/sbom-validation-sessions/{session_id}/history").json()
    assert "ai_suggestion_generated" in [event["event_type"] for event in history]

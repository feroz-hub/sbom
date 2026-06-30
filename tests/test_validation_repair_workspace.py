from __future__ import annotations

import json
from datetime import UTC, datetime
from hashlib import sha256
from pathlib import Path

from app.models import AuditLog, SBOMSource, SBOMValidationSession, SBOMValidationSessionEvent

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
    assert detail["validation_session_id"] == session_id
    assert detail["repair_workspace_url"] == f"/repair/{session_id}"
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
        assert session.raw_content_text == json.dumps(BAD_PURL_CYCLONEDX)
        assert session.repair_content_text == json.dumps(BAD_PURL_CYCLONEDX)
        assert session.original_size_bytes == len(json.dumps(BAD_PURL_CYCLONEDX).encode("utf-8"))
        assert session.original_sha256 == sha256(json.dumps(BAD_PURL_CYCLONEDX).encode("utf-8")).hexdigest()
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
    assert resp.json()["validation_status"] == "repair_draft"

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


def test_validation_session_content_chunks_and_download_preserve_original_bytes(client):
    original = b'{\r\n  "bomFormat": "CycloneDX",\r\n  "components": [\r\n'
    original_hash = sha256(original).hexdigest()
    resp = client.post(
        "/api/sboms/upload",
        data={"sbom_name": _unique("multipart-invalid")},
        files={"file": ("invalid.json", original, "application/json")},
    )
    assert resp.status_code in {400, 415, 422}, resp.text
    detail = resp.json()["detail"]
    session_id = detail["validation_session_id"]
    assert detail["file_size_bytes"] == len(original)
    assert detail["sha256"] == original_hash

    first = client.get(f"/api/sbom-validation-sessions/{session_id}/content?offset=0&limit=10")
    assert first.status_code == 200, first.text
    first_body = first.json()
    assert first_body["content"] == original.decode("utf-8")[:10]
    assert first_body["eof"] is False

    rest = client.get(f"/api/sbom-validation-sessions/{session_id}/content?offset=10&limit=10000")
    assert rest.status_code == 200, rest.text
    assert first_body["content"] + rest.json()["content"] == original.decode("utf-8")

    downloaded = client.get(f"/api/sbom-validation-sessions/{session_id}/download-original")
    assert downloaded.status_code == 200, downloaded.text
    assert downloaded.content == original
    assert sha256(downloaded.content).hexdigest() == original_hash

    from app.db import SessionLocal

    db = SessionLocal()
    try:
        actions = {
            row.action
            for row in db.query(AuditLog)
            .filter(AuditLog.entity_id == session_id)
            .all()
        }
        assert "sbom.validation_session.created" in actions
        assert "sbom.validation_session.download_original" in actions
    finally:
        db.close()


def test_large_invalid_upload_retrieves_more_than_first_ten_lines(client):
    lines = ["{", '  "bomFormat": "CycloneDX",']
    lines.extend(f'  "pad{i}": "x",' for i in range(40_000))
    lines.append('  "components": [')
    raw = ("\n".join(lines)).encode("utf-8")
    resp = client.post(
        "/api/sboms/upload",
        data={"sbom_name": _unique("large-invalid")},
        files={"file": ("large-invalid.json", raw, "application/json")},
    )
    assert resp.status_code in {400, 415, 422}, resp.text
    session_id = resp.json()["detail"]["validation_session_id"]

    meta = client.get(f"/api/sbom-validation-sessions/{session_id}")
    assert meta.status_code == 200, meta.text
    assert meta.json()["total_lines"] > 40_000

    chunk = client.get(f"/api/sbom-validation-sessions/{session_id}/content-lines?start_line=11&line_count=20")
    assert chunk.status_code == 200, chunk.text
    body = chunk.json()
    assert body["start_line"] == 11
    assert len(body["lines"]) == 20
    assert body["lines"][0].startswith('  "pad8"')
    assert body["total_lines"] > 40_000


def test_valid_multipart_upload_creates_accessible_workspace(client):
    valid = {
        "bomFormat": "CycloneDX",
        "specVersion": "1.5",
        "version": 1,
        "metadata": {"timestamp": "2026-04-30T12:00:00Z"},
        "components": [{"type": "library", "name": "ok", "version": "1.0.0"}],
    }
    raw = json.dumps(valid).encode("utf-8")
    resp = client.post(
        "/api/sboms/upload",
        data={"sbom_name": _unique("valid-workspace")},
        files={"file": ("valid.cdx.json", raw, "application/json")},
    )
    assert resp.status_code == 202, resp.text
    body = resp.json()
    assert body["workspace_id"]
    assert body["validation_session_id"] == body["workspace_id"]
    assert body["repair_workspace_url"] == f"/repair/{body['workspace_id']}"
    assert body["detected_format"] == "cyclonedx"
    assert body["sha256"] == sha256(raw).hexdigest()

    workspace = client.get(f"/api/sbom-workspaces/{body['workspace_id']}")
    assert workspace.status_code == 200, workspace.text
    meta = workspace.json()
    assert meta["imported_sbom_id"] == body["sbom_id"]
    assert meta["validation_status"] in {"valid", "valid_with_warnings"}
    assert meta["full_editor_allowed"] is True

    detail = client.get(f"/api/sboms/{body['sbom_id']}")
    assert detail.status_code == 200, detail.text
    detail_body = detail.json()
    assert detail_body["workspace_id"] == body["workspace_id"]
    assert detail_body["validation_session_id"] == body["workspace_id"]
    assert detail_body["repair_workspace_url"] == f"/repair/{body['workspace_id']}"
    assert detail_body["validation_status"] in {"valid", "valid_with_warnings", "imported"}

    listed = client.get("/api/sboms?page_size=500")
    assert listed.status_code == 200, listed.text
    listed_match = next(row for row in listed.json() if row["id"] == body["sbom_id"])
    assert listed_match["workspace_id"] == body["workspace_id"]


def test_valid_with_warnings_upload_creates_accessible_workspace(client):
    warning_only = {
        "bomFormat": "CycloneDX",
        "specVersion": "1.5",
        "version": 1,
        "metadata": {"timestamp": "2026-04-30T12:00:00Z"},
        "components": [{"type": "library", "name": "warn-only", "version": "1.0.0"}],
    }
    raw = json.dumps(warning_only).encode("utf-8")
    resp = client.post(
        "/api/sboms/upload",
        data={"sbom_name": _unique("warning-workspace")},
        files={"file": ("warning.cdx.json", raw, "application/json")},
    )
    assert resp.status_code == 202, resp.text
    body = resp.json()
    assert body["status"] == "valid_with_warnings"
    assert body["workspace_id"]
    assert body["validation_session_id"] == body["workspace_id"]
    assert body["repair_workspace_url"] == f"/repair/{body['workspace_id']}"
    assert body["validation_warnings"]

    workspace = client.get(f"/api/sbom-workspaces/{body['workspace_id']}")
    assert workspace.status_code == 200, workspace.text
    assert workspace.json()["validation_status"] == "valid_with_warnings"


def test_workspace_search_and_original_source_lines(client):
    session_id, _ = _create_failed_session(client)
    lines = client.get(
        f"/api/sbom-validation-sessions/{session_id}/content/lines",
        params={"source": "original", "start_line": 1, "line_count": 3},
    )
    assert lines.status_code == 200, lines.text
    assert lines.json()["lines"]

    search = client.get(
        f"/api/sbom-validation-sessions/{session_id}/search",
        params={"q": "not-a-purl", "source": "repair_draft", "limit": 10},
    )
    assert search.status_code == 200, search.text
    assert search.json()["matches"][0]["line_number"] >= 1


def test_unsupported_upload_creates_accessible_workspace(client):
    raw = b'{"not": "an sbom"}'
    resp = client.post(
        "/api/sboms/upload",
        data={"sbom_name": _unique("unsupported-workspace")},
        files={"file": ("unsupported.json", raw, "application/json")},
    )
    assert resp.status_code in {400, 415, 422}, resp.text
    detail = resp.json()["detail"]
    session_id = detail["validation_session_id"]
    assert detail["workspace_id"] == session_id
    assert detail["repair_workspace_url"] == f"/repair/{session_id}"

    workspace = client.get(f"/api/sbom-workspaces/{session_id}")
    assert workspace.status_code == 200, workspace.text
    assert workspace.json()["validation_status"] == "unsupported_format"


def test_workspace_metadata_endpoint_allows_all_repair_workspace_statuses(client):
    session_id, _ = _create_failed_session(client)

    from app.db import SessionLocal

    for status in [
        "failed",
        "unsupported",
        "unsupported_format",
        "valid",
        "valid_with_warnings",
        "warning",
        "repair_draft",
        "repaired",
        "repaired_valid",
        "imported",
    ]:
        db = SessionLocal()
        try:
            session = db.get(SBOMValidationSession, session_id)
            assert session is not None
            session.validation_status = status
            db.add(session)
            db.commit()
        finally:
            db.close()

        workspace = client.get(f"/api/sbom-workspaces/{session_id}")
        assert workspace.status_code == 200, (status, workspace.text)
        assert workspace.json()["validation_status"] == status


def test_sbom_detail_marks_legacy_validated_sbom_backfillable(client):
    raw = json.dumps(
        {
            "bomFormat": "CycloneDX",
            "specVersion": "1.5",
            "version": 1,
            "metadata": {"timestamp": "2026-04-30T12:00:00Z"},
            "components": [{"type": "library", "name": "legacy", "version": "1.0.0"}],
        }
    )
    created = client.post("/api/sboms", json={"sbom_name": _unique("legacy-backfillable"), "sbom_data": raw})
    assert created.status_code == 201, created.text
    sbom_id = created.json()["id"]

    detail = client.get(f"/api/sboms/{sbom_id}")
    assert detail.status_code == 200, detail.text
    body = detail.json()
    assert body["workspace_id"] is None
    assert body["workspace_available"] is True
    assert body["workspace_source"] == "backfillable"
    assert body["detected_format"] == "cyclonedx"
    assert body["detected_spec_version"] == "1.5"
    assert body["original_size_bytes"] == len(raw.encode("utf-8"))
    assert body["original_sha256"] == sha256(raw.encode("utf-8")).hexdigest()


def test_sbom_detail_marks_legacy_record_without_original_content_unavailable(client):
    raw = json.dumps(
        {
            "bomFormat": "CycloneDX",
            "specVersion": "1.5",
            "version": 1,
            "metadata": {"timestamp": "2026-04-30T12:00:00Z"},
            "components": [{"type": "library", "name": "missing-original", "version": "1.0.0"}],
        }
    )
    created = client.post("/api/sboms", json={"sbom_name": _unique("legacy-missing"), "sbom_data": raw})
    assert created.status_code == 201, created.text
    sbom_id = created.json()["id"]

    from app.db import SessionLocal

    db = SessionLocal()
    try:
        sbom = db.get(SBOMSource, sbom_id)
        assert sbom is not None
        sbom.sbom_data = None
        db.add(sbom)
        db.commit()
    finally:
        db.close()

    detail = client.get(f"/api/sboms/{sbom_id}")
    assert detail.status_code == 200, detail.text
    body = detail.json()
    assert body["workspace_available"] is False
    assert body["workspace_source"] == "unavailable"
    assert "Original SBOM content is not available" in body["workspace_unavailable_reason"]


def test_create_workspace_for_existing_sbom_is_idempotent(client):
    raw = json.dumps(
        {
            "bomFormat": "CycloneDX",
            "specVersion": "1.5",
            "version": 1,
            "metadata": {"timestamp": "2026-04-30T12:00:00Z"},
            "components": [{"type": "library", "name": "legacy-create", "version": "1.0.0"}],
        }
    )
    created = client.post("/api/sboms", json={"sbom_name": _unique("legacy-create"), "sbom_data": raw})
    assert created.status_code == 201, created.text
    sbom_id = created.json()["id"]

    first = client.post(f"/api/sboms/{sbom_id}/workspace")
    assert first.status_code == 200, first.text
    first_body = first.json()
    assert first_body["created"] is True
    assert first_body["workspace_id"]
    assert first_body["repair_workspace_url"] == f"/repair/{first_body['workspace_id']}"
    assert first_body["imported_sbom_id"] == sbom_id
    assert first_body["detected_format"] == "cyclonedx"

    second = client.post(f"/api/sboms/{sbom_id}/workspace")
    assert second.status_code == 200, second.text
    second_body = second.json()
    assert second_body["created"] is False
    assert second_body["workspace_id"] == first_body["workspace_id"]

    workspace = client.get(f"/api/sbom-workspaces/{first_body['workspace_id']}")
    assert workspace.status_code == 200, workspace.text


def test_cross_tenant_workspace_backfill_denied(client):
    from app.core.context import minimal_background_context, tenant_scope
    from app.db import SessionLocal
    from app.models import Tenant

    db = SessionLocal()
    try:
        now_dt = datetime.now(UTC)
        tenant = Tenant(
            name="Other Workspace Tenant",
            slug=_unique("other-workspace-tenant"),
            external_iam_tenant_id=_unique("other-workspace-tenant-ext"),
            status="ACTIVE",
            created_at=now_dt,
            updated_at=now_dt,
        )
        db.add(tenant)
        db.flush()
        with tenant_scope(minimal_background_context(tenant.id, tenant.external_iam_tenant_id)):
            sbom = SBOMSource(
                sbom_name=_unique("other-tenant-sbom"),
                sbom_data=json.dumps(
                    {
                        "bomFormat": "CycloneDX",
                        "specVersion": "1.5",
                        "version": 1,
                        "components": [],
                    }
                ),
                status="validated",
                error_count=0,
                warning_count=0,
                created_on=now_dt.isoformat(),
                created_by="other",
            )
            db.add(sbom)
            db.commit()
            sbom_id = sbom.id
    finally:
        db.close()

    denied = client.post(f"/api/sboms/{sbom_id}/workspace")
    assert denied.status_code == 404


def test_large_line_patch_updates_full_repair_draft(client):
    lines = ["{", '  "bomFormat": "CycloneDX",', '  "specVersion": "1.4",', '  "components": [']
    lines.extend(f'    {{"type":"library","name":"pkg-{i}","version":"1.0.0"}},' for i in range(25_000))
    lines.append("  ]")
    raw = ("\n".join(lines)).encode("utf-8")
    resp = client.post(
        "/api/sboms/upload",
        data={"sbom_name": _unique("line-patch-large")},
        files={"file": ("line-patch-large.json", raw, "application/json")},
    )
    assert resp.status_code in {400, 422}, resp.text
    session_id = resp.json()["detail"]["validation_session_id"]

    patched = client.post(
        f"/api/sbom-validation-sessions/{session_id}/repair/patches",
        json={
            "patches": [
                {
                    "operation": "replace_lines",
                    "start_line": len(lines),
                    "end_line": len(lines),
                    "replacement_text": "  ]\n}",
                }
            ]
        },
    )
    assert patched.status_code == 200, patched.text
    assert patched.json()["validation_status"] == "repair_draft"

    tail = client.get(
        f"/api/sbom-validation-sessions/{session_id}/content/lines",
        params={"start_line": len(lines), "line_count": 2},
    )
    assert tail.status_code == 200, tail.text
    assert tail.json()["lines"][-1] == "}"


def test_save_repair_draft_stores_full_content_and_revalidate_uses_it(client):
    session_id, _ = _create_failed_session(client)
    full_draft = "\n".join(f"line-{i}" for i in range(200)) + "\nnot-json"
    draft = client.put(f"/api/sbom-validation-sessions/{session_id}/repair-draft", json={"content": full_draft})
    assert draft.status_code == 200, draft.text
    body = draft.json()
    assert body["validation_status"] == "repair_draft"
    assert body["current_content"] == full_draft
    assert body["stored_sha256"] == sha256(full_draft.encode("utf-8")).hexdigest()
    assert body["total_lines"] == 201

    chunk = client.get(f"/api/sbom-validation-sessions/{session_id}/content?offset=0&limit=100000")
    assert chunk.status_code == 200, chunk.text
    assert chunk.json()["content"] == full_draft

    revalidated = client.post(f"/api/sbom-validation-sessions/{session_id}/revalidate")
    assert revalidated.status_code == 200, revalidated.text
    assert revalidated.json()["validation_status"] == "failed"
    assert revalidated.json()["latest_error_report"]["error_count"] >= 1


def test_valid_repaired_draft_revalidates_then_imports_trusted_sbom(client):
    name = _unique("valid-draft-import")
    session_id, _ = _create_failed_session(client, name)
    fixed = json.dumps(
        {
            **BAD_PURL_CYCLONEDX,
            "components": [
                {
                    **BAD_PURL_CYCLONEDX["components"][0],
                    "purl": "pkg:generic/x@1.0.0",
                }
            ],
        }
    )
    draft = client.put(f"/api/sbom-validation-sessions/{session_id}/repair-draft", json={"content": fixed})
    assert draft.status_code == 200, draft.text
    revalidated = client.post(f"/api/sbom-validation-sessions/{session_id}/revalidate")
    assert revalidated.status_code == 200, revalidated.text
    assert revalidated.json()["validation_status"] == "repaired_valid"

    imported = client.post(f"/api/sbom-validation-sessions/{session_id}/import")
    assert imported.status_code == 200, imported.text
    sbom_id = imported.json()["id"]

    workspace = client.get(f"/api/sbom-workspaces/{session_id}")
    assert workspace.status_code == 200, workspace.text
    assert workspace.json()["validation_status"] == "imported"

    detail = client.get(f"/api/sboms/{sbom_id}")
    assert detail.status_code == 200, detail.text
    assert detail.json()["workspace_id"] == session_id
    assert detail.json()["repair_workspace_url"] == f"/repair/{session_id}"

    from app.db import SessionLocal

    db = SessionLocal()
    try:
        trusted = db.get(SBOMSource, sbom_id)
        assert trusted is not None
        assert trusted.sbom_name == name
        assert "pkg:generic/x@1.0.0" in trusted.sbom_data
    finally:
        db.close()


def test_validation_session_cross_tenant_access_denied(client):
    from app.core.context import minimal_background_context, tenant_scope
    from app.db import SessionLocal
    from app.models import Tenant

    db = SessionLocal()
    try:
        now_dt = datetime.now(UTC)
        now = now_dt.isoformat()
        tenant = Tenant(
            name="Other Tenant",
            slug=_unique("other-tenant"),
            external_iam_tenant_id=_unique("other-tenant-ext"),
            status="ACTIVE",
            created_at=now_dt,
            updated_at=now_dt,
        )
        db.add(tenant)
        db.flush()
        with tenant_scope(minimal_background_context(tenant.id, tenant.external_iam_tenant_id)):
            session = SBOMValidationSession(
                id=_unique("cross-tenant-session"),
                original_filename="other.json",
                sbom_name="other",
                sanitized_content="{}",
                current_content="{}",
                raw_content_text="{}",
                repair_content_text="{}",
                validation_status="failed",
                latest_error_report_json={"entries": [], "error_count": 0, "warning_count": 0},
                can_edit=True,
                can_ai_fix=True,
                content_sha256=sha256(b"{}").hexdigest(),
                created_at=now,
                updated_at=now,
                expires_at=now,
            )
            db.add(session)
            db.commit()
            session_id = session.id
    finally:
        db.close()

    denied = client.get(f"/api/sbom-validation-sessions/{session_id}")
    assert denied.status_code == 404


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
    assert patch_resp.json()["validation_status"] == "repaired_valid"

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
    assert patch_resp.json()["validation_status"] == "repaired_valid"

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


def test_lazy_session_creation_and_inplace_import(client):
    project = _create_project(client)
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

    resp = client.post(
        "/api/sboms",
        json={
            "sbom_name": _unique("inplace-test"),
            "sbom_data": json.dumps(CLEAN_CYCLONEDX),
            "project_id": project["id"],
        },
    )
    assert resp.status_code == 201, resp.text
    sbom_data = resp.json()
    sbom_id = sbom_data["id"]

    from app.db import SessionLocal

    db = SessionLocal()
    try:
        sbom = db.get(SBOMSource, sbom_id)
        assert sbom is not None
        sbom.sbom_data = json.dumps(BAD_PURL_CYCLONEDX)
        sbom.status = "failed"
        sbom.error_count = 1
        db.add(sbom)
        db.commit()
    finally:
        db.close()

    report_resp = client.get(f"/api/sboms/{sbom_id}/validation-report")
    assert report_resp.status_code == 200
    report_body = report_resp.json()
    assert report_body["status"] == "failed"
    session_id = report_body["session_id"]
    assert session_id is not None
    assert report_body["can_edit"] is True

    patched_content = json.dumps(CLEAN_CYCLONEDX)
    patch_resp = client.patch(f"/api/sbom-validation-sessions/{session_id}", json={"current_content": patched_content})
    assert patch_resp.status_code == 200

    import_resp = client.post(f"/api/sbom-validation-sessions/{session_id}/import")
    assert import_resp.status_code == 200
    imported_body = import_resp.json()
    assert imported_body["id"] == sbom_id
    assert imported_body["status"] == "validated"
    assert imported_body["error_count"] == 0

    db = SessionLocal()
    try:
        updated_sbom = db.get(SBOMSource, sbom_id)
        assert updated_sbom.status == "validated"
        assert "pkg:generic/x@1.0.0" in updated_sbom.sbom_data
    finally:
        db.close()

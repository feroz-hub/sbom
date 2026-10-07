"""Phase 1 application release boundaries, using the normal API and Postgres fixture."""

import hashlib
import json
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

import pytest
from app.core.context import CurrentContext
from app.core.permissions import ROLE_PERMISSIONS
from app.core.security import get_current_tenant_context
from app.db import SessionLocal
from app.models import AuditLog, SBOMRepairJob, SBOMSource, SBOMValidationSession, SBOMValidationSessionEvent
from app.services.sbom.repair.engine import RepairEngine
from sqlalchemy import func, select, update

from tests.test_sbom_auto_repair import document, run_job, upload_invalid
from tests.test_sbom_upload_version_lineage import _product, _project


def base(session):
    return f"/api/sbom-validation-sessions/{session}/repair"


def test_repair_approval_preserves_upload_selected_application(client):
    project = _project(client)
    product = _product(client, project["id"])
    source = document()
    source["components"][0]["type"] = "LIBRARY"
    raw = json.dumps(source).encode()
    response = client.post(
        "/api/sboms/upload",
        data={"sbom_name": "release-scope", "project_id": project["id"], "product_id": product["id"]},
        files={"file": ("scope.cdx.json", raw, "application/json")},
    )
    assert response.status_code == 422
    session = response.json()["detail"]["session_id"]
    job = run_job(client, session)
    response = client.post(base(session) + f"/{job['repair_job_id']}/approve")
    assert response.status_code == 200, response.text
    with SessionLocal() as db:
        accepted = db.get(SBOMSource, response.json()["imported_sbom_id"])
        assert accepted.product_id == product["id"]
        assert accepted.projectid == project["id"]
        workspace = db.get(SBOMValidationSession, session)
        assert workspace.raw_content_blob == raw
        assert workspace.original_sha256 == hashlib.sha256(raw).hexdigest()


def test_valid_upload_does_not_create_repair_job_or_candidate(client, mock_external_sources):
    project = _project(client)
    product = _product(client, project["id"])
    raw = json.dumps(document()).encode()
    response = client.post(
        "/api/sboms/upload",
        data={"sbom_name": "valid-release", "project_id": project["id"], "product_id": product["id"]},
        files={"file": ("valid.cdx.json", raw, "application/json")},
    )
    assert response.status_code == 202
    with SessionLocal() as db:
        assert db.scalar(select(func.count()).select_from(SBOMRepairJob)) == 0
        accepted = db.get(SBOMSource, response.json()["sbom_id"])
        assert accepted.sbom_data.encode() == raw
        assert accepted.status == "validated"
        assert accepted.error_count == 0
    assert client.get(base(response.json()["validation_session_id"])).json() is None
    analysis = client.post(f"/api/sboms/{response.json()['sbom_id']}/analyze")
    assert analysis.status_code == 201, analysis.text
    assert analysis.json()["sbom_id"] == response.json()["sbom_id"]
    with SessionLocal() as db:
        assert db.scalar(select(func.count()).select_from(SBOMRepairJob)) == 0
        assert db.get(SBOMSource, response.json()["sbom_id"]).sbom_data.encode() == raw


def test_review_hash_mismatch_rejected_then_correct_hash_accepted(client):
    session = upload_invalid(client)
    job = run_job(client, session)
    url = base(session) + f"/{job['repair_job_id']}/approve"
    wrong = client.post(url, json={"candidate_sha256": "0" * 64})
    assert wrong.status_code == 409
    with SessionLocal() as db:
        row = db.get(SBOMRepairJob, job["repair_job_id"])
        assert row.approval_status == "PENDING"
        assert row.imported_sbom_id is None
    approved = client.post(url, json={"candidate_sha256": job["candidate_sha256"]})
    assert approved.status_code == 200
    assert approved.json()["approval_status"] == "APPROVED"
    assert client.post(url, json={"candidate_sha256": "0" * 64}).status_code == 409


def test_candidate_content_tamper_is_rejected_then_restored_candidate_can_be_approved(client):
    session = upload_invalid(client)
    job = run_job(client, session)
    with SessionLocal() as db:
        row = db.get(SBOMRepairJob, job["repair_job_id"])
        original_candidate = row.candidate_content
        db.execute(update(SBOMRepairJob).where(SBOMRepairJob.id == row.id).values(candidate_content="{}"))
        db.commit()
    url = base(session) + f"/{job['repair_job_id']}/approve"
    assert client.post(url).status_code == 409
    with SessionLocal() as db:
        db.execute(
            update(SBOMRepairJob)
            .where(SBOMRepairJob.id == job["repair_job_id"])
            .values(candidate_content=original_candidate)
        )
        db.commit()
    assert client.post(url).status_code == 200


@pytest.mark.parametrize("role", ["TENANT_ADMIN", "SECURITY_ANALYST", "DEVELOPER", "VIEWER"])
def test_existing_role_matrix_agrees_with_capabilities_and_backend(client, role):
    session = upload_invalid(client)
    job = run_job(client, session)
    ctx = CurrentContext(
        user_id=1,
        external_user_id="release-user",
        email=None,
        display_name="Release",
        tenant_id=1,
        external_tenant_id="default",
        roles=frozenset({role}),
        permissions=ROLE_PERMISSIONS[role],
    )
    client.app.dependency_overrides[get_current_tenant_context] = lambda: ctx
    try:
        response = client.get(base(session) + f"/{job['repair_job_id']}")
        assert response.status_code == 200
        caps = response.json()["capabilities"]
        writable = role in {"TENANT_ADMIN", "SECURITY_ANALYST"}
        assert caps["can_repair"] == writable
        assert caps["can_approve"] == writable
        assert caps["can_reject"] == writable
        assert caps["can_download"] == writable
        assert client.get(base(session) + f"/{job['repair_job_id']}/download").status_code == (200 if writable else 403)
        assert client.post(base(session)).status_code == (200 if writable else 403)
        if not writable:
            assert client.post(base(session) + f"/{job['repair_job_id']}/approve").status_code == 403
            assert client.post(base(session) + f"/{job['repair_job_id']}/reject").status_code == 403
    finally:
        client.app.dependency_overrides.pop(get_current_tenant_context, None)


def test_approval_requires_normal_upload_assignment_permission(client):
    session = upload_invalid(client)
    job = run_job(client, session)
    ctx = CurrentContext(
        user_id=1,
        external_user_id="release-user",
        email=None,
        display_name="Release",
        tenant_id=1,
        external_tenant_id="default",
        roles=frozenset({"TENANT_ADMIN"}),
        permissions=ROLE_PERMISSIONS["TENANT_ADMIN"] - {"product:assign_sbom"},
    )
    client.app.dependency_overrides[get_current_tenant_context] = lambda: ctx
    try:
        result = client.get(base(session) + f"/{job['repair_job_id']}").json()
        assert not result["capabilities"]["can_approve"]
        assert client.post(base(session) + f"/{job['repair_job_id']}/approve").status_code == 403
    finally:
        client.app.dependency_overrides.pop(get_current_tenant_context, None)


def test_concurrent_repair_is_idempotent(client):
    session = upload_invalid(client)
    with ThreadPoolExecutor(max_workers=2) as pool:
        results = list(pool.map(lambda _: client.post(base(session)), range(2)))
    assert [r.status_code for r in results] == [200, 200]
    assert len({r.json()["repair_job_id"] for r in results}) == 1
    with SessionLocal() as db:
        assert (
            db.scalar(select(func.count()).select_from(SBOMRepairJob).where(SBOMRepairJob.session_id == session)) == 1
        )


def test_concurrent_approval_imports_exactly_one_candidate(client):
    session = upload_invalid(client)
    job = run_job(client, session)
    with ThreadPoolExecutor(max_workers=2) as pool:
        results = list(pool.map(lambda _: client.post(base(session) + f"/{job['repair_job_id']}/approve"), range(2)))
    assert [r.status_code for r in results] == [200, 200]
    assert len({r.json()["imported_sbom_id"] for r in results}) == 1
    with SessionLocal() as db:
        assert (
            db.scalar(
                select(func.count())
                .select_from(AuditLog)
                .where(AuditLog.entity_id == job["repair_job_id"], AuditLog.action == "SBOM_REPAIR_APPROVED")
            )
            == 1
        )


def test_concurrent_approve_reject_has_one_terminal_decision(client):
    session = upload_invalid(client)
    job = run_job(client, session)
    with ThreadPoolExecutor(max_workers=2) as pool:
        results = list(
            pool.map(
                lambda action: client.post(base(session) + f"/{job['repair_job_id']}/{action}"), ["approve", "reject"]
            )
        )
    assert sorted(r.status_code for r in results) == [200, 409]
    with SessionLocal() as db:
        row = db.get(SBOMRepairJob, job["repair_job_id"])
        assert row.approval_status in {"APPROVED", "REJECTED"}
        events = db.scalars(
            select(SBOMValidationSessionEvent.event_type).where(
                SBOMValidationSessionEvent.session_id == session,
                SBOMValidationSessionEvent.event_type.in_(["SBOM_REPAIR_APPROVED", "SBOM_REPAIR_REJECTED"]),
            )
        ).all()
        assert len(events) == 1
        assert (row.imported_sbom_id is not None) == (row.approval_status == "APPROVED")


def test_rollback_retains_original_and_records_attempt(client):
    source = document()
    source["dependencies"] = [{"ref": "b", "dependsOn": ["pkg:npm/beta@2.0"]}]
    response = client.post("/api/sboms", json={"sbom_name": "rollback-release", "sbom_data": json.dumps(source)})
    assert response.status_code == 422
    session = response.json()["detail"]["session_id"]
    job = run_job(client, session)
    assert job["status"] == "REPAIR_FAILED"
    assert job["rollback"]
    assert job["rolled_back_changes"][0]["rule_name"] == "dangling_dependency_ref"
    with SessionLocal() as db:
        row = db.get(SBOMRepairJob, job["repair_job_id"])
        assert row.candidate_content == json.dumps(source)
        assert (
            db.scalar(
                select(SBOMValidationSessionEvent.id).where(
                    SBOMValidationSessionEvent.session_id == session,
                    SBOMValidationSessionEvent.event_type == "SBOM_REPAIR_RULE_ROLLED_BACK",
                )
            )
            is not None
        )
    assert client.post(base(session) + f"/{job['repair_job_id']}/approve").status_code == 409


def test_signed_document_has_explicit_manual_reason_without_mutation():
    source = document()
    source["components"][0]["type"] = "LIBRARY"
    source["signature"] = {"algorithm": "RS256", "value": "abc"}
    raw = json.dumps(source).encode()
    engine = RepairEngine()
    analysis = engine.analyze(raw)
    assert not analysis["repair_supported"]
    assert "Signed" in analysis["manual_review_reason"]
    assert analysis["auto_fixable"] == 0
    assert engine.run(raw).candidate == raw


@pytest.mark.parametrize("path", ["tests/fixtures/sboms/wild/spdx-2.3-tools-python-example.json"])
def test_accepted_spdx_json_formats_are_supported_for_repair(path):
    raw = Path(path).read_bytes()
    engine = RepairEngine()
    result = engine.analyze(raw)
    assert result["repair_supported"]
    assert result["format"] == "SPDX_JSON"
    assert result["manual_review_reason"] is None


def test_xml_repair_is_explicitly_unsupported_and_never_rewrites_bytes():
    raw = b'<bom xmlns="http://cyclonedx.org/schema/bom/1.6" version="1"><components><component type="library"><name>fixture</name><version>1</version></component></components></bom>'
    engine = RepairEngine()
    analysis = engine.analyze(raw)
    assert not analysis["repair_supported"]
    assert "unsupported" in analysis["manual_review_reason"]
    assert engine.run(raw).candidate == raw


def test_audit_and_logs_have_correlation_ids_and_no_payload(client, caplog):
    import logging

    session = upload_invalid(client)
    caplog.set_level(logging.INFO)
    client.post(base(session) + "/analyze", headers={"X-Request-ID": "release-analyze"})
    result = client.post(base(session), headers={"X-Request-ID": "release-run"}).json()
    client.post(base(session) + f"/{result['repair_job_id']}/approve", headers={"X-Request-ID": "release-approve"})
    records = [r for r in caplog.records if getattr(r, "event", "").startswith("SBOM_REPAIR_")]
    assert {r.event for r in records} >= {
        "SBOM_REPAIR_ANALYZED",
        "SBOM_REPAIR_STARTED",
        "SBOM_REPAIR_RULE_APPLIED",
        "SBOM_REPAIR_REVALIDATED",
        "SBOM_REPAIR_COMPLETED",
        "SBOM_REPAIR_APPROVED",
    }
    for record in records:
        assert record.tenant_id == 1
        assert record.user_id is not None
        assert record.request_id in {"release-analyze", "release-run", "release-approve"}
        assert record.status
        if record.event != "SBOM_REPAIR_ANALYZED":
            assert record.repair_job_id == result["repair_job_id"]
        assert "bomFormat" not in record.getMessage()
        assert "sbom_data" not in record.__dict__
        assert "candidate_content" not in record.__dict__


def test_repair_preserves_declared_versions_parent_and_explicit_current_selection(client):
    from app.models import Product

    from tests.test_sbom_upload_version_lineage import _upload

    project = _project(client)
    product = _product(client, project["id"])
    parent = _upload(client, project_id=project["id"], product_id=product["id"], version="1.0").json()
    parent_raw = client.get(f"/api/sboms/{parent['sbom_id']}?include_raw=true").json()["sbom_data"]
    source = document()
    source["components"][0]["type"] = "LIBRARY"
    response = client.post(
        "/api/sboms/upload",
        data={
            "sbom_name": "declared-release-version",
            "project_id": project["id"],
            "product_id": product["id"],
            "parent_sbom_id": parent["sbom_id"],
            "sbom_version": "2.0",
            "product_version": "Release-2",
            "set_as_current": "true",
        },
        files={"file": ("versioned.cdx.json", json.dumps(source).encode(), "application/json")},
    )
    assert response.status_code == 422, response.text
    session = response.json()["detail"]["session_id"]
    job = run_job(client, session)
    approved = client.post(base(session) + f"/{job['repair_job_id']}/approve")
    assert approved.status_code == 200, approved.text
    with SessionLocal() as db:
        candidate = db.get(SBOMSource, approved.json()["imported_sbom_id"])
        assert candidate.sbom_version == "2.0"
        assert candidate.productver == "Release-2"
        assert candidate.parent_id == parent["sbom_id"]
        assert candidate.product_id == product["id"]
        assert db.get(Product, product["id"]).current_sbom_id == candidate.id
        assert db.get(SBOMSource, parent["sbom_id"]).sbom_data == parent_raw


def test_duplicate_ref_bom_link_is_not_rebound_to_arbitrary_component():
    source = document()
    source["dependencies"] = []
    source["components"][1]["bom-ref"] = "a"
    source["components"][0]["externalReferences"] = [
        {"type": "bom", "url": "urn:cdx:99999999-aaaa-bbbb-cccc-dddddddddddd/1#a"}
    ]
    raw = json.dumps(source).encode()
    result = RepairEngine().run(raw)
    assert result.report["repairs_applied"] == 0
    assert result.report["analysis"]["suggested"] >= 1
    assert result.candidate == raw


@pytest.mark.parametrize("suffix", ["", "/changes", "/download", "/report", "/approve", "/reject"])
def test_unknown_repair_ids_use_safe_not_found_envelope(client, suffix):
    session = upload_invalid(client)
    url = base(session) + "/not-a-job" + suffix
    result = client.post(url) if suffix in {"/approve", "/reject"} else client.get(url)
    assert result.status_code == 404
    body = result.json()
    assert "error" in body or "detail" in body
    assert "candidate_content" not in result.text
    assert "traceback" not in result.text.lower()


def test_terminal_decisions_are_idempotent_and_cannot_be_reversed(client):
    session = upload_invalid(client)
    job = run_job(client, session)
    root = base(session) + f"/{job['repair_job_id']}"
    first = client.post(root + "/approve").json()
    retry = client.post(root + "/approve").json()
    assert first["imported_sbom_id"] == retry["imported_sbom_id"]
    assert retry["already_approved"]
    assert client.post(root + "/reject").status_code == 409
    session = upload_invalid(client)
    job = run_job(client, session)
    root = base(session) + f"/{job['repair_job_id']}"
    assert client.post(root + "/reject").json()["approval_status"] == "REJECTED"
    assert client.post(root + "/reject").json()["approval_status"] == "REJECTED"
    assert client.post(root + "/approve").status_code == 409


def test_rejection_and_rollback_failure_emit_safe_correlated_logs(client, caplog):
    import logging

    caplog.set_level(logging.INFO)
    session = upload_invalid(client)
    job = run_job(client, session)
    client.post(base(session) + f"/{job['repair_job_id']}/reject", headers={"X-Request-ID": "release-reject"})
    source = document()
    source["dependencies"] = [{"ref": "b", "dependsOn": ["pkg:npm/beta@2.0"]}]
    response = client.post("/api/sboms", json={"sbom_name": "rollback-audit", "sbom_data": json.dumps(source)})
    session = response.json()["detail"]["session_id"]
    failed = client.post(base(session), headers={"X-Request-ID": "release-failure"}).json()
    events = {r.event: r for r in caplog.records if getattr(r, "event", "").startswith("SBOM_REPAIR_")}
    assert events["SBOM_REPAIR_REJECTED"].request_id == "release-reject"
    assert events["SBOM_REPAIR_FAILED"].request_id == "release-failure"
    assert events["SBOM_REPAIR_FAILED"].repair_job_id == failed["repair_job_id"]
    assert events["SBOM_REPAIR_RULE_ROLLED_BACK"].repair_rule == "dangling_dependency_ref"
    assert failed["analysis"]["auto_fixable"] == 0
    assert failed["analysis"]["manual_only"] > 0
    assert "rolled back" in failed["manual_review_reason"]
    assert all("bomFormat" not in r.getMessage() for r in events.values())


def test_deletion_removes_job_metadata_but_preserves_unrelated_repair_and_original_files(client, monkeypatch, tmp_path):
    from app.services.sbom_delete_service import SBOMDeleteService

    monkeypatch.setenv("SBOM_SMALL_FILE_MAX_BYTES", "1")
    monkeypatch.setenv("SBOM_WORKSPACE_STORAGE_DIR", str(tmp_path))
    approved = []
    for _ in range(2):
        session = upload_invalid(client)
        job = run_job(client, session)
        result = client.post(base(session) + f"/{job['repair_job_id']}/approve").json()
        approved.append((session, job, result["imported_sbom_id"]))
    deleted, kept = approved
    with SessionLocal() as db:
        workspace = db.get(SBOMValidationSession, deleted[0])
        paths = [Path(p) for p in (workspace.raw_storage_path, workspace.repair_storage_path) if p]
        assert len(paths) == 2
        original_files = {p: p.read_bytes() for p in paths}
        service = SBOMDeleteService(db, tenant_id=1)
        service.permanently_delete_sbom(deleted[2], "release-test", True)
        assert db.get(SBOMRepairJob, deleted[1]["repair_job_id"]) is None
        assert db.get(SBOMValidationSession, deleted[0]) is None
        assert db.get(SBOMRepairJob, kept[1]["repair_job_id"]) is not None
        assert db.get(SBOMSource, kept[2]) is not None
        assert original_files == {p: p.read_bytes() for p in paths}
    assert client.get(f"/api/sbom-validation-sessions/{kept[0]}/download-original").status_code == 200

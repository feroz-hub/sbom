"""Phase 2 API/hash/history/role boundaries over the existing PostgreSQL fixtures."""

import hashlib
import json
from concurrent.futures import ThreadPoolExecutor

import pytest
from app.core.context import CurrentContext
from app.core.permissions import ROLE_PERMISSIONS
from app.core.security import get_current_tenant_context
from app.db import SessionLocal
from app.models import SBOMRepairJob, SBOMSource, SBOMValidationSessionEvent
from app.services.sbom.quality.service import EVENT
from sqlalchemy import select

from tests.test_sbom_auto_repair import document, run_job, upload_invalid


def url(session):
    return f"/api/sbom-validation-sessions/{session}/quality"


def test_upload_quality_history_is_immutable_hash_bound_and_deduplicated(client):
    session = upload_invalid(client)
    first = client.get(url(session))
    assert first.status_code == 200, first.text
    result = first.json()
    assert result["assessment"]["validation_status"] == "FAILED"
    assert {e["artifact_role"] for e in result["history"]} == {"ORIGINAL", "DRAFT"}
    assert all(e["artifact_hash"] == e["assessment"]["artifact_hash"] for e in result["history"])
    second = client.get(url(session)).json()
    assert result == second
    with SessionLocal() as db:
        event = db.scalar(select(SBOMValidationSessionEvent).where(SBOMValidationSessionEvent.event_type == EVENT))
        event.metadata_json = {"artifact_hash": "tampered"}
        with pytest.raises(RuntimeError, match="immutable"):
            db.flush()
        db.rollback()


def test_quality_comparison_and_accepted_snapshot_use_actual_candidate(client):
    session = upload_invalid(client)
    original = client.get(url(session)).json()["assessment"]
    job = run_job(client, session)
    quality = job["quality"]
    assert quality["before"]["artifact_hash"] == original["artifact_hash"] == job["source_sha256"]
    assert quality["after"]["artifact_hash"] == job["candidate_sha256"]
    assert quality["improvement"] > 0
    assert quality["after"]["validation_status"] == "PASSED"
    base = f"/api/sbom-validation-sessions/{session}/repair/{job['repair_job_id']}"
    assert client.post(base + "/approve", json={"candidate_sha256": "0" * 64}).status_code == 409
    response = client.post(base + "/approve", json={"candidate_sha256": job["candidate_sha256"]})
    assert response.status_code == 200, response.text
    accepted_id = response.json()["imported_sbom_id"]
    accepted = client.get(f"/api/sboms/{accepted_id}/quality").json()["assessment"]
    assert accepted["artifact_hash"] == job["candidate_sha256"]
    assert accepted["overall_score"] == quality["after"]["overall_score"]
    history = client.get(url(session)).json()["history"]
    assert {"ORIGINAL", "DRAFT", "REPAIR_SOURCE", "CANDIDATE", "ACCEPTED"} <= {e["artifact_role"] for e in history}
    assert next(e for e in history if e["artifact_role"] == "ORIGINAL")["assessment"] == {
        **original,
        "calculated_at": next(e for e in history if e["artifact_role"] == "ORIGINAL")["assessment"]["calculated_at"],
    }
    with SessionLocal() as db:
        stored = db.get(SBOMRepairJob, job["repair_job_id"])
        source = db.get(SBOMSource, accepted_id)
        assert hashlib.sha256(source.sbom_data.encode()).hexdigest() == stored.candidate_sha256


@pytest.mark.parametrize("role", ["TENANT_ADMIN", "SECURITY_ANALYST", "DEVELOPER", "VIEWER"])
def test_quality_read_matches_existing_role_permissions(client, role):
    session = upload_invalid(client)
    context = CurrentContext(
        user_id=1,
        external_user_id="quality-user",
        email=None,
        display_name="Quality",
        tenant_id=1,
        external_tenant_id="default",
        roles=frozenset({role}),
        permissions=ROLE_PERMISSIONS[role],
    )
    client.app.dependency_overrides[get_current_tenant_context] = lambda: context
    try:
        assert client.get(url(session)).status_code == 200
    finally:
        client.app.dependency_overrides.pop(get_current_tenant_context, None)


def test_cross_tenant_and_invalid_ids_do_not_expose_quality(client):
    session = upload_invalid(client)
    context = CurrentContext(
        user_id=2,
        external_user_id="foreign",
        email=None,
        display_name="Foreign",
        tenant_id=2,
        external_tenant_id="foreign",
        roles=frozenset({"TENANT_ADMIN"}),
        permissions=ROLE_PERMISSIONS["TENANT_ADMIN"],
    )
    client.app.dependency_overrides[get_current_tenant_context] = lambda: context
    try:
        response = client.get(url(session))
        assert response.status_code == 404
        assert "overall_score" not in response.text and "artifact_hash" not in response.text
        assert client.get("/api/sboms/987654/quality").status_code == 404
    finally:
        client.app.dependency_overrides.pop(get_current_tenant_context, None)
    assert client.get(url("00000000-0000-4000-8000-000000000000")).status_code == 404


def test_no_quality_read_permission_is_denied(client):
    session = upload_invalid(client)
    context = CurrentContext(
        user_id=1,
        external_user_id="restricted",
        email=None,
        display_name="Restricted",
        tenant_id=1,
        external_tenant_id="default",
        roles=frozenset(),
        permissions=frozenset(),
    )
    client.app.dependency_overrides[get_current_tenant_context] = lambda: context
    try:
        assert client.get(url(session)).status_code == 403
    finally:
        client.app.dependency_overrides.pop(get_current_tenant_context, None)


def test_concurrent_quality_reads_reuse_snapshot(client):
    session = upload_invalid(client)
    with ThreadPoolExecutor(max_workers=2) as pool:
        results = list(pool.map(lambda _: client.get(url(session)), range(2)))
    assert [r.status_code for r in results] == [200, 200]
    assert results[0].json()["assessment"] == results[1].json()["assessment"]
    history = client.get(url(session)).json()["history"]
    assert len([e for e in history if e["artifact_role"] == "DRAFT"]) == 1


def test_rollback_restores_previous_quality(client):
    source = document()
    source["dependencies"] = [{"ref": "b", "dependsOn": ["pkg:npm/beta@2.0"]}]
    result = client.post("/api/sboms", json={"sbom_name": "quality-rollback", "sbom_data": json.dumps(source)})
    assert result.status_code == 422
    session = result.json()["detail"]["session_id"]
    job = run_job(client, session)
    assert job["rollback"] and job["status"] == "REPAIR_FAILED"
    assert job["quality"]["before"]["artifact_hash"] == job["quality"]["after"]["artifact_hash"]
    assert job["quality"]["improvement"] == 0


def test_partial_candidate_keeps_failed_validation_and_manual_findings(client):
    source = document()
    source["components"][0]["licenses"] = [{"license": {"id": "NOT-SPDX"}}]
    session = upload_invalid(client, source)
    job = run_job(client, session)
    assert job["status"] == "PARTIALLY_REPAIRED"
    assert job["quality"]["after"]["validation_status"] == "FAILED"
    assert any(
        f["code"] == "QUALITY_LICENSES_INVALID" and not f["repairable"] for f in job["quality"]["after"]["findings"]
    )
    assert (
        client.post(f"/api/sbom-validation-sessions/{session}/repair/{job['repair_job_id']}/approve").status_code == 409
    )


def test_quality_config_change_appends_history_instead_of_overwriting(client, monkeypatch):
    from app.settings import get_settings

    session = upload_invalid(client)
    previous = client.get(url(session)).json()
    settings = get_settings()
    changed = dict(settings.sbom_quality_weights)
    changed["QD-01"] += 5
    changed["QD-04"] -= 5
    monkeypatch.setattr(settings, "sbom_quality_weights", changed)
    current = client.get(url(session)).json()
    assert current["assessment"]["configuration_hash"] != previous["assessment"]["configuration_hash"]
    assert current["history"][: len(previous["history"])] == previous["history"]
    assert len(current["history"]) == len(previous["history"]) + 1


def test_repair_setting_change_retains_history_and_refreshes_finding_availability(client, monkeypatch):
    from app.settings import get_settings

    settings = get_settings()
    monkeypatch.setattr(settings, "sbom_auto_repair_enabled", True)
    session = upload_invalid(client)
    previous = client.get(url(session)).json()
    assert any(f["repairable"] for f in previous["assessment"]["findings"])
    monkeypatch.setattr(settings, "sbom_auto_repair_enabled", False)
    current = client.get(url(session)).json()
    assert current["assessment"]["artifact_hash"] == previous["assessment"]["artifact_hash"]
    assert current["assessment"]["overall_score"] == previous["assessment"]["overall_score"]
    assert current["assessment"]["configuration_hash"] != previous["assessment"]["configuration_hash"]
    assert not any(f["repairable"] for f in current["assessment"]["findings"])
    assert current["history"][:len(previous["history"])] == previous["history"]
    assert len(current["history"]) == len(previous["history"]) + 1
    monkeypatch.setattr(settings, "sbom_auto_repair_enabled", True)
    restored = client.get(url(session)).json()
    assert restored["assessment"] == previous["assessment"]
    assert restored["history"] == current["history"]


def test_quality_disabled_preserves_upload_and_does_not_create_quality_events(client, monkeypatch):
    from app.settings import get_settings

    monkeypatch.setattr(get_settings(), "sbom_quality_enabled", False)
    session = upload_invalid(client)
    assert client.get(url(session)).json() == {"enabled": False, "assessment": None, "history": []}
    job = run_job(client, session)
    assert job["validation_status"] == "PASSED" and "quality" not in job
    with SessionLocal() as db:
        assert (
            db.scalar(select(SBOMValidationSessionEvent.id).where(SBOMValidationSessionEvent.event_type == EVENT))
            is None
        )


def test_quality_logs_contain_summary_correlation_without_sbom_payload(client, caplog):
    import logging

    caplog.set_level(logging.INFO)
    session = upload_invalid(client)
    client.get(url(session), headers={"X-Request-ID": "quality-request"})
    client.post(f"/api/sbom-validation-sessions/{session}/repair", headers={"X-Request-ID": "quality-run"})
    records = [r for r in caplog.records if getattr(r, "event", "").startswith("SBOM_QUALITY_")]
    assert {"SBOM_QUALITY_CALCULATED", "SBOM_QUALITY_RECALCULATED", "SBOM_QUALITY_IMPROVED"} <= {
        r.event for r in records
    }
    for record in records:
        assert record.tenant_id == 1 and record.user_id == 1 and record.request_id
        assert record.session_id == session
        assert record.engine_version == "2.0.0"
        assert "components" not in record.getMessage() and "pkg:npm" not in record.getMessage()


def test_snapshot_cannot_bind_another_artifact_assessment(client):
    from app.models import SBOMValidationSession
    from app.services.sbom.quality.service import persist_snapshot
    from fastapi import HTTPException

    session = upload_invalid(client)
    existing = client.get(url(session)).json()["assessment"]
    with SessionLocal() as db:
        workspace = db.get(SBOMValidationSession, session)
        with pytest.raises(HTTPException) as exc:
            persist_snapshot(db, workspace, b"{}", assessment=existing)
        assert exc.value.status_code == 409


def test_retained_policy_can_reproduce_historical_grade_after_configuration_change(client, monkeypatch):
    from app.core.sbom_quality_policy import QualityPolicy
    from app.settings import get_settings

    session = upload_invalid(client)
    previous = client.get(url(session)).json()
    original = previous['assessment']
    retained = QualityPolicy.model_validate(original['configuration'])
    assert retained.fingerprint() == original['configuration_hash']
    assert retained.grade(original['overall_score']) == original['grade']
    monkeypatch.setattr(get_settings(), 'sbom_quality_thresholds',
                        {'EXCELLENT': 99, 'GOOD': 95, 'FAIR': 90, 'POOR': 85, 'CRITICAL_QUALITY': 0})
    current = client.get(url(session)).json()
    assert current['assessment']['configuration_hash'] != original['configuration_hash']
    assert current['history'][:len(previous['history'])] == previous['history']
    assert retained.grade(original['overall_score']) == original['grade']


def test_snapshot_rejects_policy_evidence_that_does_not_match_hash(client):
    import copy

    from app.models import SBOMValidationSession
    from app.services.sbom.quality.service import persist_snapshot
    from app.services.validation_repair_service import session_repair_text
    from fastapi import HTTPException

    session = upload_invalid(client)
    existing = copy.deepcopy(client.get(url(session)).json()['assessment'])
    existing['configuration']['max_findings'] += 1
    with SessionLocal() as db:
        workspace = db.get(SBOMValidationSession, session)
        with pytest.raises(HTTPException) as exc:
            persist_snapshot(db, workspace, session_repair_text(workspace).encode(), assessment=existing)
        assert exc.value.status_code == 409


def test_candidate_creation_and_quality_read_are_serialized_and_hash_bound(client):
    session = upload_invalid(client)
    with ThreadPoolExecutor(max_workers=2) as pool:
        pending_quality = pool.submit(client.get, url(session))
        pending_job = pool.submit(run_job, client, session)
        assessment = pending_quality.result().json()['assessment']
        job = pending_job.result()
    assert assessment['artifact_hash'] == job['source_sha256']
    assert job['quality']['after']['artifact_hash'] == job['candidate_sha256']


def test_approval_and_quality_refresh_do_not_rebind_candidate_or_source(client):
    session = upload_invalid(client)
    job = run_job(client, session)
    with ThreadPoolExecutor(max_workers=2) as pool:
        pending_quality = pool.submit(client.get, url(session))
        pending_approval = pool.submit(client.post,
            f"/api/sbom-validation-sessions/{session}/repair/{job['repair_job_id']}/approve",
            json={'candidate_sha256': job['candidate_sha256']})
        quality = pending_quality.result()
        approved = pending_approval.result()
    assert quality.status_code == approved.status_code == 200
    assert quality.json()['assessment']['artifact_hash'] == job['source_sha256']
    accepted = client.get(f"/api/sboms/{approved.json()['imported_sbom_id']}/quality")
    assert accepted.json()['assessment']['artifact_hash'] == job['candidate_sha256']


def test_deletion_cascades_quality_history_and_denies_deleted_quality_without_touching_other_session(client):
    from app.models import SBOMValidationSession
    from app.services.sbom_delete_service import SBOMDeleteService

    deleted = upload_invalid(client)
    retained = upload_invalid(client)
    client.get(url(deleted))
    client.get(url(retained))
    job = run_job(client, deleted)
    approved = client.post(f"/api/sbom-validation-sessions/{deleted}/repair/{job['repair_job_id']}/approve").json()
    sbom_id = approved['imported_sbom_id']
    with SessionLocal() as db:
        SBOMDeleteService(db, tenant_id=1).permanently_delete_sbom(sbom_id, 'phase2-release', True)
        assert db.get(SBOMValidationSession, deleted) is None
        assert db.scalar(select(SBOMValidationSessionEvent.id).where(
            SBOMValidationSessionEvent.session_id == deleted)) is None
        assert db.scalar(select(SBOMValidationSessionEvent.id).where(
            SBOMValidationSessionEvent.session_id == retained, SBOMValidationSessionEvent.event_type == EVENT))
    assert client.get(url(deleted)).status_code == 404
    assert client.get(f'/api/sboms/{sbom_id}/quality').status_code == 404
    assert client.get(url(retained)).status_code == 200


def test_corrupted_candidate_cannot_be_presented_with_stale_quality_or_approved(client):
    from sqlalchemy import text

    session = upload_invalid(client)
    job = run_job(client, session)
    endpoint = f"/api/sbom-validation-sessions/{session}/repair/{job['repair_job_id']}"
    with SessionLocal() as db:
        candidate = db.get(SBOMRepairJob, job['repair_job_id']).candidate_content
        # Simulate storage corruption below the normal immutable ORM/API boundary.
        db.execute(text('UPDATE sbom_repair_jobs SET candidate_content=:value WHERE id=:id'),
                   {'value': candidate + ' ', 'id': job['repair_job_id']})
        db.commit()
    response = client.get(endpoint)
    assert response.status_code == 409
    assert 'overall_score' not in response.text
    assert client.post(endpoint + '/approve', json={'candidate_sha256': job['candidate_sha256']}).status_code == 409
    with SessionLocal() as db:
        db.execute(text('UPDATE sbom_repair_jobs SET candidate_content=:value WHERE id=:id'),
                   {'value': candidate, 'id': job['repair_job_id']})
        db.commit()
    assert client.get(endpoint).status_code == 200
    assert client.post(endpoint + '/approve', json={'candidate_sha256': job['candidate_sha256']}).status_code == 200

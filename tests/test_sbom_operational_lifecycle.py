"""Operational lifecycle contracts: historical preservation and current-state fences."""
from datetime import UTC, datetime, timedelta

import pytest
from app.core.context import CurrentContext, tenant_scope
from app.core.permissions import ROLE_PERMISSIONS
from app.core.security import get_current_tenant_context
from app.db import SessionLocal
from app.models import (
    AnalysisFinding,
    AnalysisRun,
    AnalysisSchedule,
    AuditLog,
    CveCache,
    IAMUser,
    SBOMComponent,
)
from app.services import sbom_lifecycle as lifecycle
from app.services.analysis_orchestrator import AnalysisOrchestrator
from app.services.analysis_service import persist_analysis_run
from app.services.dashboard_scope import DashboardScope, dashboard_scope
from fastapi import HTTPException
from sqlalchemy import func, select, text

from tests.component_advisor_support import NOW, World


@pytest.fixture
def db(client):
    session = SessionLocal()
    yield session
    session.rollback()
    session.close()


@pytest.fixture
def admin(db, client):
    user = db.scalar(select(IAMUser).order_by(IAMUser.id))
    context = CurrentContext(user_id=user.id, external_user_id="lifecycle-admin", email=None, display_name="Admin",
                             tenant_id=1, external_tenant_id="1", roles=frozenset({"TENANT_ADMIN"}),
                             permissions=ROLE_PERMISSIONS["TENANT_ADMIN"])
    client.app.dependency_overrides[get_current_tenant_context] = lambda: context
    yield context
    client.app.dependency_overrides.pop(get_current_tenant_context, None)


@pytest.fixture(autouse=True)
def revoke(monkeypatch):
    from app.workers.celery_app import celery_app
    calls = []
    monkeypatch.setattr(celery_app.control, "revoke", lambda *args, **kwargs: calls.append((args, kwargs)))
    return calls


@pytest.fixture
def world(db, admin):
    builder = World(db)
    sbom = builder.sbom(builder.product(name="lifecycle"))
    sbom.sbom_data = '{"bomFormat":"CycloneDX","specVersion":"1.5","version":1,"components":[]}'
    component = builder.component(sbom, "library", "1.0")
    builder.finding(component, "CVE-2026-1000", "HIGH")
    db.commit()
    return builder, sbom, component


def change(client, sbom, status, reason="Administrator lifecycle decision"):
    return client.post(f"/api/sboms/{sbom.id}/lifecycle", json={"status": status, "reason": reason})


def test_transition_preserves_history_and_writes_atomic_audit(client, db, admin, world, revoke):
    _, sbom, component = world
    contents = sbom.sbom_data
    response = change(client, sbom, "INACTIVE", "  Retirement after product release  ")
    assert response.status_code == 200, response.text
    assert response.json()["lifecycle_status"] == "INACTIVE"
    assert response.json()["processing_eligibility"]["reason_code"] == "SBOM_INACTIVE"
    db.refresh(sbom)
    assert sbom.is_active and sbom.sbom_data == contents
    assert db.get(SBOMComponent, component.id) is not None
    assert db.scalar(select(func.count()).select_from(AnalysisFinding)) == 1
    assert db.get(AnalysisRun, sbom.run.id) is not None
    audit = db.scalar(select(AuditLog).where(AuditLog.action == "sbom.deactivate"))
    assert audit.tenant_id == 1 and audit.user_ref_id == admin.user_id
    assert audit.old_value == {"lifecycle_status": "ACTIVE"}
    assert audit.new_value == {"lifecycle_status": "INACTIVE"}
    assert audit.metadata_json["reason"] == "Retirement after product release"
    assert audit.metadata_json["sbom_id"] == sbom.id and audit.created_at
    assert revoke == [((lifecycle.analysis_task_id(1, sbom.id, 0),), {"terminate": False})]
    assert client.get(f"/api/sboms/{sbom.id}").status_code == 200
    history = client.get(f"/api/sboms/{sbom.id}/lifecycle-history").json()
    assert history[0]["old_status"] == "ACTIVE" and history[0]["new_status"] == "INACTIVE"
    assert history[0]["actor_id"] == admin.user_id
    assert change(client, sbom, "ACTIVE", "Product restored").status_code == 200
    history = client.get(f"/api/sboms/{sbom.id}/lifecycle-history").json()
    assert len(history) == 2 and history[0]["reason"] == "Product restored"


@pytest.mark.parametrize("payload", [{"status": "INACTIVE"}, {"status": "INACTIVE", "reason": "  "},
                                     {"status": "UNKNOWN", "reason": "why"},
                                     {"status": "INACTIVE", "reason": "why", "tenant_id": 2}])
def test_invalid_transition_payload_rejected(client, db, world, payload):
    _, sbom, _ = world
    assert client.post(f"/api/sboms/{sbom.id}/lifecycle", json=payload).status_code == 422
    db.refresh(sbom)
    assert sbom.lifecycle_status == "ACTIVE"
    assert db.scalar(select(func.count()).select_from(AuditLog).where(AuditLog.action == "sbom.deactivate")) == 0


def test_same_state_conflict(client, world):
    _, sbom, _ = world
    assert change(client, sbom, "ACTIVE").status_code == 409


@pytest.mark.parametrize("role", ["VIEWER", "SECURITY_ANALYST", "DEVELOPER"])
def test_only_administrator_can_change_lifecycle(client, admin, world, role):
    _, sbom, _ = world
    from dataclasses import replace
    context = replace(admin, roles=frozenset({role}), permissions=ROLE_PERMISSIONS[role])
    client.app.dependency_overrides[get_current_tenant_context] = lambda: context
    assert change(client, sbom, "INACTIVE").status_code == 403
    assert client.get(f"/api/sboms/{sbom.id}/lifecycle-history").status_code == 200


def test_cross_tenant_transition_and_history_denied(client, db, world):
    builder, _, _ = world
    db.execute(text("INSERT INTO tenants (id,name,slug,external_iam_tenant_id,status,created_at,updated_at) VALUES (2,'Other','other','other','ACTIVE',:now,:now)"), {"now": NOW})
    other = builder.sbom(builder.product(tenant_id=2, name="other"))
    db.commit()
    assert change(client, other, "INACTIVE").status_code == 404
    assert client.get(f"/api/sboms/{other.id}/lifecycle-history").status_code == 404
    db.refresh(other)
    assert other.lifecycle_status == "ACTIVE"


def test_audit_failure_rolls_back_status(client, db, admin, world, monkeypatch):
    _, sbom, _ = world
    def failed(*args, **kwargs):
        raise RuntimeError("audit unavailable")
    monkeypatch.setattr(lifecycle, "write_audit_log", failed)
    with tenant_scope(admin), pytest.raises(RuntimeError, match="audit unavailable"):
        lifecycle.transition_lifecycle(db, admin, sbom.id, "INACTIVE", "reason")
    db.refresh(sbom)
    assert sbom.lifecycle_status == "ACTIVE" and sbom.lifecycle_revision == 0


@pytest.mark.parametrize("suffix", ["/analyze", "/analyze/stream"])
def test_inactive_direct_analysis_api_rejected(client, world, suffix):
    _, sbom, _ = world
    assert change(client, sbom, "INACTIVE").status_code == 200
    response = client.post(f"/api/sboms/{sbom.id}{suffix}", json={} if suffix.endswith("stream") else None)
    assert response.status_code == 409, response.text
    assert "SBOM_INACTIVE" in response.text


def test_inactive_comparison_rejected_before_cache(client, db, world):
    builder, sbom, _ = world
    other = builder.sbom(builder.product(name="second"))
    db.commit()
    assert change(client, sbom, "INACTIVE").status_code == 200
    responses = [client.post("/api/v1/compare", json={"run_a_id": sbom.run.id, "run_b_id": other.run.id}),
                 client.get("/api/analysis-runs/compare", params={"run_a": sbom.run.id, "run_b": other.run.id}),
                 client.get("/api/sboms/compare-versions", params={"version_a": sbom.id, "version_b": other.id})]
    for response in responses:
        assert response.status_code == 409, response.text
        assert "SBOM_INACTIVE" in response.text


@pytest.mark.parametrize("route", ["pdf", "csv", "pack"])
def test_inactive_new_report_rejected(client, world, route):
    _, sbom, _ = world
    assert change(client, sbom, "INACTIVE").status_code == 200
    response = client.post("/api/pdf-report", json={"runId": sbom.run.id}) if route == "pdf" else client.get(
        f"/api/sboms/{sbom.id}/" + ("lifecycle/report?format=csv" if route == "csv" else "reports/lifecycle-pack"))
    assert response.status_code == 409, response.text
    assert "SBOM_INACTIVE" in response.text


@pytest.mark.parametrize("status,errors,code", [("quarantined",0,"SBOM_UNSAFE"), ("pending",0,"SBOM_VALIDATION_PENDING"),
                                                 ("validated",1,"SBOM_VALIDATION_BLOCKED"), ("invalid",0,"SBOM_VALIDATION_BLOCKED")])
def test_centralized_validation_eligibility(client, db, world, status, errors, code):
    _, sbom, _ = world
    sbom.status, sbom.error_count = status, errors
    db.commit()
    response = client.post(f"/api/sboms/{sbom.id}/analyze")
    assert response.status_code == 409 and code in response.text
    assert lifecycle.processing_eligibility(sbom)["reason_code"] == code


def seed_fresh_fingerprint(db, sbom):
    now = datetime.now(UTC)
    db.add(CveCache(cve_id="CVE-2026-1000", payload={}, sources_used="NVD", fetched_at=now.isoformat(), expires_at=(now+timedelta(days=1)).isoformat()))
    db.flush()
    sbom.run.analysis_input_fingerprint = lifecycle.analysis_fingerprint(db, sbom)
    db.commit()


def totals(db):
    from app.metrics.findings import findings_latest_per_sbom_total
    from app.metrics.runs import runs_total_lifetime
    with dashboard_scope(db, DashboardScope(tenant_id=1)):
        return findings_latest_per_sbom_total(db), runs_total_lifetime(db), db.scalar(select(func.count()).select_from(SBOMComponent))


def test_dashboard_exclusion_reactivation_and_cache_revision(client, db, world):
    builder, sbom, component = world
    other = builder.sbom(builder.product(name="active-other"))
    c = builder.component(other, "other-library", "2.0")
    for number in range(99):
        builder.finding(component, f"CVE-2026-{2000+number}", "HIGH")
    for number in range(40):
        builder.finding(c, f"CVE-2026-{4000+number}", "MEDIUM")
    db.commit()
    seed_fresh_fingerprint(db, sbom)
    from app.metrics.cache import invalidation_key
    before_key = invalidation_key(db)
    assert totals(db) == (140, 2, 2)
    assert change(client, sbom, "INACTIVE").status_code == 200
    assert totals(db) == (40, 1, 1)
    assert db.scalar(select(func.count()).select_from(AnalysisFinding)) == 140
    assert change(client, sbom, "ACTIVE").status_code == 200
    assert totals(db) == (140, 2, 2)
    assert invalidation_key(db) != before_key
    db.refresh(sbom)
    assert not sbom.analysis_requires_reanalysis


@pytest.mark.parametrize("changed", ["checksum", "validation", "vulnerability", "missing"])
def test_stale_previous_analysis_not_trusted(client, db, world, changed):
    _, sbom, _ = world
    if changed != "missing":
        seed_fresh_fingerprint(db, sbom)
    assert change(client, sbom, "INACTIVE").status_code == 200
    db.refresh(sbom)
    if changed == "checksum":
        sbom.sbom_data += " "
    elif changed == "validation":
        sbom.validated_at = datetime.now(UTC).isoformat()
    elif changed == "vulnerability":
        db.get(CveCache, "CVE-2026-1000").expires_at = (datetime.now(UTC)-timedelta(days=1)).isoformat()
    db.commit()
    response = change(client, sbom, "ACTIVE")
    assert response.status_code == 200 and response.json()["analysis_requires_reanalysis"]
    db.refresh(sbom)
    db.refresh(sbom.run)
    assert not sbom.run.is_current
    assert totals(db)[0:2] == (0, 0)
    assert lifecycle.processing_eligibility(sbom)["eligible"]
    with pytest.raises(HTTPException) as error:
        lifecycle.require_processing(sbom, operation="Report generation")
    assert error.value.status_code == 409


def test_queued_jobs_cancel_and_running_results_obsolete_after_reactivation(client, db, admin, world):
    builder, sbom, _ = world
    queued = builder.run(sbom, "PENDING")
    running = builder.run(sbom, "RUNNING")
    running.analysis_input_fingerprint = {**lifecycle.analysis_fingerprint(db, sbom), "lifecycle_revision": 0}
    db.commit()
    assert change(client, sbom, "INACTIVE").status_code == 200
    db.refresh(queued)
    db.refresh(running)
    assert queued.run_status == "CANCELLED" and not queued.is_current
    assert running.run_status == "RUNNING" and not running.is_current
    assert change(client, sbom, "ACTIVE").status_code == 200
    with tenant_scope(admin):
        assert AnalysisOrchestrator(db).active_run(sbom.id) is None
        result = persist_analysis_run(db, sbom, {"findings": [], "total_findings": 0}, [], "OK", "NVD", NOW, NOW, 1, existing_run=running)
    assert not result.is_current
    db.refresh(sbom)
    assert sbom.analysis_requires_reanalysis
    assert totals(db)[0:2] == (0, 0)
    with tenant_scope(admin), pytest.raises(HTTPException):
        AnalysisOrchestrator(db).mark_running(queued, sources=["NVD"])


def test_scheduled_inactive_and_old_generation_jobs_skipped(client, db, world):
    from app.services.schedule_resolver import _eligible_sboms
    from app.workers.scheduled_analysis import analyze_sbom_async
    _, sbom, _ = world
    schedule = AnalysisSchedule(tenant_id=1, scope="SBOM", cadence="DAILY", sbom_id=sbom.id)
    db.add(schedule)
    db.commit()
    assert sbom.id in [item.id for item in _eligible_sboms(db)]
    assert change(client, sbom, "INACTIVE").status_code == 200
    db.expire_all()
    assert sbom.id not in [item.id for item in _eligible_sboms(db)]
    result = analyze_sbom_async.run(sbom_id=sbom.id, schedule_id=schedule.id, lifecycle_revision=0)
    assert result == {"status": "SKIPPED", "reason": "SBOM_INACTIVE"}
    assert change(client, sbom, "ACTIVE").status_code == 200
    for generation in (0, None):
        result = analyze_sbom_async.run(sbom_id=sbom.id, schedule_id=schedule.id, lifecycle_revision=generation)
        assert result == {"status": "SKIPPED", "reason": "SBOM_LIFECYCLE_OBSOLETE"}

@pytest.mark.parametrize("endpoint", ["/analyze-sbom-nvd", "/analyze-sbom-github", "/analyze-sbom-osv", "/analyze-sbom-vulndb", "/analyze-sbom-consolidated"])
def test_legacy_direct_api_cannot_bypass_inactive_guard(client, world, endpoint):
    _, sbom, _ = world
    assert change(client, sbom, "INACTIVE").status_code == 200
    response = client.post(endpoint, json={"sbom_id": sbom.id})
    assert response.status_code == 409, response.text
    assert "SBOM_INACTIVE" in response.text


def test_scheduler_tick_and_run_now_do_not_enqueue_inactive(client, db, world, monkeypatch):
    from app.workers.scheduled_analysis import analyze_sbom_async, tick_scheduled_analyses
    _, sbom, _ = world
    schedule = AnalysisSchedule(tenant_id=1, scope="SBOM", cadence="DAILY", sbom_id=sbom.id,
                                next_run_at=(datetime.now(UTC)-timedelta(minutes=10)).isoformat())
    db.add(schedule)
    db.commit()
    queued = []
    monkeypatch.setattr(analyze_sbom_async, "apply_async", lambda **kwargs: queued.append(kwargs))
    assert change(client, sbom, "INACTIVE").status_code == 200
    result = tick_scheduled_analyses.run()
    assert result["enqueued"] == 0 and not queued
    response = client.post(f"/api/schedules/{schedule.id}/run-now")
    assert response.status_code == 409 and "SBOM_INACTIVE" in response.text
    assert not queued


def test_new_successful_analysis_restores_freshness_without_reviving_obsolete_runs(client, db, admin, world):
    _, sbom, _ = world
    assert change(client, sbom, "INACTIVE").status_code == 200
    assert change(client, sbom, "ACTIVE").status_code == 200
    db.refresh(sbom)
    with tenant_scope(admin):
        service = AnalysisOrchestrator(db)
        pending = service.create_pending_run(sbom, sources=["NVD"], trigger_source="manual", started_on=NOW)
        result = persist_analysis_run(db, sbom, {"findings": [], "total_findings": 0}, [], "OK", "NVD", NOW, NOW, 1, existing_run=pending)
    db.refresh(sbom)
    db.refresh(sbom.run)
    assert result.is_current and not sbom.analysis_requires_reanalysis
    assert not sbom.run.is_current
    assert lifecycle.processing_eligibility(sbom)["eligible"]
    assert totals(db)[0:2] == (0, 1)


def test_inactive_excel_report_service_rejects(client, db, world):
    from app.services.sbom_vulnerability_excel_report_service import SbomVulnerabilityExcelReportService
    _, sbom, _ = world
    assert change(client, sbom, "INACTIVE").status_code == 200
    db.refresh(sbom)
    with pytest.raises(HTTPException) as error:
        SbomVulnerabilityExcelReportService(db).generate(sbom)
    assert error.value.status_code == 409 and error.value.detail["code"] == "SBOM_INACTIVE"


def test_operational_lifecycle_migration_preserves_existing_defaults_and_downgrades():
    import importlib.util
    from pathlib import Path

    from alembic.migration import MigrationContext
    from alembic.operations import Operations
    from app.db import NAMING_CONVENTION
    from sqlalchemy import Column, Integer, MetaData, Table, create_engine, inspect
    spec = importlib.util.spec_from_file_location("operational_lifecycle_migration", Path("alembic/versions/073_sbom_operational_lifecycle.py"))
    migration = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(migration)
    engine = create_engine("sqlite:///:memory:")
    metadata = MetaData(naming_convention=NAMING_CONVENTION)
    Table("sbom_source", metadata, Column("id", Integer, primary_key=True))
    Table("analysis_run", metadata, Column("id", Integer, primary_key=True))
    metadata.create_all(engine)
    with engine.begin() as connection:
        connection.execute(text("INSERT INTO sbom_source(id) VALUES (1)"))
        connection.execute(text("INSERT INTO analysis_run(id) VALUES (1)"))
        with Operations.context(MigrationContext.configure(connection, opts={"target_metadata": metadata})):
            migration.upgrade()
            assert connection.execute(text("SELECT lifecycle_status,lifecycle_revision,analysis_requires_reanalysis FROM sbom_source")).one() == ("ACTIVE", 0, 0)
            assert connection.execute(text("SELECT is_current FROM analysis_run")).scalar() == 1
            migration.downgrade()
        assert [column["name"] for column in inspect(connection).get_columns("sbom_source")] == ["id"]
        assert connection.execute(text("SELECT id FROM sbom_source")).scalar() == 1
    engine.dispose()

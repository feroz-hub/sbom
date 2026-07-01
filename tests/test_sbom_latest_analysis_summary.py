from __future__ import annotations

import json
from datetime import UTC, datetime, timedelta
from uuid import uuid4

import pytest
from app.core.context import minimal_background_context, tenant_scope
from app.models import AnalysisFinding, AnalysisRun, SBOMSource, Tenant


def _now(offset_seconds: int = 0) -> str:
    return (datetime.now(UTC) + timedelta(seconds=offset_seconds)).isoformat()


@pytest.fixture()
def db(client):
    from app.db import SessionLocal

    session = SessionLocal()
    try:
        yield session
    finally:
        session.rollback()
        session.close()


def _seed_sbom(db, *, name: str, tenant_id: int = 1, created_by: str | None = None) -> SBOMSource:
    sbom = SBOMSource(
        sbom_name=name,
        sbom_data="{}",
        status="validated",
        tenant_id=tenant_id,
        created_by=created_by,
        created_on=_now(),
    )
    db.add(sbom)
    db.flush()
    return sbom


def _seed_run(
    db,
    *,
    sbom: SBOMSource,
    status: str,
    total_findings: int = 0,
    critical: int = 0,
    high: int = 0,
    medium: int = 0,
    low: int = 0,
    raw_report: dict | None = None,
    offset_seconds: int = 0,
) -> AnalysisRun:
    run = AnalysisRun(
        sbom_id=sbom.id,
        project_id=sbom.projectid,
        tenant_id=sbom.tenant_id,
        run_status=status,
        source="test",
        started_on=_now(offset_seconds),
        completed_on=_now(offset_seconds + 1),
        total_findings=total_findings,
        critical_count=critical,
        high_count=high,
        medium_count=medium,
        low_count=low,
        raw_report=json.dumps(raw_report or {}),
    )
    db.add(run)
    db.flush()
    return run


def _seed_finding(db, *, run: AnalysisRun, severity: str = "HIGH", score: float = 7.5) -> None:
    db.add(
        AnalysisFinding(
            analysis_run_id=run.id,
            tenant_id=run.tenant_id,
            vuln_id=f"CVE-2026-{uuid4().hex[:4]}",
            severity=severity,
            score=score,
            component_name="demo",
            component_version="1.0.0",
        )
    )


def _listed_sbom(client, *, created_by: str, sbom_id: int) -> dict:
    resp = client.get(f"/api/sboms?user_id={created_by}&page_size=500")
    assert resp.status_code == 200, resp.text
    matches = [row for row in resp.json() if row["id"] == sbom_id]
    assert matches, resp.json()
    return matches[0]


def test_sbom_with_no_analysis_shows_no_latest_analysis(client, db):
    created_by = f"latest-none-{uuid4().hex}"
    sbom = _seed_sbom(db, name=f"sbom-{created_by}", created_by=created_by)
    db.commit()

    row = _listed_sbom(client, created_by=created_by, sbom_id=sbom.id)

    assert row["latest_analysis"] is None


@pytest.mark.parametrize(
    ("status", "normalized_status", "result"),
    [
        ("PENDING", "queued", "queued"),
        ("RUNNING", "running", "running"),
        ("FINDINGS", "completed", "findings"),
        ("ERROR", "failed", "failed"),
    ],
)
def test_sbom_list_returns_latest_analysis_state(client, db, status, normalized_status, result):
    created_by = f"latest-{status.lower()}-{uuid4().hex}"
    sbom = _seed_sbom(db, name=f"sbom-{created_by}", created_by=created_by)
    run = _seed_run(
        db,
        sbom=sbom,
        status=status,
        total_findings=3 if status == "FINDINGS" else 0,
        critical=1 if status == "FINDINGS" else 0,
        high=2 if status == "FINDINGS" else 0,
        medium=1 if status == "FINDINGS" else 0,
        low=1 if status == "FINDINGS" else 0,
        raw_report={"error_message": "source failed"} if status == "ERROR" else None,
    )
    if status == "FINDINGS":
        _seed_finding(db, run=run, severity="CRITICAL", score=9.5)
        _seed_finding(db, run=run, severity="HIGH", score=7.0)
    db.commit()

    row = _listed_sbom(client, created_by=created_by, sbom_id=sbom.id)
    latest = row["latest_analysis"]

    assert latest["run_id"] == run.id
    assert latest["status"] == normalized_status
    assert latest["result"] == result
    if status == "FINDINGS":
        assert latest["finding_count"] == 3
        assert latest["critical_count"] == 1
        assert latest["high_count"] == 2
        assert latest["medium_count"] == 1
        assert latest["low_count"] == 1
        assert latest["risk_score"] == 16.5
        assert latest["risk_level"] == "critical"
    if status == "ERROR":
        assert latest["error_message"] == "source failed"


def test_sbom_list_selects_latest_run_when_multiple_exist(client, db):
    created_by = f"latest-multiple-{uuid4().hex}"
    sbom = _seed_sbom(db, name=f"sbom-{created_by}", created_by=created_by)
    old_run = _seed_run(db, sbom=sbom, status="OK", offset_seconds=-10)
    latest_run = _seed_run(db, sbom=sbom, status="ERROR", raw_report={"query_errors": [{"message": "newer failed"}]})
    db.commit()

    row = _listed_sbom(client, created_by=created_by, sbom_id=sbom.id)

    assert row["latest_analysis"]["run_id"] == latest_run.id
    assert row["latest_analysis"]["run_id"] != old_run.id
    assert row["latest_analysis"]["status"] == "failed"
    assert row["latest_analysis"]["result"] == "failed"
    assert row["latest_analysis"]["error_message"] == "newer failed"


def test_rename_sbom_propagates_name_to_analysis_runs(client, db):
    """PATCH /api/sboms/{id} with a new name updates the denormalized
    analysis_run.sbom_name on every related run, in the same transaction."""
    created_by = f"rename-{uuid4().hex}"
    old_name = f"old-{created_by}"
    sbom = _seed_sbom(db, name=old_name, created_by=created_by)
    run_a = _seed_run(db, sbom=sbom, status="OK")
    run_b = _seed_run(db, sbom=sbom, status="FINDINGS", total_findings=1)
    run_a.sbom_name = old_name
    run_b.sbom_name = old_name
    db.commit()

    new_name = f"new-{created_by}"
    resp = client.patch(f"/api/sboms/{sbom.id}", json={"name": new_name}, params={"user_id": created_by})
    assert resp.status_code == 200, resp.text
    assert resp.json()["sbom_name"] == new_name

    db.expire_all()
    for run in (run_a, run_b):
        assert db.get(AnalysisRun, run.id).sbom_name == new_name


def test_rename_sbom_does_not_touch_runs_when_name_unchanged(client, db):
    """A PATCH that keeps the same name leaves related runs untouched (the
    propagation only fires when the name actually changes)."""
    created_by = f"norename-{uuid4().hex}"
    name = f"stable-{created_by}"
    sbom = _seed_sbom(db, name=name, created_by=created_by)
    run = _seed_run(db, sbom=sbom, status="OK")
    # A run whose denormalized name deliberately differs; a no-op rename (same
    # name) must NOT rewrite it, proving the change-detection guard.
    run.sbom_name = "drifted-name"
    db.commit()

    resp = client.patch(f"/api/sboms/{sbom.id}", json={"name": name}, params={"user_id": created_by})
    assert resp.status_code == 200, resp.text

    db.expire_all()
    assert db.get(AnalysisRun, run.id).sbom_name == "drifted-name"


def test_rename_sbom_only_updates_owning_tenant_runs(client, db):
    """Renaming a tenant-1 SBOM must not alter another tenant's analysis runs."""
    created_by = f"rename-tenant-{uuid4().hex}"
    default_sbom = _seed_sbom(db, name=f"default-{created_by}", created_by=created_by)
    default_run = _seed_run(db, sbom=default_sbom, status="OK")
    default_run.sbom_name = default_sbom.sbom_name

    now = datetime.now(UTC)
    other_tenant = Tenant(
        name=f"Tenant {created_by}",
        slug=f"tenant-{uuid4().hex}",
        external_iam_tenant_id=f"tenant-ext-{uuid4().hex}",
        status="ACTIVE",
        created_at=now,
        updated_at=now,
    )
    db.add(other_tenant)
    db.flush()
    with tenant_scope(minimal_background_context(other_tenant.id, other_tenant.external_iam_tenant_id)):
        other_sbom = _seed_sbom(db, name=f"other-{created_by}", tenant_id=other_tenant.id, created_by=created_by)
        other_run = _seed_run(db, sbom=other_sbom, status="OK")
        other_run.sbom_name = "other-original"
    db.commit()
    other_run_id = other_run.id

    new_name = f"renamed-{created_by}"
    resp = client.patch(f"/api/sboms/{default_sbom.id}", json={"name": new_name}, params={"user_id": created_by})
    assert resp.status_code == 200, resp.text

    db.expire_all()
    assert db.get(AnalysisRun, default_run.id).sbom_name == new_name
    # The other tenant's run is untouched.
    assert db.get(AnalysisRun, other_run_id).sbom_name == "other-original"


def test_sbom_list_latest_analysis_preserves_tenant_isolation(client, db):
    created_by = f"latest-tenant-{uuid4().hex}"
    default_sbom = _seed_sbom(db, name=f"default-{created_by}", created_by=created_by)
    _seed_run(db, sbom=default_sbom, status="OK")

    now = datetime.now(UTC)
    other_tenant = Tenant(
        name=f"Tenant {created_by}",
        slug=f"tenant-{uuid4().hex}",
        external_iam_tenant_id=f"tenant-ext-{uuid4().hex}",
        status="ACTIVE",
        created_at=now,
        updated_at=now,
    )
    db.add(other_tenant)
    db.flush()
    with tenant_scope(minimal_background_context(other_tenant.id, other_tenant.external_iam_tenant_id)):
        other_sbom = _seed_sbom(db, name=f"other-{created_by}", tenant_id=other_tenant.id, created_by=created_by)
        _seed_run(db, sbom=other_sbom, status="ERROR", raw_report={"error_message": "cross tenant"})
    db.commit()

    resp = client.get(f"/api/sboms?user_id={created_by}&page_size=500")
    assert resp.status_code == 200, resp.text
    rows = resp.json()

    assert [row["id"] for row in rows] == [default_sbom.id]
    assert rows[0]["latest_analysis"]["status"] == "completed"

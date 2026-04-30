"""
v1 endpoint patches & deprecation telemetry (ADR-0008 §1).

The v1 endpoint at ``GET /api/analysis-runs/compare`` is preserved for
back-compat during the strangler period. This file pins the patches that
land alongside v2:

  * Deprecation + Sunset headers are present on every response.
  * Counter increments on each call.
  * Pre-existing B7 status guard now fires on RUNNING / ERROR runs.
  * Existing v1 contract shape is preserved (new_findings, resolved_findings,
    common_findings, severity_delta) so external scripts keep working.
"""

from __future__ import annotations

from datetime import UTC, datetime

import pytest


@pytest.fixture
def db(client):
    from app.db import SessionLocal

    s = SessionLocal()
    try:
        yield s
    finally:
        s.rollback()
        s.close()


def _iso(dt: datetime) -> str:
    return dt.replace(microsecond=0).isoformat()


def _seed(db, *, slug: str, status: str = "FINDINGS"):
    from app.models import AnalysisRun, Projects, SBOMSource

    proj = Projects(project_name=f"v1-{slug}", project_status=1, created_on=_iso(datetime.now(UTC)))
    db.add(proj)
    db.flush()
    sbom = SBOMSource(sbom_name=f"v1-sbom-{slug}", projectid=proj.id, created_on=_iso(datetime.now(UTC)))
    db.add(sbom)
    db.flush()
    run = AnalysisRun(
        sbom_id=sbom.id,
        project_id=proj.id,
        run_status=status,
        source="TEST",
        sbom_name=sbom.sbom_name,
        started_on=_iso(datetime.now(UTC)),
        completed_on=_iso(datetime.now(UTC)),
        duration_ms=1,
        total_components=0, components_with_cpe=0, total_findings=0,
        critical_count=0, high_count=0, medium_count=0,
        low_count=0, unknown_count=0, query_error_count=0,
    )
    db.add(run)
    db.commit()
    return run


def test_v1_compare_response_carries_deprecation_headers(client, db):
    run_a = _seed(db, slug="dep-a")
    run_b = _seed(db, slug="dep-b")

    resp = client.get(
        f"/api/analysis-runs/compare?run_a={run_a.id}&run_b={run_b.id}"
    )
    assert resp.status_code == 200
    assert resp.headers.get("Deprecation") == "true"
    assert "Sunset" in resp.headers
    assert resp.headers.get("Link", "").startswith("</api/v1/compare>")


def test_v1_compare_increments_telemetry_counter(client, db):
    from app.routers.analysis import get_compare_v1_call_count

    run_a = _seed(db, slug="cnt-a")
    run_b = _seed(db, slug="cnt-b")

    before = get_compare_v1_call_count()
    client.get(f"/api/analysis-runs/compare?run_a={run_a.id}&run_b={run_b.id}")
    client.get(f"/api/analysis-runs/compare?run_a={run_a.id}&run_b={run_b.id}")
    after = get_compare_v1_call_count()
    assert after - before >= 2


def test_v1_compare_409_on_running_run(client, db):
    run_a = _seed(db, slug="rdy-a")
    run_b = _seed(db, slug="run-b", status="RUNNING")
    resp = client.get(
        f"/api/analysis-runs/compare?run_a={run_a.id}&run_b={run_b.id}"
    )
    assert resp.status_code == 409
    body = resp.json()["detail"]
    assert body["error_code"] == "COMPARE_V1_E002_RUN_NOT_READY"


def test_v1_compare_preserves_legacy_response_shape(client, db):
    run_a = _seed(db, slug="legacy-a")
    run_b = _seed(db, slug="legacy-b")
    resp = client.get(
        f"/api/analysis-runs/compare?run_a={run_a.id}&run_b={run_b.id}"
    )
    assert resp.status_code == 200
    body = resp.json()
    # Legacy contract — DO NOT change without coordinating with external
    # consumers that imported this shape.
    for k in ("run_a", "run_b", "new_findings", "resolved_findings", "common_findings", "severity_delta"):
        assert k in body
    for k in ("critical", "high", "medium", "low"):
        assert k in body["severity_delta"]

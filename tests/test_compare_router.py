"""
Compare v2 router tests (POST /api/v1/compare and export endpoint).

Covers the public HTTP contract: status codes, error envelopes, response
shape, cache-export round trip.
"""

from __future__ import annotations

import json
from datetime import UTC, datetime

import pytest


def _iso(dt: datetime) -> str:
    return dt.replace(microsecond=0).isoformat()


@pytest.fixture
def db(client):
    from app.db import SessionLocal

    s = SessionLocal()
    try:
        yield s
    finally:
        s.rollback()
        s.close()


def _seed(db, *, slug: str, status: str = "FINDINGS"):
    from app.models import AnalysisRun, Projects, SBOMSource

    proj = Projects(
        project_name=f"router-{slug}",
        project_status=1,
        created_on=_iso(datetime.now(UTC)),
    )
    db.add(proj)
    db.flush()
    sbom = SBOMSource(
        sbom_name=f"router-sbom-{slug}", projectid=proj.id,
        created_on=_iso(datetime.now(UTC)),
    )
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
        total_components=0,
        components_with_cpe=0,
        total_findings=0,
        critical_count=0, high_count=0, medium_count=0,
        low_count=0, unknown_count=0, query_error_count=0,
    )
    db.add(run)
    db.commit()
    return proj, sbom, run


def test_post_compare_returns_full_payload(client, db):
    _, _, run_a = _seed(db, slug="ok-a")
    _, _, run_b = _seed(db, slug="ok-b")

    resp = client.post(
        "/api/v1/compare",
        json={"run_a_id": run_a.id, "run_b_id": run_b.id},
    )
    assert resp.status_code == 200, resp.text
    body = resp.json()
    assert body["run_a"]["id"] == run_a.id
    assert body["run_b"]["id"] == run_b.id
    assert "posture" in body
    # Posture has no "risk_score" field — confirms PB-1 is honoured.
    assert "risk_score" not in body["posture"]
    # Three independently-defensible deltas all present.
    for k in (
        "kev_count_a", "kev_count_b", "kev_count_delta",
        "fix_available_pct_a", "fix_available_pct_b", "fix_available_pct_delta",
        "high_critical_count_a", "high_critical_count_b", "high_critical_count_delta",
    ):
        assert k in body["posture"], f"missing posture key: {k}"
    # Cache key is 64-hex.
    assert len(body["cache_key"]) == 64
    int(body["cache_key"], 16)


def test_post_compare_400_on_same_run(client, db):
    _, _, run = _seed(db, slug="same")
    resp = client.post(
        "/api/v1/compare", json={"run_a_id": run.id, "run_b_id": run.id}
    )
    assert resp.status_code == 400
    assert resp.json()["detail"]["error_code"] == "COMPARE_E003_SAME_RUN"


def test_post_compare_404_on_missing_run(client, db):
    _, _, run = _seed(db, slug="missing")
    resp = client.post(
        "/api/v1/compare", json={"run_a_id": run.id, "run_b_id": 999999}
    )
    assert resp.status_code == 404
    assert resp.json()["detail"]["error_code"] == "COMPARE_E001_RUN_NOT_FOUND"


def test_post_compare_409_on_running_run(client, db):
    _, _, run_a = _seed(db, slug="ready")
    _, _, run_b = _seed(db, slug="running", status="RUNNING")
    resp = client.post(
        "/api/v1/compare", json={"run_a_id": run_a.id, "run_b_id": run_b.id}
    )
    assert resp.status_code == 409
    body = resp.json()["detail"]
    assert body["error_code"] == "COMPARE_E002_RUN_NOT_READY"
    assert body["status"] == "RUNNING"
    assert body["retryable"] is True


def test_export_cycle_markdown_csv_json(client, db):
    _, _, run_a = _seed(db, slug="exp-a")
    _, _, run_b = _seed(db, slug="exp-b")
    resp = client.post(
        "/api/v1/compare",
        json={"run_a_id": run_a.id, "run_b_id": run_b.id},
    )
    assert resp.status_code == 200
    cache_key = resp.json()["cache_key"]

    # Markdown
    md = client.post(
        f"/api/v1/compare/{cache_key}/export", json={"format": "markdown"}
    )
    assert md.status_code == 200
    assert md.headers["content-type"].startswith("text/markdown")
    assert b"# Compare:" in md.content

    # CSV
    csvr = client.post(
        f"/api/v1/compare/{cache_key}/export", json={"format": "csv"}
    )
    assert csvr.status_code == 200
    assert csvr.headers["content-type"].startswith("text/csv")
    assert b"section,change_kind,vuln_id" in csvr.content

    # JSON round-trip
    jsr = client.post(
        f"/api/v1/compare/{cache_key}/export", json={"format": "json"}
    )
    assert jsr.status_code == 200
    payload = json.loads(jsr.content)
    assert payload["cache_key"] == cache_key


def test_export_404_on_unknown_cache_key(client):
    bogus = "0" * 64
    resp = client.post(
        f"/api/v1/compare/{bogus}/export", json={"format": "json"}
    )
    assert resp.status_code == 404
    assert resp.json()["detail"]["error_code"] == "COMPARE_E006_CACHE_MISS"


def test_export_400_on_malformed_cache_key(client):
    resp = client.post(
        "/api/v1/compare/not-hex/export", json={"format": "json"}
    )
    assert resp.status_code == 400
    assert resp.json()["detail"]["error_code"] == "COMPARE_E005_BAD_REQUEST"


def test_runs_recent_returns_compact_summaries(client, db):
    _, _, run_a = _seed(db, slug="rec-a")
    _, _, run_b = _seed(db, slug="rec-b")

    resp = client.get("/api/runs/recent?limit=5")
    assert resp.status_code == 200
    items = resp.json()
    # Newest first: most recent seed appears first.
    ids = [item["id"] for item in items[:2]]
    assert run_b.id in ids
    assert run_a.id in ids
    # Summary shape.
    sample = items[0]
    for k in ("id", "sbom_name", "project_name", "run_status", "completed_on"):
        assert k in sample


def test_runs_search_matches_sbom_name(client, db):
    _, _, run_a = _seed(db, slug="search-uniqueXY")
    _seed(db, slug="search-other")

    resp = client.get("/api/runs/search?q=uniqueXY&limit=10")
    assert resp.status_code == 200
    items = resp.json()
    ids = [item["id"] for item in items]
    assert run_a.id in ids

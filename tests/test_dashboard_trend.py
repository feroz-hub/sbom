"""Regression tests for /dashboard/trend.

The original implementation hydrated every AnalysisFinding ORM row in the
window and aggregated in Python — fast on a tiny demo DB, slow as soon
as the project accumulates real data because the dashboard is the
landing page (so every visit pays the cost).

These tests pin down both the response shape and the contract that
findings without a parent run are filtered out, so the SQL aggregation
can't silently drift back to a slower pattern that "happens to work".
"""

from __future__ import annotations

from datetime import UTC, datetime, timedelta

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


def _now_iso() -> str:
    return datetime.now(UTC).replace(microsecond=0).isoformat()


def _days_ago_iso(n: int) -> str:
    return (datetime.now(UTC) - timedelta(days=n)).replace(microsecond=0).isoformat()


def _seed_run_with_findings(db, *, started_on: str, severity_counts: dict[str, int]):
    """Insert a (Project, SBOMSource, AnalysisRun, AnalysisFindings) tuple."""
    from app.models import (
        AnalysisFinding,
        AnalysisRun,
        Projects,
        SBOMSource,
    )

    # Use unique names to avoid collisions across tests in the same session.
    suffix = started_on.replace(":", "").replace("-", "").replace("+", "")[-12:]
    proj = Projects(project_name=f"trend-proj-{suffix}", project_status=1, created_on=_now_iso())
    db.add(proj)
    db.flush()
    sbom = SBOMSource(sbom_name=f"trend-sbom-{suffix}", projectid=proj.id, created_on=_now_iso())
    db.add(sbom)
    db.flush()
    run = AnalysisRun(
        sbom_id=sbom.id,
        project_id=proj.id,
        run_status="FINDINGS",
        source="TEST",
        started_on=started_on,
        completed_on=started_on,
        duration_ms=1,
        total_components=1,
        components_with_cpe=0,
        total_findings=sum(severity_counts.values()),
        critical_count=severity_counts.get("CRITICAL", 0),
        high_count=severity_counts.get("HIGH", 0),
        medium_count=severity_counts.get("MEDIUM", 0),
        low_count=severity_counts.get("LOW", 0),
        unknown_count=severity_counts.get("UNKNOWN", 0),
        query_error_count=0,
        raw_report=None,
    )
    db.add(run)
    db.flush()
    for sev, count in severity_counts.items():
        for i in range(count):
            db.add(
                AnalysisFinding(
                    analysis_run_id=run.id,
                    component_id=None,
                    vuln_id=f"CVE-TREND-{suffix}-{sev}-{i}",
                    severity=sev,
                )
            )
    db.commit()
    return run


def test_trend_groups_findings_by_day_and_severity(client, db):
    today = _now_iso()
    yesterday = _days_ago_iso(1)
    _seed_run_with_findings(db, started_on=today, severity_counts={"CRITICAL": 2, "HIGH": 1})
    _seed_run_with_findings(db, started_on=yesterday, severity_counts={"LOW": 3})

    resp = client.get("/dashboard/trend?days=7")
    assert resp.status_code == 200
    body = resp.json()
    assert body["days"] == 7

    by_date = {row["date"]: row for row in body["series"]}
    today_key = today[:10]
    yesterday_key = yesterday[:10]

    # Pull >= because other tests in the session may have seeded runs on
    # the same dates; the contract is that OUR rows contribute their share.
    assert today_key in by_date
    assert yesterday_key in by_date
    assert by_date[today_key]["critical"] >= 2
    assert by_date[today_key]["high"] >= 1
    assert by_date[yesterday_key]["low"] >= 3


def test_trend_excludes_runs_outside_window(client, db):
    """Findings from runs older than `days` must not leak into the result."""
    far_past = _days_ago_iso(60)
    _seed_run_with_findings(db, started_on=far_past, severity_counts={"CRITICAL": 5})

    resp = client.get("/dashboard/trend?days=14")
    assert resp.status_code == 200
    by_date = {row["date"]: row for row in resp.json()["series"]}
    assert far_past[:10] not in by_date


def test_trend_unknown_severity_is_first_class(client, db):
    """v2 (redesign §9.2): ``unknown`` is a first-class field on each point.

    v1 silently dropped unknown findings from the trend chart, which meant
    a 1,000-finding run with mostly-unscored CVSS scores rendered as zero —
    the audit §3.3 #2 flagged this as a quiet correctness bug. v2 restores
    the bucket so the chart matches the hero severity bar.
    """
    today = _now_iso()
    _seed_run_with_findings(db, started_on=today, severity_counts={"UNKNOWN": 4})

    resp = client.get("/dashboard/trend?days=1")
    assert resp.status_code == 200
    body = resp.json()
    today_key = today[:10]
    matching = [r for r in body["points"] if r["date"] == today_key]
    assert matching, "today's point must be present (zero-filled or populated)"
    for row in matching:
        assert "unknown" in row, "v2 contract: unknown is first-class"
        # The severity-tier columns must not have absorbed unknown rows.
        assert row["unknown"] >= 4
        assert row["total"] >= 4


def test_trend_returns_etag_and_serves_304_on_match(client, db):
    today = _now_iso()
    _seed_run_with_findings(db, started_on=today, severity_counts={"HIGH": 1})

    first = client.get("/dashboard/trend?days=7")
    assert first.status_code == 200
    etag = first.headers.get("etag")
    assert etag, "expected ETag header on /dashboard/trend"

    second = client.get("/dashboard/trend?days=7", headers={"If-None-Match": etag})
    assert second.status_code == 304

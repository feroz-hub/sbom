"""Manager dashboard aggregates — counters, vulnerability-age, period trend.

Covers:
  * sboms_analysed_total / applications_scanned_total + posture exposure.
  * findings_age_distribution — bucket boundaries (pure), the scan-date
    observation window, and the endpoint.
  * findings_trend — granularity, the application filter (used for *exact*
    assertions on an isolated project), and the fix_available / resolved
    overlays.
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


def _iso_days_ago(n: int) -> str:
    return (datetime.now(UTC) - timedelta(days=n)).replace(microsecond=0).isoformat()


def _seed(db, name: str):
    from app.models import Projects, SBOMSource

    proj = Projects(project_name=f"mgr-{name}", project_status=1, created_on=_now_iso())
    db.add(proj)
    db.flush()
    sbom = SBOMSource(sbom_name=f"mgr-sbom-{name}", projectid=proj.id, created_on=_now_iso())
    db.add(sbom)
    db.flush()
    return sbom, proj


def _seed_run(db, *, sbom, project, started: str, findings: list[dict], status: str = "FINDINGS"):
    from app.models import AnalysisFinding, AnalysisRun

    run = AnalysisRun(
        sbom_id=sbom.id,
        project_id=project.id,
        run_status=status,
        source="TEST",
        started_on=started,
        completed_on=started,
        duration_ms=1,
        total_components=1,
        components_with_cpe=0,
        total_findings=len(findings),
        critical_count=sum(1 for f in findings if f.get("severity") == "CRITICAL"),
        high_count=sum(1 for f in findings if f.get("severity") == "HIGH"),
        medium_count=0,
        low_count=0,
        unknown_count=0,
        query_error_count=0,
    )
    db.add(run)
    db.flush()
    for f in findings:
        db.add(
            AnalysisFinding(
                analysis_run_id=run.id,
                vuln_id=f["vuln_id"],
                severity=f.get("severity", "HIGH"),
                published_on=f.get("published_on"),
                fixed_versions=f.get("fixed_versions"),
            )
        )
    db.commit()
    return run


# ── Counters ──────────────────────────────────────────────────────────────


def test_posture_exposes_counter_tiles(client, db):
    from app import metrics

    sbom, proj = _seed(db, "counters")
    _seed_run(db, sbom=sbom, project=proj, started=_iso_days_ago(1),
              findings=[{"vuln_id": "CVE-2021-0001", "severity": "HIGH"}])

    assert metrics.sboms_analysed_total(db) >= 1
    assert metrics.applications_scanned_total(db) >= 1

    body = client.get("/dashboard/posture").json()
    assert "total_sboms_analysed" in body
    assert "total_applications_scanned" in body
    # Analysed SBOMs are a subset of stored SBOMs.
    assert body["total_sboms_analysed"] <= body["total_sboms"]
    assert body["total_sboms_analysed"] >= 1
    assert body["total_applications_scanned"] >= 1


def test_applications_scanned_counts_only_projects_with_a_completed_run(client, db):
    """"Total Applications Scanned" = distinct projects with >=1 SBOM that has
    a COMPLETED run. Uploaded-only projects (and ERROR-only runs) don't count.

    Delta-based (the metric is global + not memoized) so it's robust to the
    shared session-scoped test DB.
    """
    from app import metrics

    baseline = metrics.applications_scanned_total(db)

    # (a) A project whose SBOM is only uploaded (no run) → does NOT count.
    _seed(db, "uploaded-only")
    db.commit()
    assert metrics.applications_scanned_total(db) == baseline

    # (b) A project with only a non-completed (ERROR) run → still does NOT count.
    s_err, p_err = _seed(db, "errored")
    _seed_run(db, sbom=s_err, project=p_err, started=_iso_days_ago(1),
              findings=[], status="ERROR")
    assert metrics.applications_scanned_total(db) == baseline

    # (c) A project with a completed run → counts (+1).
    s_ok, p_ok = _seed(db, "scanned")
    _seed_run(db, sbom=s_ok, project=p_ok, started=_iso_days_ago(1),
              findings=[{"vuln_id": "CVE-2021-9000", "severity": "HIGH"}])  # status defaults to FINDINGS
    assert metrics.applications_scanned_total(db) == baseline + 1


# ── Vulnerability by age ────────────────────────────────────────────────────


def test_age_bucket_boundaries():
    from datetime import date

    from app.metrics.age import _bucket_for

    today = date(2026, 6, 8)
    assert _bucket_for("2026-06-08", today) == "le_30d"           # 0d
    assert _bucket_for("2026-05-09", today) == "le_30d"           # 30d
    assert _bucket_for("2026-05-08", today) == "d31_90"           # 31d
    assert _bucket_for("2026-03-10", today) == "d31_90"           # 90d
    assert _bucket_for("2026-03-09", today) == "d91_365"          # 91d
    assert _bucket_for("2025-06-08", today) == "d91_365"          # 365d
    assert _bucket_for("2025-06-07", today) == "gt_365"           # 366d
    assert _bucket_for(None, today) == "unknown"
    assert _bucket_for("", today) == "unknown"
    assert _bucket_for("not-a-date", today) == "unknown"


def test_age_distribution_window_excludes_out_of_window_scans(client, db):
    from app import metrics
    from app.metrics.cache import reset_cache

    sbom, proj = _seed(db, "age-window")
    _seed_run(db, sbom=sbom, project=proj, started=_iso_days_ago(2),
              findings=[{"vuln_id": "CVE-2021-0002", "published_on": _iso_days_ago(5)}])

    reset_cache()
    # A window entirely in the future selects no scans → all buckets zero.
    future = (datetime.now(UTC) + timedelta(days=30)).isoformat()
    buckets = metrics.findings_age_distribution(db, window=(future, None))
    assert sum(buckets.values()) == 0


def test_age_distribution_buckets_seeded_findings(client, db):
    from app import metrics
    from app.metrics.cache import reset_cache

    sbom, proj = _seed(db, "age-buckets")
    _seed_run(db, sbom=sbom, project=proj, started=_iso_days_ago(1), findings=[
        {"vuln_id": "CVE-2021-0003", "published_on": _iso_days_ago(10)},   # le_30d
        {"vuln_id": "CVE-2021-0004", "published_on": _iso_days_ago(800)},  # gt_365
        {"vuln_id": "CVE-2021-0005", "published_on": None},                # unknown
    ])

    reset_cache()
    buckets = metrics.findings_age_distribution(db)
    assert set(buckets.keys()) == {"le_30d", "d31_90", "d91_365", "gt_365", "unknown"}
    assert buckets["le_30d"] >= 1
    assert buckets["gt_365"] >= 1
    assert buckets["unknown"] >= 1


def test_vulnerability_age_endpoint(client, db):
    sbom, proj = _seed(db, "age-endpoint")
    _seed_run(db, sbom=sbom, project=proj, started=_iso_days_ago(1),
              findings=[{"vuln_id": "CVE-2021-0006", "published_on": _iso_days_ago(15)}])

    body = client.get("/dashboard/vulnerability-age").json()
    assert "buckets" in body and "total" in body
    assert body["period"] == "all"
    # Period filter is accepted.
    assert client.get("/dashboard/vulnerability-age?period=year").status_code == 200


# ── Trend (granularity + app filter + fix overlays) ─────────────────────────


def test_trend_app_filter_fix_and_resolved(client, db):
    from app import metrics
    from app.metrics.cache import reset_cache

    sbom, proj = _seed(db, "trend")
    # Run 1 (older): findings A (with fix) + B. Run 2 (latest): only A → B resolved.
    _seed_run(db, sbom=sbom, project=proj, started=_iso_days_ago(5), findings=[
        {"vuln_id": "CVE-2021-0007", "severity": "HIGH", "fixed_versions": '["1.2.3"]'},  # A
        {"vuln_id": "CVE-2021-0008", "severity": "HIGH"},                                  # B
    ])
    _seed_run(db, sbom=sbom, project=proj, started=_iso_days_ago(1), findings=[
        {"vuln_id": "CVE-2021-0007", "severity": "HIGH", "fixed_versions": '["1.2.3"]'},  # A only
    ])

    reset_cache()
    # App filter isolates this project → exact assertions.
    points = metrics.findings_trend(db, granularity="day", application_ids=[proj.id])
    assert len(points) == 30  # 30 day points

    latest = points[-1]
    assert latest["total"] == 1            # only A is active in the latest snapshot
    assert latest["fix_available"] == 1    # A carries a fixed version
    # B resolved exactly once across the window.
    assert sum(p["resolved"] for p in points) == 1


def test_trend_granularity_point_counts(client, db):
    from app import metrics
    from app.metrics.cache import reset_cache

    sbom, proj = _seed(db, "trend-gran")
    _seed_run(db, sbom=sbom, project=proj, started=_iso_days_ago(1),
              findings=[{"vuln_id": "CVE-2021-0009", "severity": "HIGH"}])

    reset_cache()
    assert len(metrics.findings_trend(db, granularity="week", application_ids=[proj.id])) == 12
    assert len(metrics.findings_trend(db, granularity="month", application_ids=[proj.id])) == 12
    assert len(metrics.findings_trend(db, granularity="year", application_ids=[proj.id])) == 5


def test_trend_endpoint_legacy_and_manager_paths(client, db):
    # Legacy daily path unchanged (no granularity).
    legacy = client.get("/dashboard/trend?days=30").json()
    assert legacy["granularity"] is None
    assert len(legacy["points"]) == 30

    # Manager path with granularity adds fix overlays.
    mgr = client.get("/dashboard/trend?granularity=week").json()
    assert mgr["granularity"] == "week"
    assert len(mgr["points"]) == 12
    assert "fix_available" in mgr["points"][0]
    assert "resolved" in mgr["points"][0]


def test_age_distribution_filters_by_project_and_sbom(client, db):
    """Project / SBOM filters narrow the age pie to that scope.

    Isolated by the unique project/sbom ids the helpers create, so the
    filtered counts are exact (not just bounds).
    """
    from app import metrics
    from app.metrics.cache import reset_cache

    sa, pa = _seed(db, "age-proj-a")
    _seed_run(db, sbom=sa, project=pa, started=_iso_days_ago(1),
              findings=[{"vuln_id": "CVE-2021-7001", "published_on": _iso_days_ago(10)}])  # le_30d
    sb, pb = _seed(db, "age-proj-b")
    _seed_run(db, sbom=sb, project=pb, started=_iso_days_ago(1),
              findings=[{"vuln_id": "CVE-2021-7002", "published_on": _iso_days_ago(800)}])  # gt_365

    reset_cache()
    # project A → only A's finding (le_30d); B's gt_365 is excluded.
    a = metrics.findings_age_distribution(db, project_id=pa.id)
    assert a["le_30d"] == 1
    assert a["gt_365"] == 0
    assert sum(a.values()) == 1

    # project B → only B's finding (gt_365).
    b = metrics.findings_age_distribution(db, project_id=pb.id)
    assert b["gt_365"] == 1
    assert sum(b.values()) == 1

    # single SBOM (A1) → that SBOM's latest run only.
    s = metrics.findings_age_distribution(db, sbom_id=sa.id)
    assert s["le_30d"] == 1
    assert sum(s.values()) == 1

    # endpoint accepts the params.
    assert client.get(f"/dashboard/vulnerability-age?project_id={pa.id}").status_code == 200
    assert client.get(f"/dashboard/vulnerability-age?sbom_id={sa.id}").status_code == 200

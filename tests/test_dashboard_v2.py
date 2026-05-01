"""Integration + unit tests for the v2 dashboard endpoints.

Pins down the new contracts locked in ``docs/dashboard-redesign.md``:

* ``GET /dashboard/trend`` always returns ``days`` zero-filled points,
  exposes ``unknown`` and ``total``, includes ``avg_total`` and
  ``earliest_run_date``, and emits annotations for SBOM uploads and
  ≥5-finding remediation events. The legacy ``series`` alias mirrors
  ``points`` for one release.
* ``GET /dashboard/posture`` carries the v1 fields *plus* ``total_findings``,
  ``distinct_vulnerabilities``, ``net_7day_added``, ``net_7day_resolved``,
  ``headline_state``, and ``primary_action``.
* ``GET /dashboard/lifetime`` returns cumulative metrics — never decreases.
* ``compute_headline_state`` follows the precedence locked in §2.1 of the
  redesign doc.
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


def _ago_iso(seconds: int) -> str:
    return (datetime.now(UTC) - timedelta(seconds=seconds)).replace(microsecond=0).isoformat()


def _days_ago_iso(n: int) -> str:
    return (datetime.now(UTC) - timedelta(days=n)).replace(microsecond=0).isoformat()


def _seed_sbom_and_project(db, *, name: str, project_status: int = 1):
    from app.models import Projects, SBOMSource

    proj = Projects(project_name=f"v2-{name}", project_status=project_status, created_on=_now_iso())
    db.add(proj)
    db.flush()
    sbom = SBOMSource(sbom_name=f"v2-sbom-{name}", projectid=proj.id, created_on=_now_iso())
    db.add(sbom)
    db.flush()
    return sbom, proj


def _seed_run(
    db,
    *,
    sbom,
    project,
    status: str,
    started_on: str,
    findings: list[dict],
):
    from app.models import AnalysisFinding, AnalysisRun

    run = AnalysisRun(
        sbom_id=sbom.id,
        project_id=project.id,
        run_status=status,
        source="TEST",
        started_on=started_on,
        completed_on=started_on,
        duration_ms=1,
        total_components=1,
        components_with_cpe=0,
        total_findings=len(findings),
        critical_count=sum(1 for f in findings if f["severity"] == "CRITICAL"),
        high_count=sum(1 for f in findings if f["severity"] == "HIGH"),
        medium_count=sum(1 for f in findings if f["severity"] == "MEDIUM"),
        low_count=sum(1 for f in findings if f["severity"] == "LOW"),
        unknown_count=sum(1 for f in findings if f["severity"] == "UNKNOWN"),
        query_error_count=0,
    )
    db.add(run)
    db.flush()
    for f in findings:
        db.add(
            AnalysisFinding(
                analysis_run_id=run.id,
                vuln_id=f["vuln_id"],
                severity=f["severity"],
                component_name=f.get("component_name"),
                component_version=f.get("component_version"),
                fixed_versions=f.get("fixed_versions"),
            )
        )
    db.commit()
    return run


# ---------------------------------------------------------------------------
# /dashboard/trend — v2 zero-fill + new fields
# ---------------------------------------------------------------------------


def test_trend_returns_exactly_days_points_zero_filled(client, db):
    """Even with no findings, the response is a 30-element zero-filled series."""
    resp = client.get("/dashboard/trend?days=30")
    assert resp.status_code == 200
    body = resp.json()
    assert body["days"] == 30
    assert len(body["points"]) == 30
    assert len(body["series"]) == 30  # legacy alias same shape
    # Each point has every severity field including unknown + total.
    for p in body["points"]:
        for k in ("date", "critical", "high", "medium", "low", "unknown", "total"):
            assert k in p, f"missing {k} in point"
        assert p["total"] == p["critical"] + p["high"] + p["medium"] + p["low"] + p["unknown"]
    # Dates are consecutive ascending.
    dates = [p["date"] for p in body["points"]]
    assert dates == sorted(dates)


def test_trend_zero_fills_days_with_no_data(client, db):
    """A single day of findings → 30 points, 29 zeros + 1 populated row."""
    today = _now_iso()
    sbom, proj = _seed_sbom_and_project(db, name="zerofill")
    _seed_run(
        db,
        sbom=sbom,
        project=proj,
        status="FINDINGS",
        started_on=today,
        findings=[{"vuln_id": "CVE-ZF-1", "severity": "HIGH"}],
    )

    body = client.get("/dashboard/trend?days=30").json()
    assert len(body["points"]) == 30
    today_key = today[:10]
    by_date = {p["date"]: p for p in body["points"]}
    assert today_key in by_date
    assert by_date[today_key]["high"] >= 1
    # Find a day in the middle of the window that we did NOT seed and
    # confirm it's a zero point — proves the fill.
    middle_day = body["points"][15]["date"]
    if middle_day != today_key:
        assert body["points"][15]["total"] == 0


def test_trend_includes_avg_total_and_earliest_run_date(client, db):
    today = _now_iso()
    sbom, proj = _seed_sbom_and_project(db, name="avgcheck")
    _seed_run(
        db,
        sbom=sbom,
        project=proj,
        status="FINDINGS",
        started_on=today,
        findings=[{"vuln_id": f"CVE-AVG-{i}", "severity": "MEDIUM"} for i in range(10)],
    )

    body = client.get("/dashboard/trend?days=30").json()
    assert "avg_total" in body
    assert isinstance(body["avg_total"], (int, float))
    assert body["avg_total"] >= 0
    assert "earliest_run_date" in body
    # Earliest run date is one of the YYYY-MM-DD strings we'd seed.
    assert body["earliest_run_date"] is not None
    assert len(body["earliest_run_date"]) == 10


def test_trend_emits_sbom_uploaded_annotation(client, db):
    """An SBOM created today → annotation marker on today."""
    sbom, proj = _seed_sbom_and_project(db, name="annot-upload")
    today_iso = _now_iso()
    _seed_run(
        db,
        sbom=sbom,
        project=proj,
        status="FINDINGS",
        started_on=today_iso,
        findings=[{"vuln_id": "CVE-ANNOT", "severity": "LOW"}],
    )

    body = client.get("/dashboard/trend?days=30").json()
    today_key = today_iso[:10]
    annotations_today = [a for a in body["annotations"] if a["date"] == today_key]
    upload_annotations = [a for a in annotations_today if a["kind"] == "sbom_uploaded"]
    assert upload_annotations, "expected an sbom_uploaded annotation today"
    # Label includes either a count or the SBOM name; never empty.
    for a in upload_annotations:
        assert a["label"]


def test_trend_emits_remediation_annotation_on_5plus_drop(client, db):
    """Run N has 6 findings; run N+1 has 1 → remediation annotation on run N+1's day."""
    sbom, proj = _seed_sbom_and_project(db, name="remed")
    older = _ago_iso(60)
    newer = _ago_iso(20)
    findings_n = [
        {"vuln_id": f"CVE-REMED-{i}", "severity": "HIGH", "component_name": "x", "component_version": "1.0"}
        for i in range(6)
    ]
    findings_n_plus_one = [
        {"vuln_id": "CVE-REMED-0", "severity": "HIGH", "component_name": "x", "component_version": "1.0"}
    ]
    _seed_run(db, sbom=sbom, project=proj, status="FINDINGS", started_on=older, findings=findings_n)
    _seed_run(
        db,
        sbom=sbom,
        project=proj,
        status="FINDINGS",
        started_on=newer,
        findings=findings_n_plus_one,
    )

    body = client.get("/dashboard/trend?days=30").json()
    newer_key = newer[:10]
    remed = [
        a
        for a in body["annotations"]
        if a["kind"] == "remediation" and a["date"] == newer_key
    ]
    assert remed, "expected a remediation annotation when ≥5 findings were resolved"
    assert remed[0]["count"] >= 5


def test_trend_does_not_emit_remediation_for_small_drops(client, db):
    """Drop of < 5 findings should NOT mark the chart — keeps the marker meaningful."""
    sbom, proj = _seed_sbom_and_project(db, name="small-drop")
    older = _ago_iso(60)
    newer = _ago_iso(20)
    # 3 → 2 = drop of 1
    findings_n = [
        {"vuln_id": f"CVE-SD-{i}", "severity": "MEDIUM", "component_name": "y", "component_version": "1.0"}
        for i in range(3)
    ]
    findings_n_plus_one = [
        {"vuln_id": "CVE-SD-0", "severity": "MEDIUM", "component_name": "y", "component_version": "1.0"},
        {"vuln_id": "CVE-SD-1", "severity": "MEDIUM", "component_name": "y", "component_version": "1.0"},
    ]
    _seed_run(db, sbom=sbom, project=proj, status="FINDINGS", started_on=older, findings=findings_n)
    _seed_run(db, sbom=sbom, project=proj, status="FINDINGS", started_on=newer, findings=findings_n_plus_one)

    body = client.get("/dashboard/trend?days=30").json()
    newer_key = newer[:10]
    # No remediation marker for THIS sbom on newer_key (other sboms may have one)
    # We can't assert "no remediation at all today" because the test session is
    # shared, but we can assert that any marker present has count ≥ 5.
    for a in body["annotations"]:
        if a["kind"] == "remediation" and a["date"] == newer_key:
            assert a["count"] >= 5


# ---------------------------------------------------------------------------
# /dashboard/posture — extended fields
# ---------------------------------------------------------------------------


def test_posture_includes_v2_fields(client, db):
    body = client.get("/dashboard/posture").json()
    for key in (
        "total_findings",
        "distinct_vulnerabilities",
        "net_7day_added",
        "net_7day_resolved",
        "headline_state",
        "primary_action",
        "schema_version",
    ):
        assert key in body, f"missing v2 field {key}"
    assert body["headline_state"] in (
        "no_data",
        "clean",
        "kev_present",
        "criticals_no_kev",
        "high_only",
        "low_volume",
    )
    assert body["primary_action"] in (
        "upload",
        "review_kev",
        "review_critical",
        "view_top_sboms",
    )


def test_posture_preserves_v1_fields(client, db):
    """v1 sidebar consumers must keep working unchanged."""
    body = client.get("/dashboard/posture").json()
    for key in (
        "severity",
        "kev_count",
        "fix_available_count",
        "last_successful_run_at",
        "total_sboms",
        "total_active_projects",
    ):
        assert key in body, f"v1 field {key} regressed"


# ---------------------------------------------------------------------------
# Headline state machine — pure unit tests
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    "args, expected",
    [
        # (total_sboms, total_findings, critical, high, kev_count) → (state, action)
        ((0, 0, 0, 0, 0), ("no_data", "upload")),
        ((1, 0, 0, 0, 0), ("clean", "upload")),
        ((1, 100, 5, 12, 0), ("criticals_no_kev", "review_critical")),
        ((1, 100, 5, 12, 3), ("kev_present", "review_kev")),  # KEV beats critical
        ((1, 100, 0, 12, 0), ("high_only", "view_top_sboms")),
        ((1, 100, 0, 0, 0), ("low_volume", "view_top_sboms")),
        ((3, 0, 0, 0, 0), ("clean", "upload")),
        # Edge: KEV present with no criticals or highs still routes to KEV review
        ((2, 5, 0, 0, 1), ("kev_present", "review_kev")),
    ],
)
def test_headline_state_precedence(args, expected):
    from app.services.dashboard_metrics import compute_headline_state

    total_sboms, total_findings, critical, high, kev_count = args
    state, action = compute_headline_state(
        total_sboms=total_sboms,
        total_findings=total_findings,
        critical=critical,
        high=high,
        kev_count=kev_count,
    )
    assert (state, action) == expected


# ---------------------------------------------------------------------------
# /dashboard/lifetime — shape + cache + monotonic growth
# ---------------------------------------------------------------------------


def test_lifetime_endpoint_returns_required_fields(client, db):
    from app.services.dashboard_metrics import reset_lifetime_cache

    reset_lifetime_cache()
    resp = client.get("/dashboard/lifetime")
    assert resp.status_code == 200
    body = resp.json()
    for key in (
        "sboms_scanned_total",
        "projects_total",
        "runs_executed_total",
        "runs_executed_this_week",
        "findings_surfaced_total",
        "findings_resolved_total",
        "first_run_at",
        "days_monitoring",
        "schema_version",
    ):
        assert key in body, f"missing {key}"
    assert isinstance(body["sboms_scanned_total"], int)
    assert isinstance(body["days_monitoring"], int)


def test_lifetime_growth_is_monotonic_after_seeding(client, db):
    """Seeding a new run must not make any lifetime counter decrease."""
    from app.services.dashboard_metrics import reset_lifetime_cache

    reset_lifetime_cache()
    before = client.get("/dashboard/lifetime").json()

    sbom, proj = _seed_sbom_and_project(db, name="growth")
    _seed_run(
        db,
        sbom=sbom,
        project=proj,
        status="FINDINGS",
        started_on=_now_iso(),
        findings=[{"vuln_id": "CVE-GROWTH-1", "severity": "HIGH"}],
    )

    reset_lifetime_cache()
    after = client.get("/dashboard/lifetime").json()
    for key in (
        "sboms_scanned_total",
        "projects_total",
        "runs_executed_total",
        "findings_surfaced_total",
    ):
        assert after[key] >= before[key], f"{key} went backwards"


def test_lifetime_findings_resolved_after_remediation(client, db):
    """Run N has 4 findings; run N+1 has 1 → 3 resolved findings recorded."""
    from app.services.dashboard_metrics import reset_lifetime_cache

    reset_lifetime_cache()
    sbom, proj = _seed_sbom_and_project(db, name="resolved")
    older = _ago_iso(60)
    newer = _ago_iso(20)
    base = [
        {"vuln_id": f"CVE-RESV-{i}", "severity": "HIGH", "component_name": "z", "component_version": "1.0"}
        for i in range(4)
    ]
    after_fix = [
        {"vuln_id": "CVE-RESV-0", "severity": "HIGH", "component_name": "z", "component_version": "1.0"}
    ]
    _seed_run(db, sbom=sbom, project=proj, status="FINDINGS", started_on=older, findings=base)
    _seed_run(db, sbom=sbom, project=proj, status="FINDINGS", started_on=newer, findings=after_fix)

    reset_lifetime_cache()
    body = client.get("/dashboard/lifetime").json()
    # We just contributed 3 resolved tuples — total must reflect at least that.
    assert body["findings_resolved_total"] >= 3


def test_lifetime_endpoint_returns_etag(client, db):
    from app.services.dashboard_metrics import reset_lifetime_cache

    reset_lifetime_cache()
    first = client.get("/dashboard/lifetime")
    assert first.status_code == 200
    etag = first.headers.get("etag")
    assert etag, "expected ETag on /dashboard/lifetime"
    second = client.get("/dashboard/lifetime", headers={"If-None-Match": etag})
    assert second.status_code == 304

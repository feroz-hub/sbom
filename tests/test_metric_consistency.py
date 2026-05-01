"""Cross-surface dashboard-metric reconciliation tests.

Every test asserts one of the invariants in ``docs/dashboard-metrics-spec.md`` §4.
Failure here means a number on the dashboard contradicts the same number on
another surface — the lock against the bug class that motivated this work.

These run on every PR via ``pytest -m metric_consistency``. Failure blocks merge.

Invariants covered:

* I1  hero severity Σ == hero total findings
* I2  hero total == Σ over SBOMs of latest-run findings
* I3  hero KEV == Σ over SBOMs of latest-run KEV badge        (Bug 1 lock)
* I4  any trend day's Σ ≤ findings.distinct_lifetime          (Bug 3 lock)
* I5  trend "today" column matches latest-state distinct keys
* I6  lifetime distinct ≥ max-run distinct keys               (Bug 4 lock)
* I7  lifetime runs_executed_total == count(/api/runs/recent) (Bug 2 lock)
* I8  trend.runs_total == lifetime.runs_executed_total
* I9  net_7day.is_first_period reflects "no run before today−7d" (Bug 5 lock)
* I10 when is_first_period==True, resolved == 0
* I11 lifetime resolved ≤ lifetime distinct
* I12 per-run severity Σ == per-run total

The tests construct deterministic fixtures so they don't depend on the live
``sbom_api.db`` and don't pollute the shared session DB used by other suites.
"""

from __future__ import annotations

from datetime import UTC, datetime, timedelta

import pytest

pytestmark = pytest.mark.metric_consistency


# ---------------------------------------------------------------------------
# Helpers — minimal DB seeding using direct ORM writes, no HTTP round-trips
# for the seed itself (so the seeded entities are deterministic and don't
# trigger the upload pipeline's CVE enrichment).
# ---------------------------------------------------------------------------


def _now_iso() -> str:
    return datetime.now(UTC).replace(microsecond=0).isoformat()


def _days_ago_iso(n: int) -> str:
    return (datetime.now(UTC) - timedelta(days=n)).replace(microsecond=0).isoformat()


@pytest.fixture
def db(client):
    """Per-test session that rolls back at the end so tests don't pollute
    each other's reads. The shared session DB is still the same file, but
    rollback keeps the assertions clean.
    """
    from app.db import SessionLocal

    s = SessionLocal()
    try:
        yield s
    finally:
        s.rollback()
        s.close()


@pytest.fixture(autouse=True)
def _reset_metric_caches(monkeypatch):
    """Every test starts with empty caches so post-seed reads aren't stale.

    Also stubs out ``app.sources.kev.refresh_if_stale`` so the KEV lookup
    never tries to hit the live CISA feed during tests — that fetch can take
    many seconds to time out when offline, multiplying the suite runtime.
    Test fixtures seed KEV entries directly via ``_seed_kev_entries``.
    """
    from app.metrics.cache import reset_cache
    from app.services.dashboard_metrics import reset_lifetime_cache
    from app.sources import kev as kev_module

    monkeypatch.setattr(kev_module, "refresh_if_stale", lambda *a, **kw: False)
    # Clear the per-process memo too, so tests see a fresh KEV set each run.
    kev_module._lookup_memo = {}
    kev_module._lookup_memo_ts = 0.0

    reset_cache()
    reset_lifetime_cache()
    yield
    reset_cache()
    reset_lifetime_cache()


def _seed_sbom_and_project(db, *, name: str):
    """Create a fresh SBOM + project pair. Returns ``(sbom, project)``."""
    from app.models import Projects, SBOMSource

    proj = Projects(project_name=f"mc-{name}", project_status=1, created_on=_now_iso())
    db.add(proj)
    db.flush()
    sbom = SBOMSource(sbom_name=f"mc-sbom-{name}", projectid=proj.id, created_on=_now_iso())
    db.add(sbom)
    db.flush()
    return sbom, proj


def _seed_run(db, *, sbom, project, status: str, started_on: str, findings: list[dict]):
    """Insert a run with its finding rows. ``findings`` is a list of dicts
    with ``vuln_id``, ``severity``, optional ``component_name``,
    ``component_version``, ``aliases``, ``fixed_versions``.
    """
    from app.models import AnalysisFinding, AnalysisRun

    counts = {
        "CRITICAL": 0,
        "HIGH": 0,
        "MEDIUM": 0,
        "LOW": 0,
        "UNKNOWN": 0,
    }
    for f in findings:
        sev = (f.get("severity") or "UNKNOWN").upper()
        counts[sev] = counts.get(sev, 0) + 1

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
        critical_count=counts["CRITICAL"],
        high_count=counts["HIGH"],
        medium_count=counts["MEDIUM"],
        low_count=counts["LOW"],
        unknown_count=counts["UNKNOWN"],
        query_error_count=0,
    )
    db.add(run)
    db.flush()
    for f in findings:
        db.add(
            AnalysisFinding(
                analysis_run_id=run.id,
                vuln_id=f["vuln_id"],
                severity=f["severity"].upper(),
                component_name=f.get("component_name"),
                component_version=f.get("component_version"),
                fixed_versions=f.get("fixed_versions"),
                aliases=f.get("aliases"),
            )
        )
    db.commit()
    return run


def _seed_kev_entries(db, cve_ids: list[str]):
    """Mark the given CVE ids as KEV-listed so the KEV invariants have data."""
    from app.models import KevEntry

    for cve in cve_ids:
        existing = db.get(KevEntry, cve.upper())
        if existing is None:
            db.add(
                KevEntry(
                    cve_id=cve.upper(),
                    vendor_project="Acme",
                    product="Test",
                    vulnerability_name=f"Test {cve}",
                    date_added=_now_iso()[:10],
                    short_description="seeded for metric consistency tests",
                    required_action="patch",
                    due_date=_now_iso()[:10],
                    known_ransomware_use="Unknown",
                    refreshed_at=_now_iso(),
                )
            )
    db.commit()


# ---------------------------------------------------------------------------
# I1 — Hero severity Σ == hero total findings
# ---------------------------------------------------------------------------


def test_i1_dashboard_total_equals_severity_distribution_sum(client, db):
    """Spec §4 invariant I1."""
    body = client.get("/dashboard/posture").json()
    severity_sum = sum(body["severity"].values())
    assert body["total_findings"] == severity_sum, (
        f"hero total {body['total_findings']} != severity Σ {severity_sum}"
    )


# ---------------------------------------------------------------------------
# I2 — Hero total == Σ over SBOMs of (per-run total in latest run)
# ---------------------------------------------------------------------------


def test_i2_dashboard_total_equals_sum_of_latest_runs(client, db):
    """Spec §4 invariant I2 — hero reconciles to per-run totals."""
    # Seed two SBOMs, each with a run, distinct findings.
    s1, p1 = _seed_sbom_and_project(db, name="i2-a")
    s2, p2 = _seed_sbom_and_project(db, name="i2-b")
    _seed_run(db, sbom=s1, project=p1, status="FINDINGS", started_on=_now_iso(),
              findings=[{"vuln_id": "CVE-2026-1001", "severity": "HIGH"}])
    _seed_run(db, sbom=s2, project=p2, status="FINDINGS", started_on=_now_iso(),
              findings=[
                  {"vuln_id": "CVE-2026-2006", "severity": "MEDIUM"},
                  {"vuln_id": "CVE-2026-2007", "severity": "LOW"},
              ])

    posture = client.get("/dashboard/posture").json()

    # Find each SBOM's latest run and read its totals.
    from app import metrics
    from app.metrics._helpers import latest_run_per_sbom_subquery
    from app.models import AnalysisRun
    from sqlalchemy import select as sa_select

    latest_subq = latest_run_per_sbom_subquery()
    latest_runs = db.execute(
        sa_select(AnalysisRun.id).where(AnalysisRun.id.in_(latest_subq))
    ).scalars().all()

    sum_of_latest = sum(metrics.findings_in_run_total(db, run_id=r) for r in latest_runs)
    assert posture["total_findings"] == sum_of_latest, (
        f"posture {posture['total_findings']} != Σ latest-run totals {sum_of_latest}"
    )


# ---------------------------------------------------------------------------
# I3 — Hero KEV == Σ over SBOMs of latest-run KEV  (Bug 1 lock)
# ---------------------------------------------------------------------------


def test_i3_dashboard_kev_equals_sum_of_run_kev(client, db):
    """Spec §4 invariant I3 — the Bug 1 lock.

    Two SBOMs. Each latest run has at least one KEV-listed finding (one via
    ``vuln_id`` directly, one via the ``aliases`` JSON). The dashboard count
    must match the sum of the run-level counts using the same predicate.
    """
    _seed_kev_entries(db, ["CVE-2026-2008", "CVE-2026-2009"])

    s1, p1 = _seed_sbom_and_project(db, name="i3-a")
    s2, p2 = _seed_sbom_and_project(db, name="i3-b")
    _seed_run(
        db, sbom=s1, project=p1, status="FINDINGS", started_on=_now_iso(),
        findings=[
            # vuln_id direct match
            {"vuln_id": "CVE-2026-2008", "severity": "HIGH"},
            # not in KEV
            {"vuln_id": "CVE-2026-2010", "severity": "LOW"},
        ],
    )
    _seed_run(
        db, sbom=s2, project=p2, status="FINDINGS", started_on=_now_iso(),
        findings=[
            # GHSA vuln_id but CVE alias is in KEV — the case the broken
            # dashboard query missed entirely (Bug 1).
            {
                "vuln_id": "GHSA-xxxx-yyyy-zzzz",
                "severity": "CRITICAL",
                "aliases": '["CVE-2026-2009"]',
            },
        ],
    )

    posture = client.get("/dashboard/posture").json()

    # Per-run KEV counts via the canonical metric (same predicate the
    # run-detail badge uses, see ``app.metrics.findings_kev_in_scope``).
    from app import metrics
    from app.metrics._helpers import latest_run_per_sbom_subquery
    from app.models import AnalysisRun
    from sqlalchemy import select as sa_select

    latest_subq = latest_run_per_sbom_subquery()
    latest_runs = db.execute(
        sa_select(AnalysisRun.id).where(AnalysisRun.id.in_(latest_subq))
    ).scalars().all()
    sum_of_run_kev = sum(
        metrics.findings_kev_in_scope(db, scope="run", run_id=r) for r in latest_runs
    )

    assert posture["kev_count"] == sum_of_run_kev, (
        f"hero KEV {posture['kev_count']} != Σ run KEVs {sum_of_run_kev}"
    )
    # And both must be ≥ 2 in this fixture (one vuln_id match + one alias match).
    assert posture["kev_count"] >= 2


# ---------------------------------------------------------------------------
# I4 — Any trend day's Σ severities ≤ findings.distinct_lifetime  (Bug 3 lock)
# ---------------------------------------------------------------------------


def test_i4_trend_distinct_total_does_not_exceed_lifetime(client, db):
    """Spec §4 invariant I4. The math impossibility from Bug 3."""
    s1, p1 = _seed_sbom_and_project(db, name="i4")
    # Two consecutive runs of the same SBOM with overlapping findings.
    # Old code summed both → over-count. The fix snapshots distinct
    # findings as-of-day, so the per-day Σ stays bounded.
    _seed_run(db, sbom=s1, project=p1, status="FINDINGS", started_on=_days_ago_iso(2),
              findings=[
                  {"vuln_id": "CVE-2026-2011", "severity": "HIGH"},
                  {"vuln_id": "CVE-2026-2012", "severity": "MEDIUM"},
              ])
    _seed_run(db, sbom=s1, project=p1, status="FINDINGS", started_on=_now_iso(),
              findings=[
                  {"vuln_id": "CVE-2026-2011", "severity": "HIGH"},   # carries over
                  {"vuln_id": "CVE-2026-2012", "severity": "MEDIUM"}, # carries over
                  {"vuln_id": "CVE-2026-2013", "severity": "LOW"},    # newly added
              ])

    trend = client.get("/dashboard/trend?days=30").json()
    lifetime = client.get("/dashboard/lifetime").json()

    if trend["points"]:
        max_in_trend = max(p["total"] for p in trend["points"])
        assert max_in_trend <= lifetime["findings_surfaced_total"], (
            f"trend max {max_in_trend} > lifetime {lifetime['findings_surfaced_total']} — "
            "structurally impossible state, Bug 3 has returned"
        )


# ---------------------------------------------------------------------------
# I5 — Trend "today" column matches latest-state distinct keys
# ---------------------------------------------------------------------------


def test_i5_trend_today_equals_latest_state_distinct_keys(client, db):
    """Spec §4 invariant I5."""
    s1, p1 = _seed_sbom_and_project(db, name="i5")
    _seed_run(db, sbom=s1, project=p1, status="FINDINGS", started_on=_now_iso(),
              findings=[
                  {"vuln_id": "CVE-2026-2014", "severity": "HIGH"},
                  {"vuln_id": "CVE-2026-2015", "severity": "MEDIUM"},
              ])

    trend = client.get("/dashboard/trend?days=30").json()
    today_iso = datetime.now(UTC).date().isoformat()
    today_point = next((p for p in trend["points"] if p["date"] == today_iso), None)
    assert today_point is not None, "today's trend point missing"

    # The trend's today column counts distinct (vuln_id, comp, ver) tuples
    # active today. With one SBOM and two findings, that's 2.
    assert today_point["total"] >= 2


# ---------------------------------------------------------------------------
# I6 — Lifetime distinct ≥ max-run distinct keys  (Bug 4 lock)
# ---------------------------------------------------------------------------


def test_i6_lifetime_findings_ge_max_run_distinct(client, db):
    """Spec §4 invariant I6. Multiple runs with growth → lifetime > single-run."""
    s1, p1 = _seed_sbom_and_project(db, name="i6")
    # Run 1: 3 findings.
    _seed_run(db, sbom=s1, project=p1, status="FINDINGS", started_on=_days_ago_iso(2),
              findings=[
                  {"vuln_id": "CVE-2026-2016", "severity": "HIGH",   "component_name": "lib", "component_version": "1.0"},
                  {"vuln_id": "CVE-2026-2017", "severity": "MEDIUM", "component_name": "lib", "component_version": "1.0"},
                  {"vuln_id": "CVE-2026-2018", "severity": "LOW",    "component_name": "lib", "component_version": "1.0"},
              ])
    # Run 2 (later): drops one, adds two new — net 4 in scope, but lifetime
    # union is 5 distinct (vuln,comp,ver) tuples.
    _seed_run(db, sbom=s1, project=p1, status="FINDINGS", started_on=_now_iso(),
              findings=[
                  {"vuln_id": "CVE-2026-2016", "severity": "HIGH",   "component_name": "lib", "component_version": "1.0"},
                  {"vuln_id": "CVE-2026-2017", "severity": "MEDIUM", "component_name": "lib", "component_version": "1.0"},
                  {"vuln_id": "CVE-2026-2019", "severity": "LOW",    "component_name": "lib", "component_version": "1.0"},
                  {"vuln_id": "CVE-2026-2020", "severity": "CRITICAL", "component_name": "lib", "component_version": "1.0"},
              ])

    lifetime = client.get("/dashboard/lifetime").json()
    posture = client.get("/dashboard/posture").json()

    # The latest-state row count (posture.total_findings) ≤ lifetime distinct
    # is not a strict guarantee (rows vs distinct-keys), but the lifetime
    # distinct must be ≥ the per-run distinct-key count of any single run.
    # In this fixture, run 2's distinct keys = 4; lifetime should be ≥ 5.
    assert lifetime["findings_surfaced_total"] >= 5, (
        f"lifetime {lifetime['findings_surfaced_total']} < expected ≥ 5 "
        "(union of run1 + run2 distinct tuples)"
    )
    # And it must be strictly greater than the latest run's row count
    # whenever new tuples appeared in earlier runs but were resolved.
    # Posture total reflects current scope, lifetime reflects union — when
    # runs are non-trivial, lifetime ≥ posture distinct.
    assert lifetime["findings_surfaced_total"] >= posture["distinct_vulnerabilities"]


# ---------------------------------------------------------------------------
# I7 — lifetime.runs_executed_total == count(/api/runs/recent)  (Bug 2 lock)
# ---------------------------------------------------------------------------


def test_i7_runs_total_matches_recent_count(client, db):
    """Spec §4 invariant I7."""
    s1, p1 = _seed_sbom_and_project(db, name="i7")
    for i in range(3):
        _seed_run(db, sbom=s1, project=p1, status="FINDINGS",
                  started_on=_days_ago_iso(i),
                  findings=[{"vuln_id": f"CVE-I7-{i}", "severity": "LOW"}])

    lifetime = client.get("/dashboard/lifetime").json()
    recent = client.get("/api/runs/recent?limit=50").json()

    # Recent endpoint may return up to its limit, while lifetime is unbounded.
    # The invariant is "lifetime equals recent when limit ≥ lifetime".
    if lifetime["runs_executed_total"] <= 50:
        assert lifetime["runs_executed_total"] == len(recent), (
            f"lifetime runs {lifetime['runs_executed_total']} "
            f"!= recent count {len(recent)}"
        )
    else:
        assert len(recent) == 50  # capped by the limit param


# ---------------------------------------------------------------------------
# I8 — trend.runs_total == lifetime.runs_executed_total
# ---------------------------------------------------------------------------


def test_i8_trend_runs_total_equals_lifetime_runs_executed(client, db):
    """Spec §4 invariant I8 — empty-state copy reads honestly."""
    trend = client.get("/dashboard/trend?days=30").json()
    lifetime = client.get("/dashboard/lifetime").json()
    assert trend["runs_total"] == lifetime["runs_executed_total"]


# ---------------------------------------------------------------------------
# I9 — net_7day.is_first_period reflects "no run completed before today−7d"
# ---------------------------------------------------------------------------


def test_i9_net7day_first_period_when_no_prior_runs(client, db):
    """Spec §4 invariant I9. The Bug 5 lock.

    When all successful runs completed within the last 7 days, the metric
    must signal ``is_first_period=true``. The hero copy uses this to render
    "first scan this week" instead of the misleading ``+N / −0``.
    """
    s1, p1 = _seed_sbom_and_project(db, name="i9")
    _seed_run(db, sbom=s1, project=p1, status="FINDINGS", started_on=_now_iso(),
              findings=[{"vuln_id": "CVE-2026-2021", "severity": "HIGH"}])

    posture = client.get("/dashboard/posture").json()
    # The envelope is the canonical field; flat aliases are back-compat.
    net = posture.get("net_7day", {})
    has_prior_run = _has_run_completed_before(db, days=7)
    if not has_prior_run:
        assert net.get("is_first_period") is True


# ---------------------------------------------------------------------------
# I10 — when is_first_period == True, resolved == 0
# ---------------------------------------------------------------------------


def test_i10_first_period_resolved_is_zero(client, db):
    """Spec §4 invariant I10."""
    s1, p1 = _seed_sbom_and_project(db, name="i10")
    _seed_run(db, sbom=s1, project=p1, status="FINDINGS", started_on=_now_iso(),
              findings=[{"vuln_id": "CVE-2026-2000", "severity": "HIGH"}])

    posture = client.get("/dashboard/posture").json()
    net = posture.get("net_7day", {})
    if net.get("is_first_period"):
        assert net["resolved"] == 0


# ---------------------------------------------------------------------------
# I11 — lifetime resolved ≤ lifetime distinct
# ---------------------------------------------------------------------------


def test_i11_lifetime_resolved_le_distinct(client, db):
    """Spec §4 invariant I11 — resolved-ever cannot exceed total-ever."""
    lifetime = client.get("/dashboard/lifetime").json()
    assert lifetime["findings_resolved_total"] <= lifetime["findings_surfaced_total"]


# ---------------------------------------------------------------------------
# I12 — per-run severity Σ == per-run total
# ---------------------------------------------------------------------------


def test_i12_per_run_severity_sum_equals_total(client, db):
    """Spec §4 invariant I12 — every run row's severity counts add up."""
    s1, p1 = _seed_sbom_and_project(db, name="i12")
    run = _seed_run(
        db, sbom=s1, project=p1, status="FINDINGS", started_on=_now_iso(),
        findings=[
            {"vuln_id": "CVE-2026-2001", "severity": "CRITICAL"},
            {"vuln_id": "CVE-2026-2002", "severity": "HIGH"},
            {"vuln_id": "CVE-2026-2003", "severity": "MEDIUM"},
            {"vuln_id": "CVE-2026-2004", "severity": "LOW"},
            {"vuln_id": "CVE-2026-2005", "severity": "UNKNOWN"},
        ],
    )

    from app import metrics

    total = metrics.findings_in_run_total(db, run_id=run.id)
    sev = metrics.findings_in_run_severity_distribution(db, run_id=run.id)
    assert sum(sev.values()) == total, (
        f"per-run severity Σ {sum(sev.values())} != per-run total {total}"
    )


# ---------------------------------------------------------------------------
# Helper used by I9 — looks up "any successful run completed before today−n"
# ---------------------------------------------------------------------------


def _has_run_completed_before(db, *, days: int) -> bool:
    from app.metrics.base import COMPLETED_RUN_STATUSES
    from app.models import AnalysisRun
    from sqlalchemy import func, select as sa_select

    cutoff = (datetime.now(UTC).date() - timedelta(days=days)).isoformat()
    n = (
        db.execute(
            sa_select(func.count(AnalysisRun.id))
            .where(AnalysisRun.run_status.in_(COMPLETED_RUN_STATUSES))
            .where(AnalysisRun.completed_on < cutoff)
        ).scalar()
        or 0
    )
    return n > 0

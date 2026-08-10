"""Dashboard v4 — advanced-analytics metric tests.

Covers the new ``app.metrics`` modules (forecast / exploitation /
remediation / riskmap) plus endpoint smoke for the
``/dashboard/{forecast,exploitation,remediation,risk-map,risk-matrix}``
routes. Pure-math helpers are tested without a DB; lifecycle semantics are
seeded with the same direct-ORM style as ``test_metric_consistency.py``.
"""

from __future__ import annotations

from datetime import UTC, datetime, timedelta

import pytest

pytestmark = pytest.mark.metric_consistency


def _now_iso() -> str:
    return datetime.now(UTC).replace(microsecond=0).isoformat()


def _days_ago_iso(n: int) -> str:
    return (datetime.now(UTC) - timedelta(days=n)).replace(microsecond=0).isoformat()


# ---------------------------------------------------------------------------
# Fixtures — mirror test_metric_consistency.py (module-local there).
# ---------------------------------------------------------------------------


@pytest.fixture
def db(client):
    from app.db import SessionLocal

    s = SessionLocal()
    try:
        yield s
    finally:
        s.rollback()
        s.close()


@pytest.fixture(autouse=True)
def _reset_metric_caches(monkeypatch):
    from app.metrics.cache import reset_cache
    from app.services.dashboard_metrics import reset_lifetime_cache
    from app.sources import kev as kev_module

    monkeypatch.setattr(kev_module, "refresh_if_stale", lambda *a, **kw: False)
    kev_module._lookup_memo = {}
    kev_module._lookup_memo_ts = 0.0

    reset_cache()
    reset_lifetime_cache()
    yield
    reset_cache()
    reset_lifetime_cache()


def _seed_sbom_and_project(db, *, name: str):
    from app.models import Projects, SBOMSource

    proj = Projects(project_name=f"v4-{name}", project_status=1, created_on=_now_iso())
    db.add(proj)
    db.flush()
    sbom = SBOMSource(sbom_name=f"v4-sbom-{name}", projectid=proj.id, created_on=_now_iso())
    db.add(sbom)
    db.flush()
    return sbom, proj


def _seed_run(db, *, sbom, project, status: str, started_on: str, findings: list[dict]):
    from app.models import AnalysisFinding, AnalysisRun

    counts = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0, "UNKNOWN": 0}
    for f in findings:
        sev = (f.get("severity") or "UNKNOWN").upper()
        counts[sev] = counts.get(sev, 0) + 1

    run = AnalysisRun(
        sbom_id=sbom.id,
        project_id=project.id,
        run_status=status,
        sbom_name=sbom.sbom_name,
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
                score=f.get("score"),
                component_name=f.get("component_name"),
                component_version=f.get("component_version"),
                fixed_versions=f.get("fixed_versions"),
                aliases=f.get("aliases"),
            )
        )
    db.commit()
    return run


def _seed_epss(db, scores: dict[str, float]):
    from app.models import EpssScore

    for cve, p in scores.items():
        existing = db.get(EpssScore, cve.upper())
        if existing is None:
            db.add(
                EpssScore(
                    cve_id=cve.upper(),
                    epss=p,
                    percentile=0.99 if p >= 0.5 else 0.5,
                    score_date=_now_iso()[:10],
                    refreshed_at=_now_iso(),
                )
            )
    db.commit()


def _seed_kev(db, cve_ids: list[str]):
    from app.models import KevEntry

    for cve in cve_ids:
        if db.get(KevEntry, cve.upper()) is None:
            db.add(
                KevEntry(
                    cve_id=cve.upper(),
                    vendor_project="Acme",
                    product="Test",
                    vulnerability_name=f"Test {cve}",
                    date_added=_now_iso()[:10],
                    short_description="seeded for v4 tests",
                    required_action="patch",
                    due_date=_now_iso()[:10],
                    known_ransomware_use="Unknown",
                    refreshed_at=_now_iso(),
                )
            )
    db.commit()


# ---------------------------------------------------------------------------
# Pure math — no DB.
# ---------------------------------------------------------------------------


def test_linear_fit_recovers_a_perfect_line():
    from app.metrics.forecast import linear_fit

    slope, intercept, r2, resid = linear_fit([0, 1, 2, 3], [10, 8, 6, 4])
    assert slope == pytest.approx(-2.0)
    assert intercept == pytest.approx(10.0)
    assert r2 == pytest.approx(1.0)
    assert resid == pytest.approx(0.0)


def test_linear_fit_flat_series_has_zero_slope():
    from app.metrics.forecast import linear_fit

    slope, intercept, r2, _ = linear_fit([0, 1, 2, 3], [5, 5, 5, 5])
    assert slope == pytest.approx(0.0)
    assert intercept == pytest.approx(5.0)
    assert r2 == pytest.approx(0.0)


def test_velocity_anomaly_detects_spike_against_noisy_baseline():
    from app.metrics.forecast import velocity_anomaly

    a = velocity_anomaly([10, 12, 9, 11, 10, 11, 38])
    assert a["detected"] is True
    assert a["delta"] == 27


def test_velocity_anomaly_detects_spike_against_flat_baseline():
    """std == 0 must not mask the most obvious anomaly shape."""
    from app.metrics.forecast import velocity_anomaly

    a = velocity_anomaly([5, 5, 5, 5, 5, 45])
    assert a["detected"] is True
    assert a["zscore"] is None  # no finite z on a zero-variance baseline


def test_velocity_anomaly_quiet_on_small_wobble_and_short_series():
    from app.metrics.forecast import velocity_anomaly

    assert velocity_anomaly([5, 5, 5, 5, 5, 6])["detected"] is False
    assert velocity_anomaly([5, 6])["detected"] is False


def test_exploitation_probability_composes_independently():
    from app.metrics.exploitation import compose_exploitation_probability

    assert compose_exploitation_probability([0.5, 0.5]) == pytest.approx(0.75)
    assert compose_exploitation_probability([]) == 0.0
    assert compose_exploitation_probability([1.5]) == 1.0  # clamped
    assert compose_exploitation_probability([0.0, 0.0]) == 0.0


def test_sla_state_boundaries():
    from app.metrics.remediation import sla_state

    assert sla_state(8, 7) == "overdue"
    assert sla_state(7, 7) == "due_soon"  # at budget = last day, not yet over
    assert sla_state(6, 7) == "due_soon"  # ≥ 75% of budget
    assert sla_state(2, 7) == "ok"


# ---------------------------------------------------------------------------
# DB-backed — lifecycle and scope semantics.
# ---------------------------------------------------------------------------


def test_forecast_insufficient_history_with_sparse_data(client, db):
    """One day of data must NOT produce a projection (no 2-point regression)."""
    s, p = _seed_sbom_and_project(db, name="forecast-sparse")
    _seed_run(
        db,
        sbom=s,
        project=p,
        status="FINDINGS",
        started_on=_now_iso(),
        findings=[{"vuln_id": "CVE-2026-0001", "severity": "HIGH"}],
    )
    body = client.get("/dashboard/forecast").json()
    assert body["schema_version"] == 1
    assert len(body["history"]) == body["history_days"]
    if body["insufficient_history"]:
        assert body["projection"] == []
        assert body["projected_total"] is None


def test_remediation_lifecycle_mttr_sla_and_velocity(client, db):
    """CVE-A detected 20d ago, resolved 10d ago (MTTR 10d). CVE-B still
    active for 20d against a 7d critical budget → overdue by 13d."""
    from app.models import AnalysisFinding, AnalysisRun
    from sqlalchemy import delete

    db.execute(delete(AnalysisFinding))
    db.execute(delete(AnalysisRun))
    db.commit()

    s, p = _seed_sbom_and_project(db, name="remediation")
    _seed_run(
        db,
        sbom=s,
        project=p,
        status="FINDINGS",
        started_on=_days_ago_iso(20),
        findings=[
            {"vuln_id": "CVE-2026-AAAA", "severity": "CRITICAL", "component_name": "liba", "component_version": "1.0"},
            {"vuln_id": "CVE-2026-BBBB", "severity": "CRITICAL", "component_name": "libb", "component_version": "2.0"},
        ],
    )
    _seed_run(
        db,
        sbom=s,
        project=p,
        status="FINDINGS",
        started_on=_days_ago_iso(10),
        findings=[
            {"vuln_id": "CVE-2026-BBBB", "severity": "CRITICAL", "component_name": "libb", "component_version": "2.0"},
        ],
    )

    from app import metrics

    summary = metrics.remediation_summary(db)
    assert summary["mttr_days"]["critical"] == pytest.approx(10.0, abs=1.01)
    assert summary["resolved_total"] >= 1
    assert summary["sla"]["overdue"] >= 1

    offenders = {o["vuln_id"]: o for o in summary["sla"]["worst_offenders"]}
    assert "CVE-2026-BBBB" in offenders
    b = offenders["CVE-2026-BBBB"]
    assert b["sla_days"] == 7
    assert b["age_days"] >= 19
    assert b["days_over"] == b["age_days"] - b["sla_days"]
    # Resolved CVE-A must not appear as an active offender.
    assert "CVE-2026-AAAA" not in offenders

    vel = summary["velocity"]
    assert vel["new_findings"] >= 2
    assert vel["resolved_findings"] >= 1


def test_remediation_endpoint_smoke(client, db):
    body = client.get("/dashboard/remediation").json()
    assert body["schema_version"] == 1
    assert {"overdue", "due_soon", "ok"} <= set(body["sla"].keys())


def test_exploitation_outlook_composes_seeded_epss(client, db):
    s, p = _seed_sbom_and_project(db, name="exploit")
    _seed_run(
        db,
        sbom=s,
        project=p,
        status="FINDINGS",
        started_on=_now_iso(),
        findings=[
            {"vuln_id": "CVE-2026-1111", "severity": "HIGH", "component_name": "libx", "component_version": "1.0"},
            {"vuln_id": "CVE-2026-2222", "severity": "HIGH", "component_name": "liby", "component_version": "1.0"},
        ],
    )
    _seed_epss(db, {"CVE-2026-1111": 0.5, "CVE-2026-2222": 0.5})
    _seed_kev(db, ["CVE-2026-1111"])

    from app import metrics

    out = metrics.portfolio_exploitation_outlook(db)
    assert out["schema_version"] == 1
    assert out["distinct_cves"] >= 2
    assert out["kev_cves"] >= 1
    # Probability must be ≥ the two-CVE composition (other seeds only raise it).
    assert out["probability_30d"] >= 0.75 - 1e-9
    drivers = {d["cve"]: d for d in out["top_drivers"]}
    if "CVE-2026-1111" in drivers:
        assert drivers["CVE-2026-1111"]["kev"] is True


def test_risk_map_and_matrix_reflect_latest_run(client, db):
    s, p = _seed_sbom_and_project(db, name="riskmap")
    _seed_run(
        db,
        sbom=s,
        project=p,
        status="FINDINGS",
        started_on=_now_iso(),
        findings=[
            {
                "vuln_id": "CVE-2026-3333",
                "severity": "CRITICAL",
                "score": 9.8,
                "component_name": "libz",
                "component_version": "3.0",
                "fixed_versions": '["3.1"]',
            },
            {
                "vuln_id": "CVE-2026-4444",
                "severity": "LOW",
                "score": 3.1,
                "component_name": "libw",
                "component_version": "0.1",
            },
        ],
    )
    _seed_epss(db, {"CVE-2026-3333": 0.9})

    map_body = client.get("/dashboard/risk-map").json()
    cell = next((i for i in map_body["items"] if i["sbom_id"] == s.id), None)
    assert cell is not None, "seeded SBOM missing from risk map"
    assert cell["findings_total"] == 2
    assert cell["dominant"] == "critical"
    assert cell["project"] == p.project_name

    matrix_body = client.get("/dashboard/risk-matrix").json()
    pts = {pt["vuln_id"]: pt for pt in matrix_body["points"]}
    assert "CVE-2026-3333" in pts
    assert pts["CVE-2026-3333"]["cvss"] == pytest.approx(9.8)
    assert pts["CVE-2026-3333"]["epss"] == pytest.approx(0.9)
    assert pts["CVE-2026-3333"]["has_fix"] is True


def test_advanced_endpoints_all_return_200(client, db):
    for path in (
        "/dashboard/forecast",
        "/dashboard/exploitation",
        "/dashboard/remediation",
        "/dashboard/risk-map",
        "/dashboard/risk-matrix",
    ):
        res = client.get(path)
        assert res.status_code == 200, f"{path} → {res.status_code}"
        assert res.json().get("schema_version") == 1, f"{path} missing schema_version"

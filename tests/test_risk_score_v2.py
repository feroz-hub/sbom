"""
Tests for the v2 risk scorer (CVSS + EPSS + KEV composite).

We test the pure-Python scoring math against an in-memory SQLite session
seeded with hand-crafted ``AnalysisFinding`` rows. KEV and EPSS lookups
are stubbed at the module level so the tests don't hit external APIs.
"""

from __future__ import annotations

import pytest
from sqlalchemy.orm import Session

from app.models import (
    AnalysisFinding,
    AnalysisRun,
    EpssScore,
    KevEntry,
    Projects,
    SBOMSource,
)
from app.services import risk_score
from app.services.risk_score import score_findings


# ---------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------


def _new_db() -> Session:
    """Build an in-memory SQLite database with the project schema."""
    from sqlalchemy import create_engine
    from sqlalchemy.orm import sessionmaker

    from app.db import Base
    import app.models  # noqa: F401  ensures models are registered

    engine = create_engine("sqlite:///:memory:")
    Base.metadata.create_all(engine)
    return sessionmaker(bind=engine)()


def _seed_run(db: Session) -> AnalysisRun:
    proj = Projects(id=1, project_name="t", project_status=1)
    sbom = SBOMSource(id=1, sbom_name="t", projectid=1)
    run = AnalysisRun(
        id=1,
        sbom_id=1,
        project_id=1,
        run_status="PASS",
        source="NVD",
        started_on="2026-04-29T00:00:00+00:00",
        completed_on="2026-04-29T00:00:01+00:00",
        duration_ms=1000,
    )
    db.add_all([proj, sbom, run])
    db.commit()
    return run


def _make_finding(
    *,
    run_id: int,
    vuln_id: str,
    cvss: float | None,
    severity: str,
    component: str = "lib",
    version: str = "1.0",
    aliases: str | None = None,
) -> AnalysisFinding:
    return AnalysisFinding(
        analysis_run_id=run_id,
        vuln_id=vuln_id,
        score=cvss,
        severity=severity,
        component_name=component,
        component_version=version,
        aliases=aliases,
    )


@pytest.fixture(autouse=True)
def _stub_external(monkeypatch):
    """
    Default: KEV and EPSS lookups return empty. Individual tests override
    these via monkeypatch to assert the boost paths.
    """
    monkeypatch.setattr(risk_score, "lookup_kev_set_memoized", lambda db, ids: set())
    monkeypatch.setattr(
        risk_score, "get_epss_scores_memoized", lambda db, ids: {c: 0.0 for c in ids}
    )


# ---------------------------------------------------------------------
# Pure-formula tests (no DB)
# ---------------------------------------------------------------------


def test_empty_findings_returns_zero_low():
    db = _new_db()
    summary = score_findings(db, [])
    assert summary["total_risk_score"] == 0.0
    assert summary["risk_band"] == "LOW"
    assert summary["components"] == []
    assert summary["worst_finding"] is None
    assert summary["kev_count"] == 0
    assert summary["methodology"]["version"] == "2.0.0"


def test_single_high_no_epss_no_kev_uses_raw_cvss():
    """One CVSS-7.5 finding, no EPSS, no KEV → score == 7.5."""
    db = _new_db()
    run = _seed_run(db)
    f = _make_finding(run_id=run.id, vuln_id="CVE-2024-0001", cvss=7.5, severity="HIGH")
    db.add(f)
    db.commit()

    summary = score_findings(db, [f])
    assert summary["total_risk_score"] == 7.5
    # 7.5 < 20 → LOW band by worst-finding rule (intentional: an SBOM with a
    # single non-amplified high CVE is not in itself a CRITICAL situation).
    assert summary["risk_band"] == "LOW"
    assert summary["worst_finding"]["score"] == 7.5
    assert summary["kev_count"] == 0


def test_severity_fallback_when_score_missing():
    """A CRITICAL with score=NULL falls back to 9.5 in the formula."""
    db = _new_db()
    run = _seed_run(db)
    f = _make_finding(run_id=run.id, vuln_id="CVE-2024-0002", cvss=None, severity="CRITICAL")
    db.add(f)
    db.commit()

    summary = score_findings(db, [f])
    assert summary["total_risk_score"] == 9.5  # severity-mapped fallback


def test_epss_amplifies(monkeypatch):
    """CVSS=8.0, EPSS=0.5 → 8.0 * (1 + 5*0.5) = 8.0 * 3.5 = 28.0."""
    db = _new_db()
    run = _seed_run(db)
    f = _make_finding(run_id=run.id, vuln_id="CVE-2024-0003", cvss=8.0, severity="HIGH")
    db.add(f)
    db.commit()

    monkeypatch.setattr(
        risk_score, "get_epss_scores_memoized", lambda db, ids: {"CVE-2024-0003": 0.5}
    )
    summary = score_findings(db, [f])
    assert summary["total_risk_score"] == pytest.approx(28.0, rel=1e-3)
    # 28 >= 20 → MEDIUM
    assert summary["risk_band"] == "MEDIUM"


def test_kev_doubles_and_critical_band(monkeypatch):
    """CVSS=9.0 + KEV → 9.0 * 1 * 2 = 18.0; KEV+CVSS>=9 forces CRITICAL band."""
    db = _new_db()
    run = _seed_run(db)
    f = _make_finding(run_id=run.id, vuln_id="CVE-2024-0004", cvss=9.0, severity="CRITICAL")
    db.add(f)
    db.commit()

    monkeypatch.setattr(
        risk_score, "lookup_kev_set_memoized", lambda db, ids: {"CVE-2024-0004"}
    )
    summary = score_findings(db, [f])
    assert summary["total_risk_score"] == pytest.approx(18.0, rel=1e-3)
    # Worst-score 18 < 80, but the KEV+CVSS>=9 branch promotes to CRITICAL.
    assert summary["risk_band"] == "CRITICAL"
    assert summary["worst_finding"]["in_kev"] is True
    assert summary["kev_count"] == 1


def test_kev_and_epss_compound(monkeypatch):
    """CVSS=10, EPSS=0.9, KEV → 10 * (1+5*0.9) * 2 = 10 * 5.5 * 2 = 110."""
    db = _new_db()
    run = _seed_run(db)
    f = _make_finding(
        run_id=run.id, vuln_id="CVE-2021-44228", cvss=10.0, severity="CRITICAL"
    )
    db.add(f)
    db.commit()

    monkeypatch.setattr(
        risk_score, "lookup_kev_set_memoized", lambda db, ids: {"CVE-2021-44228"}
    )
    monkeypatch.setattr(
        risk_score, "get_epss_scores_memoized", lambda db, ids: {"CVE-2021-44228": 0.9}
    )
    summary = score_findings(db, [f])
    assert summary["total_risk_score"] == pytest.approx(110.0, rel=1e-3)
    assert summary["risk_band"] == "CRITICAL"


def test_aliases_are_searched_for_cves(monkeypatch):
    """A GHSA finding whose KEV-listed CVE lives in `aliases` still gets boosted."""
    db = _new_db()
    run = _seed_run(db)
    # vuln_id is a GHSA, not a CVE — KEV is only keyed on CVE.
    f = _make_finding(
        run_id=run.id,
        vuln_id="GHSA-jfh8-c2jp-5v3q",
        cvss=10.0,
        severity="CRITICAL",
        aliases='["CVE-2021-44228"]',
    )
    db.add(f)
    db.commit()

    monkeypatch.setattr(
        risk_score, "lookup_kev_set_memoized", lambda db, ids: {"CVE-2021-44228"}
    )
    summary = score_findings(db, [f])
    # Without alias-search this would be 10; with it, KEV doubles to 20.
    assert summary["total_risk_score"] == pytest.approx(20.0, rel=1e-3)
    assert summary["worst_finding"]["in_kev"] is True


def test_per_component_aggregation_and_sort():
    """Multiple findings on the same component sum; sort by component_score desc."""
    db = _new_db()
    run = _seed_run(db)
    findings = [
        _make_finding(run_id=run.id, vuln_id="CVE-2024-1001", cvss=8.0, severity="HIGH", component="A"),
        _make_finding(run_id=run.id, vuln_id="CVE-2024-1002", cvss=4.0, severity="MEDIUM", component="A"),
        _make_finding(run_id=run.id, vuln_id="CVE-2024-1003", cvss=9.0, severity="CRITICAL", component="B"),
    ]
    db.add_all(findings)
    db.commit()

    summary = score_findings(db, findings)
    # Component A: 8 + 4 = 12; component B: 9 → A sorts first.
    assert [c["name"] for c in summary["components"]] == ["A", "B"]
    assert summary["components"][0]["component_score"] == 12.0
    assert summary["components"][1]["component_score"] == 9.0
    assert summary["total_risk_score"] == 21.0


def test_methodology_is_returned():
    db = _new_db()
    summary = score_findings(db, [])
    m = summary["methodology"]
    assert m["version"] == "2.0.0"
    assert "cvss" in m["formula"].lower()
    assert "epss" in m["formula"].lower()
    assert "kev" in m["formula"].lower()
    assert "CRITICAL" in m["bands"]
    assert m["sources"]["epss"].startswith("FIRST.org")


def test_band_thresholds_at_boundaries(monkeypatch):
    """Boundary check on the worst-finding-driven band."""
    db = _new_db()
    run = _seed_run(db)

    # CVE IDs must match CVE-YYYY-NNNN[N..] regex to be picked up by the EPSS
    # lookup; otherwise the lookup is a no-op and EPSS=0 by default.
    f = _make_finding(run_id=run.id, vuln_id="CVE-2024-0099", cvss=10.0, severity="CRITICAL")
    db.add(f)
    db.commit()

    # CVSS=10, EPSS=0.8 → 10 * (1 + 5*0.8) = 50.0 → HIGH
    monkeypatch.setattr(
        risk_score, "get_epss_scores_memoized", lambda db, ids: {"CVE-2024-0099": 0.8}
    )
    summary = score_findings(db, [f])
    assert summary["worst_finding"]["score"] == pytest.approx(50.0, rel=1e-3)
    assert summary["risk_band"] == "HIGH"

    # CVSS=10, EPSS=1.0 → 10 * 6 = 60 — still HIGH, NOT CRITICAL without KEV.
    monkeypatch.setattr(
        risk_score, "get_epss_scores_memoized", lambda db, ids: {"CVE-2024-0099": 1.0}
    )
    summary = score_findings(db, [f])
    assert summary["worst_finding"]["score"] == pytest.approx(60.0, rel=1e-3)
    assert summary["risk_band"] == "HIGH"


# ---------------------------------------------------------------------
# KEV/EPSS source modules
# ---------------------------------------------------------------------


def test_kev_lookup_with_seeded_table():
    """
    The lookup helper should match against whatever's in the local mirror,
    independent of the network. Refresh-if-stale is short-circuited by
    inserting a row dated "now".
    """
    from datetime import datetime, timezone

    from app.sources.kev import lookup_kev_set

    db = _new_db()
    db.add(
        KevEntry(
            cve_id="CVE-2021-44228",
            refreshed_at=datetime.now(timezone.utc).replace(microsecond=0).isoformat(),
        )
    )
    db.commit()

    # Disable the network refresh path — the seeded row is fresh, so it
    # shouldn't trigger one anyway, but be defensive.
    result = lookup_kev_set(db, ["CVE-2021-44228", "CVE-2024-9999"])
    assert result == {"CVE-2021-44228"}


def test_epss_falls_back_to_zero_on_cache_miss(monkeypatch):
    """
    A CVE with no row in `epss_score` and a network-disabled fetcher
    should be returned as 0.0 (no row inserted).
    """
    from app.sources import epss as epss_mod

    monkeypatch.setattr(epss_mod, "_fetch_batch", lambda ids: {})
    db = _new_db()
    result = epss_mod.get_epss_scores(db, ["CVE-2024-FAKE"])
    assert result == {"CVE-2024-FAKE": 0.0}
    # Nothing got cached — no junk row written.
    assert db.query(EpssScore).count() == 0

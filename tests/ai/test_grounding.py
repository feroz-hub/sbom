"""GroundingContext builder tests against the real DB schema.

Builds a minimal :class:`AnalysisRun` + :class:`AnalysisFinding` +
:class:`SBOMComponent` graph in the test DB so we exercise the actual
queries the orchestrator will run in production.
"""

from __future__ import annotations

import json

import pytest
from app.ai.grounding import build_grounding_context
from app.db import SessionLocal
from app.models import (
    AnalysisFinding,
    AnalysisRun,
    CveCache,
    EpssScore,
    KevEntry,
    SBOMComponent,
    SBOMSource,
)


@pytest.fixture()
def _seeded_finding(client):  # pragma: no cover — fixture wiring
    db = SessionLocal()
    try:
        # Cleanup
        db.query(AnalysisFinding).delete()
        db.query(AnalysisRun).delete()
        db.query(SBOMComponent).delete()
        db.query(SBOMSource).delete()
        db.query(CveCache).delete()
        db.query(KevEntry).delete()
        db.query(EpssScore).delete()
        db.commit()

        sbom = SBOMSource(sbom_name="test", sbom_data=None, sbom_type=None)
        db.add(sbom)
        db.flush()
        component = SBOMComponent(
            sbom_id=sbom.id,
            name="org.apache.logging.log4j:log4j-core",
            version="2.16.0",
            purl="pkg:maven/org.apache.logging.log4j/log4j-core@2.16.0",
            cpe="cpe:2.3:a:apache:log4j:2.16.0:*:*:*:*:*:*:*",
        )
        db.add(component)
        db.flush()
        run = AnalysisRun(
            sbom_id=sbom.id,
            run_status="OK",
            sbom_name="test",
            source="NVD",
            started_on="2026-01-01T00:00:00Z",
            completed_on="2026-01-01T00:00:01Z",
        )
        db.add(run)
        db.flush()
        finding = AnalysisFinding(
            analysis_run_id=run.id,
            component_id=component.id,
            vuln_id="CVE-2021-44832",
            source="NVD",
            title="log4j RCE",
            description="Apache Log4j2 RCE via JDBC Appender.",
            severity="critical",
            score=9.0,
            vector="CVSS:3.1/AV:N/AC:H/PR:H/UI:N/S:U/C:H/I:H/A:H",
            cpe=component.cpe,
            component_name=component.name,
            component_version=component.version,
            fixed_versions=json.dumps(["2.17.1", "2.12.4"]),
            cwe=json.dumps(["CWE-502"]),
            aliases=json.dumps(["GHSA-jfh8-c2jp-5v3q"]),
        )
        db.add(finding)
        db.commit()

        yield finding.id
    finally:
        db.close()


def test_grounding_from_finding_only(_seeded_finding):
    db = SessionLocal()
    try:
        f = db.query(AnalysisFinding).filter_by(id=_seeded_finding).one()
        ctx = build_grounding_context(f, db=db)
    finally:
        db.close()

    assert ctx.cve_id == "CVE-2021-44832"
    assert ctx.severity == "critical"
    assert ctx.cvss_v3_score == 9.0
    assert ctx.cwe_ids == ["CWE-502"]
    assert ctx.component.purl.startswith("pkg:maven/")
    # Falls back to finding.fixed_versions when cve_cache is empty.
    fixed_in = [fv.fixed_in for fv in ctx.fix_versions]
    assert fixed_in == ["2.17.1", "2.12.4"]
    assert "fix_version_data" in ctx.sources_used


def test_grounding_pulls_kev_and_epss(_seeded_finding):
    db = SessionLocal()
    try:
        db.add(KevEntry(cve_id="CVE-2021-44832", refreshed_at="2026-01-01T00:00:00Z"))
        db.add(
            EpssScore(
                cve_id="CVE-2021-44832",
                epss=0.97,
                percentile=1.0,
                refreshed_at="2026-01-01T00:00:00Z",
            )
        )
        db.commit()
        f = db.query(AnalysisFinding).filter_by(id=_seeded_finding).one()
        ctx = build_grounding_context(f, db=db)
    finally:
        db.close()

    assert ctx.kev_listed is True
    assert ctx.epss_score == 0.97
    assert ctx.epss_percentile == 1.0
    assert "kev" in ctx.sources_used
    assert "epss" in ctx.sources_used


def test_grounding_prefers_cve_cache_payload(_seeded_finding):
    db = SessionLocal()
    try:
        db.add(
            CveCache(
                cve_id="CVE-2021-44832",
                payload={
                    "summary": "Merged summary from cve_cache.",
                    "fix_versions": [
                        {"ecosystem": "Maven", "package": "log4j-core", "fixed_in": "2.17.1"},
                    ],
                    "exploitation": {
                        "cisa_kev_listed": True,
                        "cisa_kev_due_date": "2022-06-30",
                        "epss_score": 0.97,
                        "epss_percentile": 1.0,
                    },
                    "sources_used": ["osv", "nvd", "kev", "epss"],
                    "references": [{"url": "https://logging.apache.org/log4j/2.x/security.html", "type": "advisory"}],
                },
                sources_used="osv,nvd,kev,epss",
                fetched_at="2026-01-01T00:00:00Z",
                expires_at="2099-01-01T00:00:00Z",
            )
        )
        db.commit()
        f = db.query(AnalysisFinding).filter_by(id=_seeded_finding).one()
        ctx = build_grounding_context(f, db=db)
    finally:
        db.close()

    assert ctx.cve_summary_from_db == "Merged summary from cve_cache."
    assert [fv.fixed_in for fv in ctx.fix_versions] == ["2.17.1"]
    assert ctx.kev_listed is True
    assert ctx.references == ["https://logging.apache.org/log4j/2.x/security.html"]
    assert "osv" in ctx.sources_used


def test_grounding_handles_no_fix_data():
    db = SessionLocal()
    try:
        db.query(AnalysisFinding).delete()
        db.query(AnalysisRun).delete()
        db.commit()

        sbom = SBOMSource(sbom_name="test2")
        db.add(sbom)
        db.flush()
        run = AnalysisRun(
            sbom_id=sbom.id,
            run_status="OK",
            source="NVD",
            started_on="2026-01-01T00:00:00Z",
            completed_on="2026-01-01T00:00:01Z",
        )
        db.add(run)
        db.flush()
        finding = AnalysisFinding(
            analysis_run_id=run.id,
            vuln_id="CVE-NO-FIX",
            source="NVD",
            severity="HIGH",
            score=7.8,
            component_name="some-pkg",
            component_version="1.0.0",
            fixed_versions=None,
        )
        db.add(finding)
        db.commit()
        ctx = build_grounding_context(finding, db=db)
    finally:
        db.close()

    assert ctx.fix_versions == []
    assert "fix_version_data" not in ctx.sources_used

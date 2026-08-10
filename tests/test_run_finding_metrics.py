from __future__ import annotations

import json
import os
import subprocess
import sys

import pytest


@pytest.fixture()
def db(client):
    from app.db import SessionLocal

    session = SessionLocal()
    try:
        yield session
    finally:
        session.rollback()
        session.close()


def _now() -> str:
    return "2026-07-03T00:00:00Z"


def _seed_sbom(db, name: str = "metrics-sbom"):
    from app.models import SBOMSource

    sbom = SBOMSource(
        sbom_name=name,
        sbom_data=json.dumps({"bomFormat": "CycloneDX", "components": []}),
        status="validated",
        created_by="metrics-test",
    )
    db.add(sbom)
    db.commit()
    db.refresh(sbom)
    return sbom


def test_persist_run_deduplicates_same_cve_from_multiple_sources(client, db):
    from app.services.analysis_service import persist_analysis_run

    sbom = _seed_sbom(db, "same-cve-same-component")
    components = [
        {
            "name": "openssl",
            "version": "3.0.0",
            "purl": "pkg:generic/openssl@3.0.0",
        }
    ]
    details = {
        "total_components": 1,
        "components_with_cpe": 0,
        "total_findings": 2,
        "analysis_metadata": {"raw_observation_count": 2},
        "findings": [
            {
                "vuln_id": "CVE-2026-1000",
                "aliases": ["GHSA-abcd-efgh-ijkl"],
                "sources": ["NVD"],
                "severity": "HIGH",
                "applicability_status": "affected",
                "component_name": "openssl",
                "component_version": "3.0.0",
            },
            {
                "vuln_id": "GHSA-abcd-efgh-ijkl",
                "aliases": ["CVE-2026-1000"],
                "sources": ["OSV"],
                "severity": "MEDIUM",
                "applicability_status": "affected",
                "component_name": "openssl",
                "component_version": "3.0.0",
            },
        ],
    }

    run = persist_analysis_run(
        db=db,
        sbom_obj=sbom,
        details=details,
        components=components,
        run_status="FINDINGS",
        source="NVD,OSV",
        started_on=_now(),
        completed_on=_now(),
        duration_ms=1,
    )
    db.commit()
    db.refresh(run)

    assert run.total_findings == 1
    assert run.high_count == 1
    assert run.medium_count == 0

    body = client.get(f"/api/runs/{run.id}").json()
    assert body["metrics"]["raw_observation_count"] == 2
    assert body["metrics"]["total_findings"] == 1
    assert body["metrics"]["unique_vulnerabilities"] == 1
    assert sum(body["metrics"]["severity_counts"].values()) == 1

    resp = client.get(f"/api/runs/{run.id}/findings-enriched?page_size=50")
    assert resp.headers["X-Total-Count"] == "1"
    findings = resp.json()
    assert len(findings) == 1
    assert findings[0]["vuln_id"] == "CVE-2026-1000"
    assert set(findings[0]["source"].split(",")) == {"NVD", "OSV"}


def test_same_cve_on_two_components_counts_two_findings(db):
    from app.metrics.findings import canonical_finding_metrics_for_run
    from app.models import AnalysisFinding, AnalysisRun, SBOMComponent

    sbom = _seed_sbom(db, "same-cve-two-components")
    comp_a = SBOMComponent(sbom_id=sbom.id, name="openssl", version="3.0.0")
    comp_b = SBOMComponent(sbom_id=sbom.id, name="libssl", version="3.0.0")
    db.add_all([comp_a, comp_b])
    db.flush()
    run = AnalysisRun(
        sbom_id=sbom.id,
        run_status="FINDINGS",
        source="TEST",
        started_on=_now(),
        completed_on=_now(),
        duration_ms=1,
        total_components=2,
        components_with_cpe=0,
        total_findings=2,
    )
    db.add(run)
    db.flush()
    db.add_all(
        [
            AnalysisFinding(
                analysis_run_id=run.id,
                component_id=comp_a.id,
                vuln_id="CVE-2026-2000",
                severity="HIGH",
                component_name="openssl",
                component_version="3.0.0",
            ),
            AnalysisFinding(
                analysis_run_id=run.id,
                component_id=comp_b.id,
                vuln_id="CVE-2026-2000",
                severity="HIGH",
                component_name="libssl",
                component_version="3.0.0",
            ),
        ]
    )
    db.commit()

    metrics = canonical_finding_metrics_for_run(db, run=run)
    assert metrics.total_findings == 2
    assert metrics.unique_vulnerabilities == 1
    assert metrics.severity_counts["high"] == 2


def test_run_detail_and_enriched_endpoint_collapse_existing_duplicate_rows(client, db):
    from app.models import AnalysisFinding, AnalysisRun, SBOMComponent

    sbom = _seed_sbom(db, "stale-duplicates")
    component = SBOMComponent(sbom_id=sbom.id, name="log4j-core", version="2.14.1")
    db.add(component)
    db.flush()
    run = AnalysisRun(
        sbom_id=sbom.id,
        run_status="FINDINGS",
        source="NVD,OSV",
        started_on=_now(),
        completed_on=_now(),
        duration_ms=1,
        total_components=1,
        components_with_cpe=0,
        total_findings=2,
        high_count=2,
        raw_report=json.dumps({"total_findings": 2}),
    )
    db.add(run)
    db.flush()
    db.add_all(
        [
            AnalysisFinding(
                analysis_run_id=run.id,
                component_id=component.id,
                vuln_id="CVE-2026-3000",
                source="NVD",
                severity="HIGH",
                component_name="log4j-core",
                component_version="2.14.1",
            ),
            AnalysisFinding(
                analysis_run_id=run.id,
                component_id=component.id,
                vuln_id="GHSA-mnop-qrst-uvwx",
                aliases=json.dumps(["CVE-2026-3000"]),
                source="OSV",
                severity="MEDIUM",
                component_name="log4j-core",
                component_version="2.14.1",
            ),
        ]
    )
    db.commit()

    body = client.get(f"/api/runs/{run.id}").json()
    assert body["total_findings"] == 2
    assert body["metrics"]["raw_observation_count"] == 2
    assert body["metrics"]["total_findings"] == 1
    assert body["metrics"]["severity_counts"]["high"] == 1

    resp = client.get(f"/api/runs/{run.id}/findings-enriched?page_size=50")
    assert resp.headers["X-Total-Count"] == "1"
    assert resp.headers["X-Unfiltered-Total-Count"] == "1"
    rows = resp.json()
    assert len(rows) == 1
    assert set(rows[0]["source"].split(",")) == {"NVD", "OSV"}

    estimate = client.post(f"/api/v1/runs/{run.id}/ai-fixes/estimate", json={"scope": None}).json()
    assert estimate["total_findings_in_scope"] == 1


def test_reconcile_script_updates_stale_cached_counts(client, db):
    from app.models import AnalysisFinding, AnalysisRun, SBOMComponent

    sbom = _seed_sbom(db, "reconcile-stale")
    component = SBOMComponent(sbom_id=sbom.id, name="pkg", version="1.0.0")
    db.add(component)
    db.flush()
    run = AnalysisRun(
        sbom_id=sbom.id,
        run_status="FINDINGS",
        source="TEST",
        started_on=_now(),
        completed_on=_now(),
        duration_ms=1,
        total_components=1,
        components_with_cpe=0,
        total_findings=2,
        high_count=2,
        raw_report=json.dumps({"total_findings": 2}),
    )
    db.add(run)
    db.flush()
    db.add_all(
        [
            AnalysisFinding(
                analysis_run_id=run.id,
                component_id=component.id,
                vuln_id="CVE-2026-4000",
                severity="HIGH",
                component_name="pkg",
                component_version="1.0.0",
            ),
            AnalysisFinding(
                analysis_run_id=run.id,
                component_id=component.id,
                vuln_id="CVE-2026-4000",
                severity="HIGH",
                component_name="pkg",
                component_version="1.0.0",
            ),
        ]
    )
    db.commit()

    env = os.environ.copy()
    database_url = db.get_bind().url.render_as_string(hide_password=False)
    env["DATABASE_URL"] = database_url
    env["TEST_DATABASE_URL"] = database_url
    env["TEST_POSTGRES_DATABASE_URL"] = database_url
    dry = subprocess.run(
        [sys.executable, "scripts/reconcile_analysis_run_finding_counts.py", "--run-id", str(run.id), "--dry-run"],
        cwd=os.getcwd(),
        env=env,
        text=True,
        capture_output=True,
        check=True,
    )
    assert "stored findings_count: 2" in dry.stdout
    assert "canonical findings: 1" in dry.stdout
    assert "updated: no" in dry.stdout

    applied = subprocess.run(
        [sys.executable, "scripts/reconcile_analysis_run_finding_counts.py", "--run-id", str(run.id), "--apply"],
        cwd=os.getcwd(),
        env=env,
        text=True,
        capture_output=True,
        check=True,
    )
    assert "updated: yes" in applied.stdout

    db.expire_all()
    fresh = db.get(AnalysisRun, run.id)
    assert fresh.total_findings == 1
    assert fresh.high_count == 1

    second = subprocess.run(
        [sys.executable, "scripts/reconcile_analysis_run_finding_counts.py", "--run-id", str(run.id), "--apply"],
        cwd=os.getcwd(),
        env=env,
        text=True,
        capture_output=True,
        check=True,
    )
    assert "updated: no" in second.stdout

"""Portfolio vulnerability listing, grouped by ownership.

The dashboard severity pie is portfolio-scoped but its click used to route to
a single analysis run, so the destination showed a fraction of the number the
user had clicked. These tests lock the property that fixes it: the grouped
list and the severity distribution are the same scope, so their counts agree
per severity bucket and in total.
"""

from __future__ import annotations

from datetime import UTC, datetime

import pytest
from app import metrics
from app.db import SessionLocal
from app.metrics.cache import reset_cache
from app.models import AnalysisFinding, AnalysisRun, Product, Projects, SBOMSource


def _now() -> str:
    return datetime.now(UTC).isoformat()


@pytest.fixture()
def db(client):
    session = SessionLocal()
    try:
        yield session
    finally:
        session.rollback()
        session.close()


def _seed(db, *, severities: list[str], project_name: str, product_name: str) -> dict:
    """One project → product → SBOM → completed run with the given findings."""
    reset_cache()
    project = Projects(project_name=project_name, created_by="alice", project_status=1, created_on=_now())
    db.add(project)
    db.flush()

    product = Product(
        project_id=project.id,
        name=product_name,
        normalized_name=product_name.lower(),
        slug=product_name.lower().replace(" ", "-"),
        created_by="alice",
        created_at=_now(),
        updated_at=_now(),
    )
    db.add(product)
    db.flush()

    sbom = SBOMSource(
        sbom_name=f"{product_name} sbom",
        sbom_data="{}",
        status="validated",
        projectid=project.id,
        product_id=product.id,
        created_by="alice",
        created_on=_now(),
    )
    db.add(sbom)
    db.flush()

    run = AnalysisRun(
        sbom_id=sbom.id,
        project_id=project.id,
        product_id=product.id,
        tenant_id=sbom.tenant_id,
        run_status="FINDINGS",
        source="NVD",
        sbom_name=sbom.sbom_name,
        started_on=_now(),
        completed_on=_now(),
        total_findings=len(severities),
    )
    db.add(run)
    db.flush()

    for i, severity in enumerate(severities):
        db.add(
            AnalysisFinding(
                analysis_run_id=run.id,
                tenant_id=run.tenant_id,
                vuln_id=f"CVE-2026-{run.id:04d}{i:02d}",
                severity=severity,
                score=7.5,
                component_name="lodash",
                component_version="4.17.15",
            )
        )
    db.commit()
    reset_cache()
    return {"project": project, "product": product, "sbom": sbom, "run": run}


def test_grouped_list_total_matches_severity_distribution(client, db):
    """The number on a pie slice is the number the grouped list reports."""
    _seed(db, severities=["HIGH", "HIGH", "CRITICAL", "LOW"], project_name="Alpha", product_name="Gateway")

    distribution = metrics.findings_latest_per_sbom_severity_distribution(db)
    for bucket, expected in distribution.items():
        listed = metrics.findings_latest_per_sbom_grouped_by_scope(db, severity=bucket, limit=1)
        assert listed["total"] == expected, f"{bucket}: list={listed['total']} distribution={expected}"

    unfiltered = metrics.findings_latest_per_sbom_grouped_by_scope(db, limit=1)
    assert unfiltered["total"] == metrics.findings_latest_per_sbom_total(db)


def test_rows_carry_project_and_product_attribution(client, db):
    seeded = _seed(db, severities=["HIGH"], project_name="Beta", product_name="Pump Controller")

    result = metrics.findings_latest_per_sbom_grouped_by_scope(db, severity="high", limit=100)
    row = next(r for r in result["findings"] if r["sbom_id"] == seeded["sbom"].id)

    assert row["project_name"] == "Beta"
    assert row["product_name"] == "Pump Controller"
    assert row["sbom_name"] == seeded["sbom"].sbom_name
    assert row["run_id"] == seeded["run"].id
    assert row["vuln_id"].startswith("CVE-2026-")


def test_superseded_run_is_excluded(client, db):
    """Only the latest run per SBOM counts — a re-scan replaces, not adds."""
    seeded = _seed(db, severities=["HIGH", "HIGH"], project_name="Gamma", product_name="Monitor")
    sbom = seeded["sbom"]

    before = metrics.findings_latest_per_sbom_grouped_by_scope(db, severity="high", limit=1)["total"]

    newer = AnalysisRun(
        sbom_id=sbom.id,
        project_id=sbom.projectid,
        product_id=sbom.product_id,
        tenant_id=sbom.tenant_id,
        run_status="FINDINGS",
        source="NVD",
        sbom_name=sbom.sbom_name,
        started_on=_now(),
        completed_on=_now(),
        total_findings=1,
    )
    db.add(newer)
    db.flush()
    db.add(
        AnalysisFinding(
            analysis_run_id=newer.id,
            tenant_id=newer.tenant_id,
            vuln_id="CVE-2026-9999",
            severity="HIGH",
            score=9.1,
            component_name="lodash",
            component_version="4.17.15",
        )
    )
    db.commit()
    reset_cache()

    after = metrics.findings_latest_per_sbom_grouped_by_scope(db, severity="high", limit=100)
    # Two findings dropped out with the superseded run, one arrived with the new one.
    assert after["total"] == before - 2 + 1
    assert any(r["vuln_id"] == "CVE-2026-9999" for r in after["findings"])
    assert all(r["run_id"] != seeded["run"].id for r in after["findings"] if r["sbom_id"] == sbom.id)


def test_unknown_severity_is_rejected(client, db):
    with pytest.raises(ValueError):
        metrics.findings_latest_per_sbom_grouped_by_scope(db, severity="catastrophic")


def test_endpoint_returns_grouped_rows_and_rejects_bad_severity(client, db):
    _seed(db, severities=["HIGH", "MEDIUM"], project_name="Delta", product_name="Infuser")

    resp = client.get("/api/vulnerabilities?severity=high&page_size=100")
    assert resp.status_code == 200, resp.text
    body = resp.json()
    assert body["severity"] == "high"
    assert body["total"] >= 1
    assert body["returned"] == len(body["findings"])
    assert {"project_name", "product_name", "sbom_name", "vuln_id"} <= set(body["findings"][0])

    # Ordering contract: descending score, so a truncated page is the worst first.
    scores = [f["score"] or 0 for f in body["findings"]]
    assert scores == sorted(scores, reverse=True)

    bad = client.get("/api/vulnerabilities?severity=catastrophic")
    assert bad.status_code == 422, bad.text


def test_endpoint_pagination_reports_total_before_truncation(client, db):
    _seed(db, severities=["HIGH"] * 5, project_name="Epsilon", product_name="Sensor")

    resp = client.get("/api/vulnerabilities?severity=high&page_size=2")
    assert resp.status_code == 200, resp.text
    body = resp.json()
    assert body["returned"] == 2
    assert body["total"] >= 5
    assert body["total"] > body["returned"]

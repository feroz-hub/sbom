from __future__ import annotations

import json
from datetime import UTC, datetime

from sqlalchemy import create_engine
from sqlalchemy.orm import Session, sessionmaker

from app.db import Base
from app.models import AnalysisFinding, AnalysisRun, KevEntry, SBOMSource, Tenant
from app.routers.runs import list_run_findings_enriched
from app.services.analysis_service import persist_analysis_run
from app.services.kev_enrichment import enrich_findings_with_kev


def _now_iso() -> str:
    return datetime.now(UTC).replace(microsecond=0).isoformat()


def _new_db() -> Session:
    engine = create_engine("sqlite:///:memory:")
    Base.metadata.create_all(engine)
    return sessionmaker(bind=engine)()


def _seed_tenant(db: Session) -> None:
    if db.get(Tenant, 1) is None:
        db.add(
            Tenant(
                id=1,
                name="Default Tenant",
                slug="default",
                external_iam_tenant_id="local-default",
                status="ACTIVE",
                created_at=datetime.now(UTC),
                updated_at=datetime.now(UTC),
            )
        )
        db.commit()


def test_enrich_findings_with_kev_uses_primary_cve_and_aliases():
    db = _new_db()
    _seed_tenant(db)
    db.add(
        KevEntry(
            cve_id="CVE-2026-45659",
            vendor_project="Acme",
            product="Widget",
            vulnerability_name="Widget bug",
            date_added="2026-01-01",
            required_action="Apply vendor patch",
            due_date="2026-02-01",
            known_ransomware_campaign_use="Known",
            notes="CISA notes",
            cwes=["CWE-79"],
            refreshed_at=_now_iso(),
        )
    )
    primary = AnalysisFinding(
        id=1,
        analysis_run_id=1,
        vuln_id="CVE-2026-45659",
        aliases=None,
        severity="HIGH",
    )
    alias = AnalysisFinding(
        id=2,
        analysis_run_id=1,
        vuln_id="GHSA-abcd-efgh-ijkl",
        aliases=json.dumps(["CVE-2026-45659"]),
        severity="HIGH",
    )
    miss = AnalysisFinding(
        id=3,
        analysis_run_id=1,
        vuln_id="CVE-2026-0001",
        aliases=None,
        severity="LOW",
    )

    enriched = enrich_findings_with_kev(db, [primary, alias, miss])

    assert enriched[1].is_kev is True
    assert enriched[1].matched_cve == "CVE-2026-45659"
    assert enriched[1].required_action == "Apply vendor patch"
    assert enriched[1].ransomware_status == "Known"
    assert enriched[1].vendor_project == "Acme"
    assert enriched[1].product == "Widget"
    assert enriched[1].kev_date_added == "2026-01-01"
    assert enriched[1].kev_due_date == "2026-02-01"
    assert enriched[1].notes == "CISA notes"
    assert enriched[1].cwes == ["CWE-79"]
    assert enriched[2].is_kev is True
    assert enriched[3].is_kev is False


def test_persist_analysis_run_records_kev_metadata_in_raw_report():
    db = _new_db()
    _seed_tenant(db)
    sbom = SBOMSource(
        id=1,
        sbom_name="kev-analysis-sbom",
        sbom_data=json.dumps({"bomFormat": "CycloneDX", "components": []}),
        status="validated",
        created_on=_now_iso(),
    )
    db.add(sbom)
    db.add(
        KevEntry(
            cve_id="CVE-2026-45659",
            vendor_project="Acme",
            product="Widget",
            date_added="2026-01-01",
            due_date="2026-02-01",
            known_ransomware_campaign_use="Unknown",
            refreshed_at=_now_iso(),
        )
    )
    db.commit()

    run = persist_analysis_run(
        db=db,
        sbom_obj=sbom,
        details={
            "total_components": 1,
            "components_with_cpe": 0,
            "total_findings": 1,
            "analysis_metadata": {},
            "findings": [
                {
                    "vuln_id": "CVE-2026-45659",
                    "sources": ["NVD"],
                    "severity": "HIGH",
                    "component_name": "openssl",
                    "component_version": "3.0.0",
                    "applicability_status": "affected",
                }
            ],
        },
        components=[{"name": "openssl", "version": "3.0.0"}],
        run_status="FINDINGS",
        source="NVD",
        started_on=_now_iso(),
        completed_on=_now_iso(),
        duration_ms=1,
    )
    raw_report = json.loads(run.raw_report)
    assert raw_report["metrics"]["kev_findings"] == 1
    assert raw_report["metrics"]["kev_cves"] == ["CVE-2026-45659"]
    assert raw_report["analysis_metadata"]["kev_findings"] == 1
    assert raw_report["analysis_metadata"]["kev_cves"] == ["CVE-2026-45659"]


def test_enriched_findings_api_response_includes_kev_fields():
    db = _new_db()
    _seed_tenant(db)
    sbom = SBOMSource(
        id=1,
        sbom_name="kev-api-sbom",
        sbom_data=json.dumps({"bomFormat": "CycloneDX", "components": []}),
        status="validated",
        created_on=_now_iso(),
    )
    run = AnalysisRun(
        id=1,
        sbom_id=1,
        run_status="FINDINGS",
        source="NVD",
        started_on=_now_iso(),
        completed_on=_now_iso(),
        duration_ms=1,
        total_components=1,
        total_findings=1,
        query_error_count=0,
    )
    finding = AnalysisFinding(
        id=1,
        analysis_run_id=1,
        vuln_id="CVE-2026-45659",
        source="NVD",
        severity="HIGH",
        score=8.0,
        component_name="openssl",
        component_version="3.0.0",
    )
    kev = KevEntry(
        cve_id="CVE-2026-45659",
        vendor_project="Acme",
        product="Widget",
        vulnerability_name="Widget bug",
        date_added="2026-01-01",
        short_description="Short CISA description",
        required_action="Apply vendor patch",
        due_date="2026-02-01",
        known_ransomware_campaign_use="Known",
        notes="CISA notes",
        refreshed_at=_now_iso(),
    )
    db.add_all([sbom, run, finding, kev])
    db.commit()

    rows = list_run_findings_enriched(run_id=1, severity=None, page=1, page_size=50, db=db)

    assert len(rows) == 1
    row = rows[0]
    assert row["in_kev"] is True
    assert row["is_kev"] is True
    assert row["kev_date_added"] == "2026-01-01"
    assert row["kev_due_date"] == "2026-02-01"
    assert row["required_action"] == "Apply vendor patch"
    assert row["vendor_project"] == "Acme"
    assert row["product"] == "Widget"
    assert row["ransomware_status"] == "Known"
    assert row["notes"] == "CISA notes"

from __future__ import annotations

import json
from datetime import UTC, datetime

import pytest

from app.analysis import _augment_components_with_cpe
from app.models import SBOMSource, Tenant
from app.parsing import extract_components
from app.services.analysis_service import persist_analysis_run
from app.services.component_deduplication_service import ComponentDeduplicationService
from app.services.pdf_service import rebuild_run_from_db
from app.services.sbom_service import now_iso


@pytest.fixture()
def db(app):
    from app.db import Base, SessionLocal, engine

    Base.metadata.create_all(bind=engine)
    session = SessionLocal()
    if session.get(Tenant, 1) is None:
        now = datetime.now(UTC)
        session.add(
            Tenant(
                id=1,
                name="Default",
                slug="default",
                external_iam_tenant_id="default",
                status="ACTIVE",
                created_at=now,
                updated_at=now,
            )
        )
        session.commit()
    try:
        yield session
    finally:
        session.rollback()
        session.close()


def test_cyclonedx_pillow_identity_survives_normalization():
    sbom = {
        "bomFormat": "CycloneDX",
        "specVersion": "1.6",
        "components": [
            {
                "bom-ref": "72-pillow@12.2.0",
                "type": "library",
                "name": "pillow",
                "version": "12.2.0",
                "purl": "pkg:pypi/pillow@12.2.0",
            }
        ],
    }
    parsed = extract_components(sbom)
    canonical, _, _, _, _ = ComponentDeduplicationService.deduplicate_components(parsed, [])
    augmented, _ = _augment_components_with_cpe(canonical)

    pillow = augmented[0]
    assert pillow["normalized_name"] == "pillow"
    assert pillow["version"] == "12.2.0"
    assert pillow["ecosystem"].lower() == "pypi"
    assert pillow["purl"] == "pkg:pypi/pillow@12.2.0"
    assert pillow["cpe"] == "cpe:2.3:a:python:pillow:12.2.0:*:*:*:*:*:*:*"
    assert pillow["cpe_source"] == "trusted_mapping"


def test_report_rebuild_displays_component_purl_with_zero_findings(db):
    sbom = {
        "bomFormat": "CycloneDX",
        "specVersion": "1.6",
        "components": [
            {
                "bom-ref": "72-pillow@12.2.0",
                "type": "library",
                "name": "pillow",
                "version": "12.2.0",
                "purl": "pkg:pypi/pillow@12.2.0",
            }
        ],
    }
    row = SBOMSource(sbom_name="purl-report", sbom_data=json.dumps(sbom), status="validated")
    db.add(row)
    db.commit()
    db.refresh(row)

    components = _augment_components_with_cpe(
        ComponentDeduplicationService.deduplicate_components(extract_components(sbom), [])[0]
    )[0]
    run = persist_analysis_run(
        db,
        row,
        {
            "total_components": 1,
            "components_with_cpe": 1,
            "total_findings": 0,
            "critical": 0,
            "high": 0,
            "medium": 0,
            "low": 0,
            "unknown": 0,
            "query_errors": [],
            "findings": [],
        },
        components,
        "OK",
        "MULTI",
        now_iso(),
        now_iso(),
        1,
    )
    db.commit()

    rebuilt = rebuild_run_from_db(db, run.id)
    pillow = next(component for component in rebuilt["components"] if component["name"] == "pillow")
    assert pillow["purl"] == "pkg:pypi/pillow@12.2.0"
    assert len(pillow["combined"]) == 0
    assert rebuilt["summary"]["findings"]["total"] == 0


def test_persistence_rejects_unknown_applicability(db):
    sbom = SBOMSource(sbom_name="unknown-reject", sbom_data="{}", status="validated")
    db.add(sbom)
    db.commit()
    db.refresh(sbom)
    with pytest.raises(AssertionError):
        persist_analysis_run(
            db,
            sbom,
            {
                "total_components": 1,
                "components_with_cpe": 0,
                "total_findings": 1,
                "query_errors": [],
                "findings": [
                    {
                        "vuln_id": "CVE-UNKNOWN",
                        "sources": ["NVD"],
                        "component_name": "pillow",
                        "component_version": "12.2.0",
                        "applicability_status": "unknown",
                    }
                ],
            },
            [{"name": "pillow", "version": "12.2.0", "purl": "pkg:pypi/pillow@12.2.0"}],
            "FINDINGS",
            "NVD",
            now_iso(),
            now_iso(),
            1,
        )

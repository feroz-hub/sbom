from __future__ import annotations

import json
import logging

import pytest
from sqlalchemy import text


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
    return "2026-07-07T00:00:00Z"


def _seed_sbom(db, name: str = "analysis-finding-regression"):
    from app.models import SBOMSource

    sbom = SBOMSource(
        sbom_name=name,
        sbom_data=json.dumps({"bomFormat": "CycloneDX", "components": []}),
        status="validated",
        created_by="analysis-regression-test",
    )
    db.add(sbom)
    db.commit()
    db.refresh(sbom)
    return sbom


def _finding(**overrides):
    data = {
        "vuln_id": "CVE-2026-7000",
        "sources": ["NVD"],
        "severity": "HIGH",
        "score": 8.8,
        "vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
        "component_name": "openssl",
        "component_version": "3.0.0",
        "applicability_status": "affected",
        "match_reason": "matched",
        "matched_range": ">=3.0.0",
        "match_strategy": "cpe_name",
        "attack_vector": "Network",
        "cvss_version": "3.1",
    }
    data.update(overrides)
    return data


def _persist(db, sbom, findings, source: str = "NVD"):
    from app.services.analysis_service import persist_analysis_run

    components = [
        {
            "name": "openssl",
            "version": "3.0.0",
            "purl": "pkg:generic/openssl@3.0.0",
        }
    ]
    return persist_analysis_run(
        db=db,
        sbom_obj=sbom,
        details={
            "total_components": len(components),
            "components_with_cpe": 0,
            "total_findings": len(findings),
            "analysis_metadata": {"raw_observation_count": len(findings)},
            "findings": findings,
        },
        components=components,
        run_status="FINDINGS",
        source=source,
        started_on=_now(),
        completed_on=_now(),
        duration_ms=1,
        correlation_id="test-correlation",
    )


def test_normal_finding_persists_successfully(client, db):
    from app.models import AnalysisFinding

    sbom = _seed_sbom(db, "normal-finding")
    run = _persist(db, sbom, [_finding()])
    db.commit()

    row = db.query(AnalysisFinding).filter(AnalysisFinding.analysis_run_id == run.id).one()
    assert row.vuln_id == "CVE-2026-7000"
    assert row.component_version == "3.0.0"
    assert run.run_status == "FINDINGS"


def test_bulk_insert_persists_long_external_finding_values(client, db):
    from app.models import AnalysisFinding

    sbom = _seed_sbom(db, "long-finding-values")
    long_component_version = "1.0.0-alpha.1+long-build-metadata-1234567890"
    long_range = ">=1.0.0-alpha.1, <2.0.0 || >=3.0.0, <3.5.0"
    long_vector = (
        "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/"
        "SC:H/SI:H/SA:H/E:A/CR:H/IR:H/AR:H/MAV:N/MAC:L/MPR:N/MUI:N"
    )
    long_provider_id = "PYSEC-2026-very-long-provider-identifier-for-regression-1234567890"

    findings = [
        _finding(
            vuln_id=f"CVE-2026-{8000 + idx}",
            component_name=f"component-{idx}",
            component_version="3.0.0",
        )
        for idx in range(270)
    ]
    findings.append(
        _finding(
            vuln_id=long_provider_id,
            sources=["GITHUB", "OSV", "NVD"],
            component_name="component-with-long-version",
            component_version=long_component_version,
            matched_range=long_range,
            vector=long_vector,
            match_strategy="ghsa_alias",
        )
    )

    run = _persist(db, sbom, findings, source="GITHUB,OSV,NVD")
    db.commit()

    rows = db.query(AnalysisFinding).filter(AnalysisFinding.analysis_run_id == run.id).all()
    assert len(rows) == 271
    long_row = next(row for row in rows if row.vuln_id == long_provider_id.upper())
    assert long_row.component_version == long_component_version
    assert long_row.matched_range == long_range
    assert set(long_row.source.split(",")) == {"GITHUB", "OSV", "NVD"}
    assert long_row.vector == long_vector
    assert len(long_row.vuln_id) > len("CVE-2026-8000")


def test_preflush_diagnostic_identifies_all_overflowing_bounded_columns(client, db, caplog):
    from app.services.analysis_service import AnalysisFindingPersistenceValidationError

    sbom = _seed_sbom(db, "overflow-diagnostic")
    caplog.set_level(logging.WARNING, logger="app.services.analysis_service")

    with pytest.raises(AnalysisFindingPersistenceValidationError) as excinfo:
        _persist(
            db,
            sbom,
            [
                _finding(
                    vuln_id="CVE-2026-9000",
                    sources=["SOURCE-" + "X" * 130],
                    component_name="diagnostic-component",
                    match_reason="reason-" + "Y" * 70,
                    match_strategy="strategy-" + "Z" * 70,
                )
            ],
            source="diagnostic",
        )

    fields = {violation["field"] for violation in excinfo.value.violations}
    assert {"source", "match_reason", "match_strategy"}.issubset(fields)
    logged_fields = {
        record.__dict__.get("field")
        for record in caplog.records
        if record.getMessage() == "analysis.finding_column_overflow"
    }
    assert {"source", "match_reason", "match_strategy"}.issubset(logged_fields)
    assert all("Y" * 70 not in record.getMessage() for record in caplog.records)


def test_analysis_finding_orm_lengths_match_postgres_schema(client, db):
    if db.bind.dialect.name != "postgresql":
        pytest.skip("information_schema length assertion is PostgreSQL-specific")

    from app.models import AnalysisFinding
    from sqlalchemy import inspect
    from sqlalchemy.sql.sqltypes import String, Text

    orm_columns = {}
    for column in inspect(AnalysisFinding).columns:
        if isinstance(column.type, Text):
            orm_columns[column.name] = None
        elif isinstance(column.type, String):
            orm_columns[column.name] = column.type.length

    rows = db.execute(
        text(
            """
            SELECT column_name, data_type, character_maximum_length
            FROM information_schema.columns
            WHERE table_schema = 'public'
              AND table_name = 'analysis_finding'
            """
        )
    ).mappings()
    db_columns = {row["column_name"]: row for row in rows}

    for name, orm_length in orm_columns.items():
        db_row = db_columns[name]
        if db_row["data_type"] == "text":
            db_length = None
        else:
            db_length = db_row["character_maximum_length"]
        assert db_length == orm_length, f"{name}: ORM length {orm_length}, DB length {db_length}"

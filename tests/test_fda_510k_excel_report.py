from __future__ import annotations

import json
from io import BytesIO
from uuid import uuid4

import pytest
from app.db import SessionLocal
from app.models import AnalysisFinding, AnalysisRun, Projects, SBOMComponent, SBOMSource
from openpyxl import load_workbook

EXCEL_MEDIA_TYPE = "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet"


@pytest.fixture()
def db(client):
    session = SessionLocal()
    try:
        yield session
    finally:
        session.close()


def _metadata() -> dict:
    return {
        "device_name": "Infusion Controller",
        "device_model_catalog_number": "IC-510K",
        "manufacturer_sponsor": "Acme Medical",
        "submission_type": "510(k)",
        "submission_number": "K260001",
        "product_code_regulation_number": "XYZ / 21 CFR 880.5725",
        "device_software_version": "9.4.1",
        "top_level_primary_component": "Infusion Controller Firmware",
        "author_of_sbom_data": "Build Pipeline",
        "sbom_version": "2026.07",
        "sbom_formats_for_submission": "CycloneDX / SPDX (machine-readable) + this workbook",
        "sbom_generation_tool_and_version": "Syft 1.2.3",
        "primary_data_source": "Persisted SBOM analysis results",
        "prepared_by": "Regulatory Ops",
        "date_prepared": "2026-07-03",
        "reviewed_approved_by": "Quality Lead",
        "date_approved": "2026-07-03",
    }


def _seed_ready_sbom(db):
    token = uuid4().hex[:8]
    project = Projects(project_name=f"FDA Project {token}", project_status=1)
    db.add(project)
    db.flush()
    raw = {
        "bomFormat": "CycloneDX",
        "components": [
            {
                "bom-ref": "pkg:maven/org.example/crypto-core@1.0.0",
                "name": "crypto-core",
                "version": "1.0.0",
            }
        ],
        "dependencies": [{"ref": "device-app", "dependsOn": ["pkg:maven/org.example/crypto-core@1.0.0"]}],
    }
    sbom = SBOMSource(
        sbom_name=f"FDA SBOM {token}",
        sbom_data=json.dumps(raw),
        projectid=project.id,
        sbom_version="2026.07",
        productver="9.4.1",
        product_name="Infusion Controller Firmware",
        created_by="Build Pipeline",
    )
    db.add(sbom)
    db.flush()
    component = SBOMComponent(
        sbom_id=sbom.id,
        bom_ref="pkg:maven/org.example/crypto-core@1.0.0",
        name="crypto-core",
        version="1.0.0",
        supplier="Example Software",
        purl="pkg:maven/org.example/crypto-core@1.0.0",
        normalized_purl="pkg:maven/org.example/crypto-core@1.0.0",
        component_type="Library",
        license="Apache-2.0",
        lifecycle_status="EOL",
        maintenance_status="No longer maintained",
        eos_date="2026-12-31",
        eol_date="2027-01-31",
        lifecycle_recommendation="Upgrade to crypto-core 1.2.0 before EOS.",
        lifecycle_checked_at="2026-07-03T00:00:00Z",
        lifecycle_source="Unit Test",
    )
    db.add(component)
    db.flush()
    run = AnalysisRun(
        sbom_id=sbom.id,
        project_id=project.id,
        run_status="FINDINGS",
        sbom_name=sbom.sbom_name,
        source="stored-test-data",
        started_on="2026-07-03T08:00:00Z",
        completed_on="2026-07-03T08:01:00Z",
        total_components=1,
        total_findings=1,
        high_count=1,
    )
    db.add(run)
    db.flush()
    db.add(
        AnalysisFinding(
            analysis_run_id=run.id,
            component_id=component.id,
            vuln_id="CVE-2026-12345",
            source="NVD",
            title="Stored vulnerability",
            severity="HIGH",
            score=8.1,
            vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
            published_on="2026-07-01T00:00:00Z",
            component_name=component.name,
            component_version=component.version,
            fixed_versions=json.dumps(["1.2.0"]),
            cpe="cpe:2.3:a:example:crypto-core:1.0.0:*:*:*:*:*:*:*",
        )
    )
    db.commit()
    return project, sbom


def _post_export(client, project_id: int, sbom_id: int):
    return client.post(
        f"/api/projects/{project_id}/reports/fda-510k-sbom/export",
        json={"selections": [{"sbom_id": sbom_id}], "metadata": _metadata()},
    )


def test_fda_510k_export_uses_template_and_removes_examples(client, db):
    project, sbom = _seed_ready_sbom(db)

    response = _post_export(client, project.id, sbom.id)

    assert response.status_code == 200, response.text
    assert response.headers["content-type"] == EXCEL_MEDIA_TYPE
    assert "FDA_510k_SBOM_Report" in response.headers["content-disposition"]

    workbook = load_workbook(BytesIO(response.content), data_only=False)
    assert workbook.sheetnames == [
        "Instructions",
        "SBOM Metadata",
        "SBOM Components",
        "Environment & 3rd-Party Deps",
        "Vulnerabilities & VEX",
        "Lifecycle & Support Plan",
        "Supplier & Security Contacts",
        "FDA Compliance Dashboard",
    ]
    assert workbook.calculation.calcMode == "auto"
    assert workbook.calculation.fullCalcOnLoad is True
    assert workbook.calculation.forceFullCalc is True

    # Metadata rows shifted when the template gained the author block (16-18)
    # and the manufacturer security-contact block (26-28).
    metadata = workbook["SBOM Metadata"]
    assert metadata["C5"].value == "Infusion Controller"
    assert metadata["C19"].is_date, "SBOM Timestamp moved from C16 to C19"
    assert metadata["C32"].is_date, "Date Prepared moved from C24 to C32"

    components = workbook["SBOM Components"]
    assert components["A3"].value == 1
    assert components["B3"].value == "crypto-core"
    assert components["E3"].value == "PURL"
    assert components["F3"].value == "pkg:maven/org.example/crypto-core@1.0.0"
    assert components["T3"].is_date, "EOS date moved from L to T"
    # Days to EOS / Lifecycle Flag are template formulas keyed on T. Writing a
    # value into either would break the Compliance Dashboard that reads them.
    assert components["V3"].value == '=IF(T3="","",T3-TODAY())'
    assert components["W3"].value.startswith('=IF(T3="","",IF(T3<TODAY()')

    vulnerabilities = workbook["Vulnerabilities & VEX"]
    assert vulnerabilities["A3"].value == 1
    assert vulnerabilities["B3"].value == "crypto-core"
    assert vulnerabilities["D3"].value == "CVE-2026-12345"
    assert vulnerabilities["H3"].value == "High", "Severity moved from G to H"
    assert vulnerabilities["J3"].value in {"Yes", "No"}, "CISA KEV Status is a Yes/No dropdown"
    assert vulnerabilities["K3"].value in {
        "Not Affected",
        "Affected",
        "Fixed",
        "Under Investigation",
    }, "VEX Status must match the template dropdown"

    lifecycle = workbook["Lifecycle & Support Plan"]
    assert lifecycle["A3"].value == 1
    assert lifecycle["B3"].value == "crypto-core"
    assert lifecycle["F3"].is_date
    assert lifecycle["H3"].value == '=IF(F3="","",F3-TODAY())', "Days to EOS stays a formula"
    assert lifecycle["O3"].value in {"Planned", "In Progress", "Complete", "Risk Accepted"}

    # Supplier & Security Contacts is intentionally left blank for manual
    # completion — the platform holds no PSIRT addresses or CVD policy URLs.
    contacts = workbook["Supplier & Security Contacts"]
    assert contacts["B2"].value == "Supplier / Manufacturer Legal Name", "headers preserved"
    assert all(contacts.cell(row=row, column=col).value is None for row in (3, 4) for col in range(1, 8))

    text_values = [
        str(cell.value)
        for worksheet in [
            workbook["SBOM Components"],
            workbook["Environment & 3rd-Party Deps"],
            workbook["Vulnerabilities & VEX"],
            workbook["Lifecycle & Support Plan"],
            workbook["Supplier & Security Contacts"],
        ]
        for row in worksheet.iter_rows()
        for cell in row
        if cell.value is not None
    ]
    joined = "\n".join(text_values)
    assert "EXAMPLE — replace with your data" not in joined
    assert "\nEX\n" not in f"\n{joined}\n"
    assert "OpenSSL" not in joined
    assert "Linux Kernel" not in joined
    assert "CVE-2024-XXXXX" not in joined
    # Placeholders shipped by the revised template's worked example row.
    assert "example-library" not in joined
    assert "Example Software Foundation" not in joined
    assert "CVE-2026-00000" not in joined
    assert "example-linux-server" not in joined


def test_fda_510k_export_returns_structured_409_for_incomplete_lifecycle(client, db):
    project, sbom = _seed_ready_sbom(db)
    component = db.query(SBOMComponent).filter(SBOMComponent.sbom_id == sbom.id).one()
    component.lifecycle_checked_at = None
    db.commit()

    response = _post_export(client, project.id, sbom.id)

    assert response.status_code == 409
    detail = response.json()["detail"]
    assert detail["code"] == "fda_510k_report_incomplete_analysis"
    assert detail["blockers"] == [
        {
            "sbom_id": sbom.id,
            "sbom_name": sbom.sbom_name,
            "analysis_type": "lifecycle",
            "status": "missing",
        }
    ]

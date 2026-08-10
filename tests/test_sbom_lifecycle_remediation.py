# tests/test_sbom_lifecycle_remediation.py

from __future__ import annotations

import json

import pytest
from app.db import SessionLocal
from app.models import Projects, SBOMComponent, SBOMSource
from app.services.completeness_service import compute_and_save_completeness
from app.services.lifecycle import LifecycleEnrichmentService
from app.services.lifecycle.provider_base import LifecycleProvider
from app.services.lifecycle.types import EOL, HIGH, UNKNOWN, LifecycleResult, NormalizedComponent, unknown_result
from app.services.remediation_service import create_or_update_remediation, get_remediation_for_finding
from app.services.version_control_service import compare_versions, edit_sbom, restore_version
from sqlalchemy import select


@pytest.fixture()
def db(client):
    session = SessionLocal()
    try:
        yield session
    finally:
        session.rollback()
        session.close()


class FakeLifecycleProvider(LifecycleProvider):
    name = "Test Provider"

    def lookup(self, component: NormalizedComponent) -> LifecycleResult:
        if component.normalized_name == "log4j-core":
            return LifecycleResult(
                component_name=component.normalized_name,
                component_version=component.normalized_version,
                ecosystem=component.ecosystem,
                purl=component.purl,
                lifecycle_status=EOL,
                eol_date="2021-12-30",
                eos_date="2021-12-15",
                maintenance_status="End of life",
                source_name=self.name,
                source_url="https://example.test/log4j",
                confidence=HIGH,
            )
        return unknown_result(component, self.name)


def test_lifecycle_provider_resolution(db):
    # Seed a minimal SBOM
    sbom = SBOMSource(sbom_name="lifecycle-test-sbom", sbom_data="{}", status="validated")
    db.add(sbom)
    db.flush()

    comp1 = SBOMComponent(sbom_id=sbom.id, name="log4j-core", version="2.15.0", component_type="library")
    # active component
    comp2 = SBOMComponent(sbom_id=sbom.id, name="some-active-component", version="1.0.0", component_type="library")
    db.add(comp1)
    db.add(comp2)
    db.commit()

    LifecycleEnrichmentService(providers=[FakeLifecycleProvider()]).enrich_sbom(db, sbom.id)

    db.refresh(comp1)
    db.refresh(comp2)

    assert comp1.lifecycle_status == EOL
    assert comp1.eol_date is not None
    assert comp1.lifecycle_source == "Test Provider"
    assert comp2.lifecycle_status == UNKNOWN


def test_completeness_score_calculation(db):
    sbom_data = {
        "bomFormat": "CycloneDX",
        "specVersion": "1.4",
        "components": [
            {
                "name": "pkg1",
                "version": "1.0.0",
                "supplier": {"name": "Supplier A"},
                "licenses": [{"license": {"id": "MIT"}}],
                "hashes": [{"alg": "SHA-256", "content": "somehash"}],
            },
            {"name": "pkg2", "version": "1.0.0", "type": "library"},
        ],
    }
    sbom = SBOMSource(sbom_name="completeness-test-sbom", sbom_data=json.dumps(sbom_data), status="validated")
    db.add(sbom)
    db.flush()

    # Perfect component (has name, version, supplier, license, hashes)
    comp1 = SBOMComponent(
        sbom_id=sbom.id, name="pkg1", version="1.0.0", supplier="Supplier A", license="MIT", hashes="somehash"
    )
    # Component missing license and supplier and hashes
    comp2 = SBOMComponent(sbom_id=sbom.id, name="pkg2", version="1.0.0", component_type="library")
    db.add(comp1)
    db.add(comp2)
    db.commit()

    compute_and_save_completeness(db, sbom)
    db.refresh(sbom)

    # Score should be calculated (between 0 and 100) and stored
    assert sbom.completeness_score is not None
    assert 0 < sbom.completeness_score < 100
    report = (
        json.loads(sbom.completeness_report) if isinstance(sbom.completeness_report, str) else sbom.completeness_report
    )
    assert len(report["missing_fields"]) > 0


def test_sbom_editing_and_versioning(db):
    # Seed a project
    proj = Projects(project_name="edit-test-project", created_by="alice")
    db.add(proj)
    db.flush()

    # Seed a parent SBOM with a mock CycloneDX payload
    sbom_data = {
        "bomFormat": "CycloneDX",
        "specVersion": "1.4",
        "metadata": {"component": {"name": "test-app", "version": "1.0.0"}},
        "components": [
            {
                "bom-ref": "pkg:maven/org.apache.logging.log4j/log4j-core@2.15.0",
                "name": "log4j-core",
                "version": "2.15.0",
            }
        ],
    }

    parent_sbom = SBOMSource(
        sbom_name="edit-target-sbom",
        sbom_data=json.dumps(sbom_data),
        projectid=proj.id,
        sbom_version="1.0.0",
        productver="1.0.0",
        product_name="test-app",
        description="manual product metadata",
        status="validated",
    )
    db.add(parent_sbom)
    db.flush()

    comp = SBOMComponent(
        sbom_id=parent_sbom.id,
        bom_ref="pkg:maven/org.apache.logging.log4j/log4j-core@2.15.0",
        name="log4j-core",
        version="2.15.0",
    )
    db.add(comp)
    db.commit()

    # Apply manual component edit
    updates = {
        "metadata": {},
        "components": [
            {
                "bom_ref": "pkg:maven/org.apache.logging.log4j/log4j-core@2.15.0",
                "name": "log4j-core-edited",
                "version": "2.16.0",
                "supplier": "Apache Foundation",
                "license": "Apache-2.0",
                "hashes": "sha256hashvalue",
                "lifecycle": {
                    "lifecycle_status": "deprecated",
                    "eos_date": "2026-12-31",
                    "eol_date": "2027-12-31",
                    "is_deprecated": True,
                    "maintenance_status": "unmaintained",
                },
            }
        ],
    }

    new_version = edit_sbom(db, parent_sbom.id, user_id="bob", updates=updates, change_summary="Updated log4j version")
    assert new_version.parent_id == parent_sbom.id
    assert new_version.sbom_version == "1.0.1"
    assert new_version.productver == "1.0.0"
    assert new_version.product_name == "test-app"
    assert new_version.description == "manual product metadata"

    # Verify component overrides are mapped
    new_comp = db.execute(
        select(SBOMComponent)
        .where(SBOMComponent.sbom_id == new_version.id)
        .where(SBOMComponent.bom_ref == "pkg:maven/org.apache.logging.log4j/log4j-core@2.15.0")
    ).scalar_one()

    assert new_comp.name == "log4j-core-edited"
    assert new_comp.version == "2.16.0"
    assert new_comp.license == "Apache-2.0"
    assert new_comp.lifecycle_status == "Deprecated"
    assert new_comp.is_deprecated is True

    # Compare versions
    diff = compare_versions(db, parent_sbom.id, new_version.id)
    assert diff["total_changed"] == 1
    assert diff["changed"][0]["name"] == "log4j-core-edited"
    assert "version" in diff["changed"][0]["changes"]

    # Restore version
    restored = restore_version(db, new_version.id, parent_sbom.id, user_id="bob")
    assert restored.sbom_version == "1.0.2"
    assert restored.productver == "1.0.0"
    assert restored.product_name == "test-app"
    assert restored.description == "manual product metadata"
    assert restored.change_summary.startswith("Restored previous version")


def test_partial_lifecycle_override_survives_catalog_sync(db):
    proj = Projects(project_name="partial-lifecycle-project", created_by="alice")
    db.add(proj)
    db.flush()

    sbom_data = {
        "bomFormat": "CycloneDX",
        "specVersion": "1.4",
        "components": [
            {
                "bom-ref": "pkg:maven/org.apache.logging.log4j/log4j-core@2.15.0",
                "name": "log4j-core",
                "version": "2.15.0",
            }
        ],
    }
    parent_sbom = SBOMSource(
        sbom_name="partial-lifecycle-sbom",
        sbom_data=json.dumps(sbom_data),
        projectid=proj.id,
        sbom_version="1.0.0",
        status="validated",
    )
    db.add(parent_sbom)
    db.commit()

    new_version = edit_sbom(
        db,
        parent_sbom.id,
        user_id="bob",
        updates={
            "components": [
                {
                    "bom_ref": "pkg:maven/org.apache.logging.log4j/log4j-core@2.15.0",
                    "version": "2.16.0",
                    "lifecycle": {"maintenance_status": "maintained"},
                }
            ]
        },
        change_summary="Partial lifecycle override",
    )

    new_comp = db.execute(
        select(SBOMComponent)
        .where(SBOMComponent.sbom_id == new_version.id)
        .where(SBOMComponent.bom_ref == "pkg:maven/org.apache.logging.log4j/log4j-core@2.15.0")
    ).scalar_one()

    assert new_comp.lifecycle_status == UNKNOWN
    assert new_comp.maintenance_status == "maintained"
    assert new_comp.lifecycle_manual_override is True


def test_sbom_versions_use_strict_parent_lineage(client, db):
    proj = Projects(project_name="lineage-project", created_by="alice")
    db.add(proj)
    db.flush()

    root = SBOMSource(
        sbom_name="same-name",
        sbom_data="{}",
        projectid=proj.id,
        sbom_version="1.0.0",
        status="validated",
    )
    unrelated = SBOMSource(
        sbom_name="same-name",
        sbom_data="{}",
        projectid=proj.id,
        sbom_version="9.9.9",
        status="validated",
    )
    db.add(root)
    db.add(unrelated)
    db.flush()

    child = SBOMSource(
        sbom_name="same-name",
        sbom_data="{}",
        projectid=proj.id,
        parent_id=root.id,
        sbom_version="1.0.1",
        status="validated",
    )
    db.add(child)
    db.commit()

    response = client.get(f"/api/sboms/{child.id}/versions")
    assert response.status_code == 200
    ids = [item["id"] for item in response.json()]
    assert ids == [root.id, child.id]
    assert unrelated.id not in ids


def test_compare_versions_reports_metadata_dependency_and_lifecycle_changes(db):
    doc_a = {
        "bomFormat": "CycloneDX",
        "specVersion": "1.5",
        "metadata": {"component": {"name": "app", "version": "1.0.0"}},
        "components": [],
        "dependencies": [{"ref": "pkg:lib/main@1.0.0", "dependsOn": ["pkg:lib/old-dep@1.0.0"]}],
    }
    doc_b = {
        "bomFormat": "CycloneDX",
        "specVersion": "1.5",
        "metadata": {"component": {"name": "app", "version": "1.1.0"}},
        "components": [],
        "dependencies": [
            {"ref": "pkg:lib/main@1.0.0", "dependsOn": ["pkg:lib/new-dep@2.0.0"]},
            {"ref": "pkg:lib/new-dep@2.0.0", "dependsOn": []},
        ],
    }
    sbom_a = SBOMSource(sbom_name="compare-a", sbom_data=json.dumps(doc_a), status="validated")
    sbom_b = SBOMSource(sbom_name="compare-b", sbom_data=json.dumps(doc_b), status="validated")
    db.add(sbom_a)
    db.add(sbom_b)
    db.flush()

    db.add_all(
        [
            SBOMComponent(
                sbom_id=sbom_a.id,
                bom_ref="pkg:lib/main@1.0.0",
                name="main",
                version="1.0.0",
                supplier="Old Supplier",
                license="MIT",
                hashes="SHA-256:old",
                lifecycle_status="active",
                eos_date="2027-01-01",
                eol_date="2028-01-01",
                is_deprecated=False,
                maintenance_status="maintained",
            ),
            SBOMComponent(
                sbom_id=sbom_a.id,
                bom_ref="pkg:lib/remove@1.0.0",
                name="remove",
                version="1.0.0",
            ),
            SBOMComponent(
                sbom_id=sbom_b.id,
                bom_ref="pkg:lib/main@1.0.0",
                name="main",
                version="1.1.0",
                supplier="New Supplier",
                license="Apache-2.0",
                hashes="SHA-256:new",
                lifecycle_status="eol",
                eos_date="2026-01-01",
                eol_date="2026-06-01",
                is_deprecated=True,
                maintenance_status="unmaintained",
            ),
            SBOMComponent(
                sbom_id=sbom_b.id,
                bom_ref="pkg:lib/add@1.0.0",
                name="add",
                version="1.0.0",
            ),
        ]
    )
    db.commit()

    diff = compare_versions(db, sbom_a.id, sbom_b.id)
    assert diff["total_added"] == 1
    assert diff["total_removed"] == 1
    assert diff["total_changed"] == 1
    changed_fields = diff["changed"][0]["changes"]
    for field in (
        "version",
        "supplier",
        "license",
        "hashes",
        "lifecycle_status",
        "eos_date",
        "eol_date",
        "is_deprecated",
        "maintenance_status",
    ):
        assert field in changed_fields
    assert "component" in diff["metadata_changes"]
    dependency_change = diff["dependency_changes"]["changed"][0]
    assert dependency_change["ref"] == "pkg:lib/main@1.0.0"
    assert dependency_change["added_dependencies"] == ["pkg:lib/new-dep@2.0.0"]
    assert dependency_change["removed_dependencies"] == ["pkg:lib/old-dep@1.0.0"]


def test_export_native_sbom_and_rejects_unsupported_conversion(client, db, sample_sbom_dict):
    sbom = SBOMSource(
        sbom_name="export-native",
        sbom_data=json.dumps(sample_sbom_dict),
        sbom_version="1.0.0",
        status="validated",
    )
    db.add(sbom)
    db.commit()

    native = client.get(f"/api/sboms/{sbom.id}/export")
    assert native.status_code == 200
    assert native.headers["content-type"].startswith("application/vnd.cyclonedx+json")
    assert json.loads(native.text)["bomFormat"] == "CycloneDX"

    unsupported = client.get(f"/api/sboms/{sbom.id}/export?format=spdx")
    assert unsupported.status_code == 400
    assert "Unsupported SBOM conversion" in unsupported.json()["detail"]


def test_remediation_tracking(db):
    # Seed project & findings
    proj = Projects(project_name="remediation-test-project", created_by="alice")
    db.add(proj)
    db.flush()

    remediation_data = {
        "vuln_id": "CVE-2021-44228",
        "component_name": "log4j-core",
        "component_version": "2.14.0",
        "fixed_version": "2.15.0",
        "status": "In Progress",
        "owner": "security-lead@org.com",
        "due_date": "2026-06-30",
        "fix_notes": "Mitigating via JVM parameter until patch is verified",
    }

    record = create_or_update_remediation(db, proj.id, remediation_data)
    assert record.id is not None
    assert record.status == "In Progress"

    # Fetch remediation for finding
    fetched = get_remediation_for_finding(db, proj.id, "CVE-2021-44228", "log4j-core", "2.14.0")
    assert fetched is not None
    assert fetched.owner == "security-lead@org.com"


def test_remediation_validation_and_audit_history(client, db):
    proj = Projects(project_name="remediation-validation-project", created_by="alice")
    db.add(proj)
    db.commit()

    base_payload = {
        "vuln_id": "CVE-2026-0001",
        "component_name": "openssl",
        "component_version": "3.0.0",
    }

    invalid_status = client.post(
        f"/api/remediation?project_id={proj.id}",
        json={**base_payload, "status": "Resolved"},
    )
    assert invalid_status.status_code == 400

    invalid_due_date = client.post(
        f"/api/remediation?project_id={proj.id}",
        json={**base_payload, "status": "Open", "due_date": "06/30/2026"},
    )
    assert invalid_due_date.status_code == 400

    fixed_without_resolution = client.post(
        f"/api/remediation?project_id={proj.id}",
        json={**base_payload, "status": "Fixed", "fixed_version": "3.0.9"},
    )
    assert fixed_without_resolution.status_code == 400

    fixed_without_fix_detail = client.post(
        f"/api/remediation?project_id={proj.id}",
        json={**base_payload, "status": "Fixed", "resolution_date": "2026-06-11"},
    )
    assert fixed_without_fix_detail.status_code == 400

    accepted_without_reason = client.post(
        f"/api/remediation?project_id={proj.id}",
        json={**base_payload, "status": "Accepted Risk"},
    )
    assert accepted_without_reason.status_code == 400

    created = client.post(
        f"/api/remediation?project_id={proj.id}&user_id=alice",
        json={**base_payload, "status": "Open", "owner": "security@example.com"},
    )
    assert created.status_code == 200
    remediation_id = created.json()["id"]

    in_progress = client.post(
        f"/api/remediation?project_id={proj.id}&user_id=bob",
        json={**base_payload, "status": "In Progress", "owner": "security@example.com"},
    )
    assert in_progress.status_code == 200

    fixed = client.post(
        f"/api/remediation?project_id={proj.id}&user_id=carol",
        json={
            **base_payload,
            "status": "Fixed",
            "owner": "security@example.com",
            "fixed_version": "3.0.9",
            "resolution_date": "2026-06-11",
            "fix_notes": "Patched and verified in staging",
        },
    )
    assert fixed.status_code == 200
    assert fixed.json()["status"] == "Fixed"

    history = client.get(f"/api/remediation/{remediation_id}/history")
    assert history.status_code == 200
    rows = history.json()
    assert [(row["old_status"], row["new_status"]) for row in rows] == [
        (None, "Open"),
        ("Open", "In Progress"),
        ("In Progress", "Fixed"),
    ]
    assert rows[-1]["changed_by"] == "carol"
    assert rows[-1]["note"] == "Patched and verified in staging"

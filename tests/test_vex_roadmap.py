from __future__ import annotations

import csv
import io
import json
import os

from app.db import SessionLocal
from app.models import SBOMComponent, SBOMSource, VexOverrideAudit, VexStatement
from app.services.lifecycle.normalizer import normalize_component
from app.services.lifecycle.repository_health_provider import RepositoryHealthProvider
from app.services.lifecycle.types import LOW, MEDIUM, UNKNOWN, UNSUPPORTED
from app.services.lifecycle.vex_discovery import (
    CsafVexDiscoveryProvider,
    VendorVexDiscoveryProvider,
    discover_and_import_vex_documents,
)
from sqlalchemy import select


def _session():
    return SessionLocal()


def _csaf_document() -> dict:
    return {
        "document": {
            "category": "csaf_vex",
            "publisher": {"name": "Example Vendor"},
            "tracking": {
                "id": "EXAMPLE-2026-001",
                "current_release_date": "2026-06-12T00:00:00Z",
            },
        },
        "product_tree": {
            "full_product_names": [
                {
                    "product_id": "CSAFPID-LODASH",
                    "name": "lodash 4.17.20",
                    "product_identification_helper": {"purl": "pkg:npm/lodash@4.17.20"},
                },
                {
                    "product_id": "CSAFPID-UNMATCHED",
                    "name": "Vendor Appliance 1.0",
                    "product_identification_helper": {"purl": "pkg:generic/vendor/appliance@1.0"},
                },
            ]
        },
        "vulnerabilities": [
            {
                "cve": "CVE-2020-8203",
                "product_status": {
                    "known_not_affected": ["CSAFPID-LODASH"],
                    "known_affected": ["CSAFPID-UNMATCHED"],
                },
                "flags": [
                    {
                        "label": "vulnerable_code_not_in_execute_path",
                        "product_ids": ["CSAFPID-LODASH"],
                    }
                ],
                "threats": [
                    {
                        "category": "impact",
                        "details": "The vulnerable code path is not reachable in this build.",
                        "product_ids": ["CSAFPID-LODASH"],
                    }
                ],
                "remediations": [
                    {
                        "category": "mitigation",
                        "details": "Disable the affected feature until patched.",
                        "product_ids": ["CSAFPID-UNMATCHED"],
                    }
                ],
            }
        ],
    }


def test_csaf_import_maps_products_and_keeps_unmatched(client):
    db = _session()
    try:
        sbom = SBOMSource(sbom_name="csaf-vex-sbom", sbom_data="{}", status="validated")
        db.add(sbom)
        db.flush()
        component = SBOMComponent(
            sbom_id=sbom.id,
            name="lodash",
            version="4.17.20",
            purl="pkg:npm/lodash@4.17.20",
        )
        db.add(component)
        db.commit()

        response = client.post(
            f"/api/sboms/{sbom.id}/vex",
            json={"document": _csaf_document(), "source_name": "CSAF upload"},
        )

        assert response.status_code == 200, response.text
        body = response.json()
        assert body["format"] == "CSAF VEX"
        assert body["statements_imported"] == 2
        assert body["matched_statements"] == 1
        assert body["unmatched_statements"] == 1

        listed = client.get(f"/api/sboms/{sbom.id}/vex").json()["statements"]
        by_status = {row["status"]: row for row in listed}
        assert by_status["not_affected"]["component_id"] == component.id
        assert by_status["not_affected"]["confidence"] == MEDIUM
        assert by_status["affected"]["component_id"] is None
        assert by_status["affected"]["confidence"] == LOW
        assert by_status["affected"]["evidence_json"]["mapping"] == "unmatched"
    finally:
        db.rollback()
        db.close()


def test_vendor_vex_discovery_success_imports_cached_csaf_document(client):
    db = _session()
    try:
        sbom = SBOMSource(
            sbom_name="discover-vex-sbom",
            sbom_data='{"bomFormat":"CycloneDX","externalReferences":[{"type":"vex","url":"https://vendor.test/security/vex.json"}]}',
            status="validated",
        )
        db.add(sbom)
        db.flush()
        db.add(SBOMComponent(sbom_id=sbom.id, name="lodash", version="4.17.20", purl="pkg:npm/lodash@4.17.20"))
        db.commit()

        calls: list[str] = []

        def fake_get(url: str):
            calls.append(url)
            return _csaf_document()

        provider = CsafVexDiscoveryProvider(http_get=fake_get)
        result = discover_and_import_vex_documents(db, sbom.id, providers=[provider])

        assert result["discovered_documents"] == 1
        assert result["statements_imported"] == 2
        assert result["unmatched_statements"] == 1
        assert calls == ["https://vendor.test/security/vex.json"]
    finally:
        db.rollback()
        db.close()


def test_vendor_vex_discovery_failure_returns_error_without_upload_failure():
    db = _session()
    try:
        sbom = SBOMSource(
            sbom_name="discover-failure-sbom",
            sbom_data='{"bomFormat":"CycloneDX","externalReferences":[{"type":"vex","url":"https://vendor.test/missing-vex.json"}]}',
            status="validated",
        )
        db.add(sbom)
        db.commit()

        class BrokenProvider(VendorVexDiscoveryProvider):
            name = "Broken Provider"

            def candidates(self, sbom, components):  # noqa: ANN001
                raise RuntimeError("network policy denied")

        result = discover_and_import_vex_documents(db, sbom.id, providers=[BrokenProvider()])
        assert result["statements_imported"] == 0
        assert result["errors"][0]["provider"] == "Broken Provider"
    finally:
        db.rollback()
        db.close()


def test_vendor_vex_discovery_blocks_private_internal_ip_urls():
    db = _session()
    try:
        sbom = SBOMSource(
            sbom_name="discover-private-urls",
            sbom_data=json.dumps(
                {
                    "bomFormat": "CycloneDX",
                    "externalReferences": [
                        {"type": "vex", "url": "http://127.0.0.1/vex.json"},
                        {"type": "vex", "url": "http://169.254.169.254/latest/meta-data"},
                        {"type": "vex", "url": "http://10.0.0.8/vex.json"},
                        {"type": "vex", "url": "http://localhost/vex.json"},
                        {"type": "vex", "url": "http://service.internal/vex.json"},
                    ],
                }
            ),
            status="validated",
        )
        db.add(sbom)
        db.commit()

        calls: list[str] = []

        def fake_get(url: str):
            calls.append(url)
            return _csaf_document()

        provider = VendorVexDiscoveryProvider(http_get=fake_get)
        assert provider.candidates(sbom, []) == []

        result = discover_and_import_vex_documents(db, sbom.id, providers=[provider])
        assert result["discovered_documents"] == 0
        assert result["statements_imported"] == 0
        assert calls == []
    finally:
        db.rollback()
        db.close()


def test_vex_csv_report_export(client):
    db = _session()
    try:
        sbom = SBOMSource(sbom_name="vex-csv-sbom", sbom_data="{}", status="validated")
        db.add(sbom)
        db.flush()
        component = SBOMComponent(sbom_id=sbom.id, name="openssl", version="3.0.0")
        db.add(component)
        db.flush()
        db.add(
            VexStatement(
                sbom_id=sbom.id,
                component_id=component.id,
                vulnerability_id="CVE-2026-0001",
                cve_id="CVE-2026-0001",
                status="affected",
                action_statement="Upgrade",
                source_name="test",
                confidence="High",
                evidence_json={"source": "unit"},
                created_at="2026-06-12T00:00:00Z",
            )
        )
        db.commit()

        response = client.get(f"/api/sboms/{sbom.id}/vex/report?format=csv&report_type=affected")
        assert response.status_code == 200
        assert response.headers["content-type"].startswith("text/csv")
        rows = list(csv.DictReader(io.StringIO(response.text)))
        assert rows[0]["vulnerability_id"] == "CVE-2026-0001"
        assert rows[0]["matched"] == "True"
    finally:
        db.rollback()
        db.close()


def test_manual_vex_override_validation_and_history_endpoint(client):
    db = _session()
    try:
        sbom = SBOMSource(sbom_name="manual-vex-validation-sbom", sbom_data="{}", status="validated")
        db.add(sbom)
        db.flush()
        component = SBOMComponent(sbom_id=sbom.id, name="openssl", version="3.0.0")
        db.add(component)
        db.commit()

        invalid = client.patch(
            f"/api/components/{component.id}/vulnerabilities/CVE-2026-0002/vex-override",
            json={"status": "fixed", "reason": "reviewed"},
        )
        assert invalid.status_code == 422

        valid = client.patch(
            f"/api/components/{component.id}/vulnerabilities/CVE-2026-0002/vex-override",
            json={
                "status": "fixed",
                "fixed_version": "3.0.8",
                "reason": "vendor fixed release validated",
                "evidence_url": "https://vendor.test/advisory",
            },
        )
        assert valid.status_code == 200

        history = client.get(f"/api/components/{component.id}/vulnerabilities/CVE-2026-0002/vex-override/history")
        assert history.status_code == 200
        body = history.json()
        assert len(body["history"]) == 1
        assert body["history"][0]["reason"] == "vendor fixed release validated"
    finally:
        db.rollback()
        db.close()


def test_lifecycle_csv_report_export(client):
    db = _session()
    try:
        sbom = SBOMSource(sbom_name="lifecycle-csv-sbom", sbom_data="{}", status="validated")
        db.add(sbom)
        db.flush()
        db.add(
            SBOMComponent(
                sbom_id=sbom.id,
                name="legacy-lib",
                version="1.0.0",
                lifecycle_status="EOL",
                eol_date="2024-01-01",
                unsupported=True,
                lifecycle_source="Vendor",
                lifecycle_confidence="High",
                lifecycle_checked_at="2026-06-12T00:00:00Z",
            )
        )
        db.commit()

        response = client.get(f"/api/sboms/{sbom.id}/lifecycle/report?format=csv&report_type=eol_eos_eof")
        assert response.status_code == 200
        rows = list(csv.DictReader(io.StringIO(response.text)))
        assert rows[0]["name"] == "legacy-lib"
        assert rows[0]["lifecycle_status"] == "EOL"
    finally:
        db.rollback()
        db.close()


def test_report_pack_exports(client):
    db = _session()
    try:
        sbom = SBOMSource(sbom_name="report-pack-sbom", sbom_data="{}", status="validated")
        db.add(sbom)
        db.flush()
        component = SBOMComponent(sbom_id=sbom.id, name="openssl", version="3.0.0", lifecycle_status="EOL")
        db.add(component)
        db.add(
            VexStatement(
                sbom_id=sbom.id,
                component_id=component.id,
                vulnerability_id="CVE-2026-0003",
                status="affected",
                created_at="2026-06-12T00:00:00Z",
            )
        )
        db.commit()

        vex_pack = client.get(f"/api/sboms/{sbom.id}/reports/vex-pack")
        assert vex_pack.status_code == 200
        assert vex_pack.headers["content-type"].startswith("application/zip")

        lifecycle_pack = client.get(f"/api/sboms/{sbom.id}/reports/lifecycle-pack")
        assert lifecycle_pack.status_code == 200
        assert lifecycle_pack.headers["content-type"].startswith("application/zip")
    finally:
        db.rollback()
        db.close()


def test_gitlab_repository_health_archived_marks_unsupported():
    def fake_get(url: str):
        if url.endswith("/releases?per_page=1"):
            return [{"tag_name": "v1.2.3", "released_at": "2026-01-01T00:00:00Z"}]
        return {
            "archived": True,
            "last_activity_at": "2026-01-01T00:00:00Z",
            "web_url": "https://gitlab.com/acme/lib",
            "default_branch": "main",
        }

    component = normalize_component(
        SBOMComponent(
            sbom_id=1,
            name="lib",
            version="1.0.0",
            purl="pkg:generic/acme/lib@1.0.0",
        )
    )
    component.repository_url = "https://gitlab.com/acme/lib"
    result = RepositoryHealthProvider(http_get=fake_get).lookup(component)
    assert result.lifecycle_status == UNSUPPORTED
    assert result.source_name == "GitLab Repository"
    assert result.confidence == MEDIUM
    assert result.evidence["latest_release"]["tag_name"] == "v1.2.3"


def test_generic_repository_health_remains_unknown_low_confidence():
    component = normalize_component(SBOMComponent(sbom_id=1, name="lib", version="1.0.0"))
    component.repository_url = "https://code.example.test/acme/lib"
    result = RepositoryHealthProvider(http_get=lambda url: {"ignored": True}).lookup(component)
    assert result.lifecycle_status == UNKNOWN
    assert result.confidence == LOW
    assert result.unsupported is False


def test_rbac_blocks_viewer_and_allows_security_override(client, monkeypatch):
    db = _session()
    try:
        sbom = SBOMSource(sbom_name="rbac-vex-sbom", sbom_data="{}", status="validated")
        db.add(sbom)
        db.flush()
        component = SBOMComponent(sbom_id=sbom.id, name="openssl", version="1.1.1")
        db.add(component)
        db.commit()

        monkeypatch.setenv("API_AUTH_MODE", "bearer")
        monkeypatch.setenv("API_AUTH_TOKENS", "secret")
        headers = {"Authorization": "Bearer secret"}
        payload = {
            "status": "affected",
            "reason": "security review",
            "impact_statement": "reachable",
        }
        blocked = client.patch(
            f"/api/components/{component.id}/vulnerabilities/CVE-2026-9999/vex-override",
            json=payload,
            headers=headers,
        )
        assert blocked.status_code == 403

        allowed = client.patch(
            f"/api/components/{component.id}/vulnerabilities/CVE-2026-9999/vex-override",
            json=payload,
            headers={**headers, "X-SBOM-Roles": "security", "X-SBOM-User": "sec@example.test"},
        )
        assert allowed.status_code == 200
        audit = (
            db.execute(select(VexOverrideAudit).where(VexOverrideAudit.component_id == component.id)).scalars().first()
        )
        assert audit is not None
        assert audit.changed_by == "sec@example.test"
    finally:
        monkeypatch.setenv("API_AUTH_MODE", "none")
        os.environ.pop("API_AUTH_TOKENS", None)
        db.rollback()
        db.close()

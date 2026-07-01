"""Tests for SPDX to CycloneDX conversion and lifecycle enrichment export."""

from __future__ import annotations

import json
import uuid
from pathlib import Path

from app.models import SBOMComponent
from app.services.sbom_conversion_service import convert_spdx_to_cyclonedx
from app.validation import run as run_validation
from sqlalchemy import select

FIXTURES = Path(__file__).resolve().parent / "fixtures" / "sboms" / "valid"


def _unique(prefix: str) -> str:
    return f"{prefix}-{uuid.uuid4().hex[:8]}"


def _load_spdx(name: str = "spdx_2_3_minimal.json") -> dict:
    with open(FIXTURES / name, encoding="utf-8") as fh:
        return json.load(fh)


def _upload_spdx(client, name: str | None = None, fixture: str = "spdx_2_3_minimal.json") -> int:
    sbom_name = name or _unique("spdx-convert")
    with open(FIXTURES / fixture, "rb") as fh:
        resp = client.post(
            "/api/sboms/upload",
            data={"sbom_name": sbom_name, "created_by": "conversion-test"},
            files={"file": (fixture, fh, "application/json")},
        )
    assert resp.status_code == 202, resp.text
    return resp.json()["sbom_id"]


class TestSpdxToCyclonedxConversionService:
    def test_valid_spdx_converts_to_valid_cyclonedx(self):
        result = convert_spdx_to_cyclonedx(_load_spdx())
        assert not result.conversion_errors
        assert result.cyclonedx_bom.get("bomFormat") == "CycloneDX"
        assert result.cyclonedx_bom.get("specVersion") == "1.6"
        report = run_validation(json.dumps(result.cyclonedx_bom).encode())
        assert report.error_count == 0

    def test_spdx_packages_become_cyclonedx_components(self):
        result = convert_spdx_to_cyclonedx(_load_spdx())
        components = result.cyclonedx_bom.get("components") or []
        names = {c.get("name") for c in components}
        assert "foo" in names

    def test_spdx_spdxid_preserved_as_property(self):
        result = convert_spdx_to_cyclonedx(_load_spdx())
        pkg_component = next(c for c in result.cyclonedx_bom["components"] if c.get("name") == "foo")
        props = {p["name"]: p["value"] for p in pkg_component.get("properties") or []}
        assert props.get("spdx:SPDXID") == "SPDXRef-Package-foo"

    def test_spdx_license_declared_maps_to_cyclonedx_license(self):
        result = convert_spdx_to_cyclonedx(_load_spdx())
        pkg_component = next(c for c in result.cyclonedx_bom["components"] if c.get("name") == "foo")
        licenses = pkg_component.get("licenses") or []
        assert any(lic.get("expression") == "Apache-2.0" for lic in licenses)

    def test_spdx_checksums_map_to_cyclonedx_hashes(self):
        spdx = _load_spdx("spdx_2_3_realistic.json")
        result = convert_spdx_to_cyclonedx(spdx)
        with_hashes = [c for c in result.cyclonedx_bom["components"] if c.get("hashes")]
        assert with_hashes
        assert with_hashes[0]["hashes"][0]["alg"] == "SHA-256"

    def test_spdx_purl_external_ref_maps_to_cyclonedx_purl(self):
        result = convert_spdx_to_cyclonedx(_load_spdx())
        pkg_component = next(c for c in result.cyclonedx_bom["components"] if c.get("name") == "foo")
        assert pkg_component.get("purl") == "pkg:npm/foo@1.0.0"

    def test_spdx_depends_on_maps_to_cyclonedx_dependencies(self):
        spdx = _load_spdx()
        spdx["relationships"].append(
            {
                "spdxElementId": "SPDXRef-Package-foo",
                "relationshipType": "DEPENDS_ON",
                "relatedSpdxElement": "SPDXRef-Package-bar",
            }
        )
        spdx["packages"].append(
            {
                "SPDXID": "SPDXRef-Package-bar",
                "name": "bar",
                "versionInfo": "2.0.0",
                "downloadLocation": "NOASSERTION",
                "filesAnalyzed": False,
                "licenseConcluded": "MIT",
                "licenseDeclared": "MIT",
                "copyrightText": "NOASSERTION",
            }
        )
        result = convert_spdx_to_cyclonedx(spdx)
        deps = result.cyclonedx_bom.get("dependencies") or []
        foo_dep = next((d for d in deps if d.get("ref") == "SPDXRef-Package-foo"), None)
        assert foo_dep is not None
        assert "SPDXRef-Package-bar" in (foo_dep.get("dependsOn") or [])

    def test_unsupported_spdx_relationship_becomes_warning(self):
        spdx = _load_spdx()
        spdx["relationships"].append(
            {
                "spdxElementId": "SPDXRef-Package-foo",
                "relationshipType": "AMENDS",
                "relatedSpdxElement": "SPDXRef-DOCUMENT",
            }
        )
        result = convert_spdx_to_cyclonedx(spdx)
        assert any("AMENDS" in w for w in result.conversion_warnings)

    def test_generated_cyclonedx_has_no_dangling_dependency_refs(self):
        result = convert_spdx_to_cyclonedx(_load_spdx("spdx_2_3_realistic.json"))
        refs = {c.get("bom-ref") for c in result.cyclonedx_bom.get("components") or []}
        for dep in result.cyclonedx_bom.get("dependencies") or []:
            assert dep.get("ref") in refs
            for target in dep.get("dependsOn") or []:
                assert target in refs

    def test_duplicate_spdxid_handled_safely(self):
        spdx = _load_spdx()
        duplicate = dict(spdx["packages"][0])
        duplicate["name"] = "foo-copy"
        spdx["packages"].append(duplicate)
        result = convert_spdx_to_cyclonedx(spdx)
        refs = [c.get("bom-ref") for c in result.cyclonedx_bom["components"]]
        assert len(refs) == len(set(refs))

    def test_conversion_rejects_non_spdx_shape(self):
        result = convert_spdx_to_cyclonedx({"bomFormat": "CycloneDX"})
        assert result.conversion_errors

    def test_conversion_rejects_no_packages(self):
        spdx = _load_spdx()
        spdx["packages"] = []
        result = convert_spdx_to_cyclonedx(spdx)
        assert any("No SPDX packages" in e for e in result.conversion_errors)


class TestSpdxToCyclonedxConversionApi:
    def test_conversion_api_rejects_non_spdx_source(self, client):
        cyclonedx = {
            "bomFormat": "CycloneDX",
            "specVersion": "1.5",
            "serialNumber": "urn:uuid:11111111-2222-3333-4444-555555555555",
            "version": 1,
            "metadata": {"timestamp": "2026-04-30T12:00:00Z"},
            "components": [
                {
                    "type": "library",
                    "bom-ref": "pkg:pypi/requests@2.32.0",
                    "name": "requests",
                    "version": "2.32.0",
                    "purl": "pkg:pypi/requests@2.32.0",
                }
            ],
        }
        resp = client.post(
            "/api/sboms",
            json={"sbom_name": _unique("cdx-no-convert"), "sbom_data": json.dumps(cyclonedx)},
        )
        assert resp.status_code in {200, 201}
        sbom_id = resp.json()["id"]
        convert = client.post(f"/api/sboms/{sbom_id}/convert/cyclonedx")
        assert convert.status_code == 400
        assert "spdx" in convert.json()["detail"].lower()

    def test_convert_spdx_creates_converted_sbom(self, client):
        sbom_id = _upload_spdx(client)
        # Raw document content is opt-in via ?include_raw=true (matches the
        # frontend and other tests); the default detail response omits it.
        original = client.get(f"/api/sboms/{sbom_id}?include_raw=true").json()
        original_data = original["sbom_data"]

        convert = client.post(f"/api/sboms/{sbom_id}/convert/cyclonedx")
        assert convert.status_code == 200, convert.text
        body = convert.json()
        assert body["source_sbom_id"] == sbom_id
        assert body["converted_sbom_id"]
        assert body["source_format"] == "SPDX"
        assert body["target_format"] == "CycloneDX"
        assert body["enrichment_status"] == "pending"
        assert "background" in body["message"].lower()

        refreshed = client.get(f"/api/sboms/{sbom_id}?include_raw=true").json()
        assert refreshed["sbom_data"] == original_data
        assert refreshed["converted_sbom_id"] == body["converted_sbom_id"]
        assert refreshed["conversion_status"] in {"completed", "completed_with_warnings"}

        converted = client.get(f"/api/sboms/{body['converted_sbom_id']}?include_raw=true").json()
        converted_doc = json.loads(converted["sbom_data"])
        assert converted_doc.get("bomFormat") == "CycloneDX"

    def test_conversion_report_saved_and_retrievable(self, client):
        sbom_id = _upload_spdx(client)
        convert = client.post(f"/api/sboms/{sbom_id}/convert/cyclonedx")
        assert convert.status_code == 200

        report_resp = client.get(f"/api/sboms/{sbom_id}/conversion-report")
        assert report_resp.status_code == 200
        report = report_resp.json()
        assert report["source_format"] == "SPDX"
        assert report["target_format"] == "CycloneDX"
        assert report["package_count"] >= 1

    def test_export_original_spdx_unchanged(self, client):
        sbom_id = _upload_spdx(client)
        # Raw content is opt-in via ?include_raw=true (default detail omits it).
        before = client.get(f"/api/sboms/{sbom_id}?include_raw=true").json()["sbom_data"]
        client.post(f"/api/sboms/{sbom_id}/convert/cyclonedx")
        export = client.get(f"/api/sboms/{sbom_id}/export?export_mode=original")
        assert export.status_code == 200
        assert json.loads(export.text) == json.loads(before)

    def test_export_enriched_cyclonedx_includes_lifecycle_properties(self, client):
        from app.db import SessionLocal

        sbom_id = _upload_spdx(client)
        convert = client.post(f"/api/sboms/{sbom_id}/convert/cyclonedx")
        converted_id = convert.json()["converted_sbom_id"]

        db = SessionLocal()
        try:
            component = db.execute(
                select(SBOMComponent).where(
                    SBOMComponent.sbom_id == converted_id,
                    SBOMComponent.name == "foo",
                )
            ).scalar_one_or_none()
            if component:
                component.lifecycle_status = "EOL"
                component.eol_date = "2025-01-01"
                component.lifecycle_confidence = "HIGH"
                component.lifecycle_checked_at = "2026-06-17T00:00:00Z"
                db.commit()
        finally:
            db.close()

        export = client.get(f"/api/sboms/{sbom_id}/export?format=cyclonedx&export_mode=enriched")
        assert export.status_code == 200
        doc = json.loads(export.text)
        foo = next(c for c in doc["components"] if c.get("name") == "foo")
        prop_names = {p["name"] for p in foo.get("properties") or []}
        if component:
            assert "lifecycle:status" in prop_names

    def test_export_conversion_report_json(self, client):
        sbom_id = _upload_spdx(client)
        client.post(f"/api/sboms/{sbom_id}/convert/cyclonedx")
        export = client.get(f"/api/sboms/{sbom_id}/export?format=conversion-report")
        assert export.status_code == 200
        report = json.loads(export.text)
        assert report.get("source_format") == "SPDX"


class TestSpdxConversionPerformance:
    def test_convert_does_not_call_lifecycle_in_persist_path(self, monkeypatch):
        from app.db import SessionLocal
        from app.models import SBOMSource
        from app.services.sbom_conversion_service import convert_and_persist_spdx_to_cyclonedx

        lifecycle_calls: list[int] = []

        def _track_lifecycle(db, sbom_id, **kwargs):
            lifecycle_calls.append(sbom_id)
            return {"sbom_id": sbom_id}

        monkeypatch.setattr(
            "app.services.lifecycle_service.sync_lifecycle_for_sbom",
            _track_lifecycle,
        )

        spdx_data = json.dumps(_load_spdx())
        db = SessionLocal()
        try:
            source = SBOMSource(
                sbom_name="perf-test-spdx",
                sbom_data=spdx_data,
                status="validated",
                original_format="spdx",
                current_format="spdx",
            )
            db.add(source)
            db.commit()
            db.refresh(source)

            convert_and_persist_spdx_to_cyclonedx(db, source)

            assert lifecycle_calls == []
            db.refresh(source)
            assert source.enrichment_status == "pending"
        finally:
            db.rollback()
            db.close()

    def test_run_post_conversion_enrichment_marks_completed(self, monkeypatch):
        from app.db import SessionLocal
        from app.models import SBOMSource
        from app.services.sbom_conversion_service import (
            convert_and_persist_spdx_to_cyclonedx,
            run_post_conversion_enrichment,
        )

        monkeypatch.setattr(
            "app.services.lifecycle_service.sync_lifecycle_for_sbom",
            lambda db, sbom_id, **kwargs: {"sbom_id": sbom_id, "components_enriched": 1},
        )
        monkeypatch.setattr(
            "app.services.lifecycle.vex_provider.process_embedded_vex_for_sbom",
            lambda db, sbom_id: None,
        )
        monkeypatch.setattr(
            "app.services.completeness_service.compute_and_save_completeness",
            lambda db, sbom: None,
        )

        db = SessionLocal()
        try:
            source = SBOMSource(
                sbom_name="bg-enrich-spdx",
                sbom_data=json.dumps(_load_spdx()),
                status="validated",
                original_format="spdx",
                current_format="spdx",
            )
            db.add(source)
            db.commit()
            db.refresh(source)

            converted, _, _ = convert_and_persist_spdx_to_cyclonedx(db, source)
            run_post_conversion_enrichment(converted.id, source.id)

            db.refresh(converted)
            db.refresh(source)
            assert converted.enrichment_status == "completed"
            assert source.enrichment_status == "completed"
        finally:
            db.rollback()
            db.close()

    def test_convert_api_returns_before_enrichment_finishes(self, client, monkeypatch):
        import time

        def slow_background(converted_sbom_id: int, source_sbom_id: int | None = None) -> None:
            time.sleep(2)

        monkeypatch.setattr(
            "app.routers.sbom_versions.run_post_conversion_enrichment",
            slow_background,
        )

        sbom_id = _upload_spdx(client)
        started = time.perf_counter()
        convert = client.post(f"/api/sboms/{sbom_id}/convert/cyclonedx")
        elapsed = time.perf_counter() - started

        assert convert.status_code == 200
        assert elapsed < 5.0
        assert convert.json()["enrichment_status"] == "pending"

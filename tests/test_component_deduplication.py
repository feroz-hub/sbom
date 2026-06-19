"""Tests for Component Deduplication, API filters, and Export functionality."""

from __future__ import annotations

import json

import pytest
from app.services.component_deduplication_service import ComponentDeduplicationService
from app.validation.errors import W120_DUPLICATE_COMPONENT_DETECTED

# Test fixtures for CycloneDX SBOMs with duplicate components
_DUPLICATE_CYCLONEDX = {
    "bomFormat": "CycloneDX",
    "specVersion": "1.5",
    "serialNumber": "urn:uuid:11111111-2222-3333-4444-555555555555",
    "version": 1,
    "metadata": {
        "timestamp": "2026-04-30T12:00:00Z",
        "component": {
            "type": "application",
            "bom-ref": "pkg:generic/phase2-valid@1.0.0",
            "name": "phase2-valid",
            "version": "1.0.0",
        },
    },
    "components": [
        {
            "type": "application",
            "bom-ref": "pkg:generic/phase2-valid@1.0.0",
            "name": "phase2-valid",
            "version": "1.0.0",
            "purl": "pkg:generic/phase2-valid@1.0.0"
        },
        {
            "type": "library",
            "bom-ref": "ref-lodash-1",
            "name": "lodash",
            "version": "4.17.21",
            "purl": "pkg:npm/lodash@4.17.21",
            "licenses": [{"license": {"name": "MIT"}}],
            "hashes": [{"alg": "SHA-256", "content": "1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef"}],
            "supplier": {"name": "JS Supplier"}
        },
        {
            "type": "library",
            "bom-ref": "ref-lodash-2",
            "name": "lodash",
            "version": "4.17.21",
            "purl": "pkg:npm/lodash@4.17.21",
            "licenses": [{"license": {"name": "Apache-2.0"}}],
            "hashes": [{"alg": "SHA-1", "content": "1234567890abcdef1234567890abcdef12345678"}],
            "supplier": {"name": "Alternate Supplier"}
        }
    ],
    "dependencies": [
        {
            "ref": "pkg:generic/phase2-valid@1.0.0",
            "dependsOn": ["ref-lodash-1", "ref-lodash-2"]
        },
        {
            "ref": "ref-lodash-2",
            "dependsOn": []
        }
    ]
}

@pytest.fixture
def unique_name(request) -> str:
    import uuid
    return f"dedupe-{request.node.name}-{uuid.uuid4().hex[:8]}"

def test_deduplication_service_logic():
    """Test pure python deduplication and merging logic."""
    components = [
        {
            "name": "lodash",
            "version": "4.17.21",
            "purl": "pkg:npm/lodash@4.17.21",
            "bom_ref": "ref-lodash-1",
            "license": "MIT",
            "hashes": "SHA-256:12345",
            "supplier": "JS Supplier"
        },
        {
            "name": "lodash",
            "version": "4.17.21",
            "purl": "pkg:npm/lodash@4.17.21",
            "bom_ref": "ref-lodash-2",
            "license": "Apache-2.0",
            "hashes": "SHA-1:67890",
            "supplier": "Alternate Supplier"
        }
    ]
    dependencies = [
        {"ref": "app-ref", "dependsOn": ["ref-lodash-1", "ref-lodash-2"]},
        {"ref": "ref-lodash-2", "dependsOn": []}
    ]

    canonical, duplicates, ref_mapping, report, warnings = ComponentDeduplicationService.deduplicate_components(
        components, dependencies
    )

    # 1. Verification of identity & groupings
    assert len(canonical) == 1
    assert len(duplicates) == 1
    assert duplicates[0]["is_duplicate"] is True
    assert duplicates[0]["duplicate_of_ref"] == "ref-lodash-1"

    # 2. Attribute merging checks
    canonical_comp = canonical[0]
    assert canonical_comp["license"] == "Apache-2.0, MIT" or canonical_comp["license"] == "MIT, Apache-2.0"
    assert "SHA-256:12345" in canonical_comp["hashes"]
    assert "SHA-1:67890" in canonical_comp["hashes"]
    assert canonical_comp["supplier"] == "JS Supplier"  # Kept the first one

    # 3. Conflict report
    assert len(report["conflicts"]) > 0
    conflict_fields = [c["field"] for c in report["conflicts"]]
    assert "license" in conflict_fields
    assert "supplier" in conflict_fields

    # 4. Ref mapping remapping check
    assert ref_mapping == {"ref-lodash-2": "ref-lodash-1"}


def test_api_dedupe_on_upload(client, unique_name):
    """Test that duplicates are processed, flagged, and reports are saved during upload."""
    resp = client.post(
        "/api/sboms",
        json={"sbom_name": unique_name, "sbom_data": json.dumps(_DUPLICATE_CYCLONEDX)},
    )
    assert resp.status_code == 201, resp.text
    sbom_id = resp.json()["id"]

    # Dedupe report endpoint check
    report_resp = client.get(f"/api/sboms/{sbom_id}/dedupe-report")
    assert report_resp.status_code == 200, report_resp.text
    report = report_resp.json()
    assert report["duplicates_found"] == 2
    assert report["duplicates_merged"] == 1
    assert "ref-lodash-2" in report["ref_mapping"]

    # Component list checking with include_duplicates parameter
    # 1. include_duplicates = False (default)
    components_resp = client.get(f"/api/sboms/{sbom_id}/components")
    assert components_resp.status_code == 200
    payload = components_resp.json()
    components = payload["items"]
    assert payload["include_duplicates"] is False
    assert payload["unique_count"] == 2
    assert payload["duplicate_count"] == 1
    assert payload["total_count"] == 2
    # Should contain 2 components: app and canonical lodash
    assert len(components) == 2
    names = [c["name"] for c in components]
    assert "phase2-valid" in names
    assert "lodash" in names
    for c in components:
        assert c.get("is_duplicate") is False or c.get("is_duplicate") is None

    # 2. include_duplicates = True
    components_dup_resp = client.get(f"/api/sboms/{sbom_id}/components?include_duplicates=true")
    assert components_dup_resp.status_code == 200
    payload_all = components_dup_resp.json()
    components_all = payload_all["items"]
    assert payload_all["include_duplicates"] is True
    assert payload_all["unique_count"] == 2
    assert payload_all["duplicate_count"] == 1
    assert payload_all["total_count"] == 3
    # Should contain 3 components: app, canonical lodash, and duplicate lodash
    assert len(components_all) == 3
    duplicates_flag = [c.get("is_duplicate") for c in components_all]
    assert True in duplicates_flag
    duplicate_row = next(c for c in components_all if c.get("is_duplicate"))
    assert duplicate_row.get("canonical_component_name") == "lodash"
    assert duplicate_row.get("canonical_component_version") == "4.17.21"
    assert duplicate_row.get("duplicate_reason")


def test_component_list_search_hides_and_includes_duplicates(client, unique_name):
    resp = client.post(
        "/api/sboms",
        json={"sbom_name": unique_name, "sbom_data": json.dumps(_DUPLICATE_CYCLONEDX)},
    )
    assert resp.status_code == 201
    sbom_id = resp.json()["id"]

    hidden = client.get(f"/api/sboms/{sbom_id}/components?search=lodash")
    assert hidden.status_code == 200
    hidden_payload = hidden.json()
    assert hidden_payload["total_count"] == 1
    assert len(hidden_payload["items"]) == 1
    assert hidden_payload["items"][0]["is_duplicate"] is False

    visible = client.get(f"/api/sboms/{sbom_id}/components?include_duplicates=true&search=lodash")
    assert visible.status_code == 200
    visible_payload = visible.json()
    assert visible_payload["total_count"] == 2
    assert len(visible_payload["items"]) == 2
    assert sum(1 for item in visible_payload["items"] if item.get("is_duplicate")) == 1


def test_component_list_pagination_respects_duplicate_filter(client, unique_name):
    resp = client.post(
        "/api/sboms",
        json={"sbom_name": unique_name, "sbom_data": json.dumps(_DUPLICATE_CYCLONEDX)},
    )
    assert resp.status_code == 201
    sbom_id = resp.json()["id"]

    page_default = client.get(f"/api/sboms/{sbom_id}/components?page_size=1")
    assert page_default.status_code == 200
    page_default_payload = page_default.json()
    assert page_default_payload["total_count"] == 2
    assert len(page_default_payload["items"]) == 1

    page_with_dupes = client.get(
        f"/api/sboms/{sbom_id}/components?include_duplicates=true&page_size=1"
    )
    assert page_with_dupes.status_code == 200
    page_with_dupes_payload = page_with_dupes.json()
    assert page_with_dupes_payload["total_count"] == 3
    assert len(page_with_dupes_payload["items"]) == 1


def test_component_list_does_not_modify_stored_sbom(client, unique_name):
    resp = client.post(
        "/api/sboms",
        json={"sbom_name": unique_name, "sbom_data": json.dumps(_DUPLICATE_CYCLONEDX)},
    )
    assert resp.status_code == 201
    sbom_id = resp.json()["id"]

    before = client.get(f"/api/sboms/{sbom_id}").json()["sbom_data"]
    list_resp = client.get(f"/api/sboms/{sbom_id}/components?include_duplicates=false")
    assert list_resp.status_code == 200
    after = client.get(f"/api/sboms/{sbom_id}").json()["sbom_data"]
    assert before == after
    stored = json.loads(after)
    assert len(stored["components"]) == 3


def test_validation_warnings_for_duplicates(client, unique_name):
    """Test that duplicate component validation warnings are raised during verification."""
    resp = client.post(
        "/api/sboms/upload",
        params={"strict_ntia": "false"},
        data={"sbom_name": unique_name},
        files={"file": ("sbom.json", json.dumps(_DUPLICATE_CYCLONEDX), "application/json")}
    )
    assert resp.status_code == 202, resp.text
    body = resp.json()
    
    warnings = [w["code"] for w in body["warnings"]]
    assert W120_DUPLICATE_COMPONENT_DETECTED in warnings


def test_export_mode_original_vs_normalized(client, unique_name):
    """Test original (raw) vs normalized (deduplicated) export modes."""
    # 1. Upload the SBOM
    resp = client.post(
        "/api/sboms",
        json={"sbom_name": unique_name, "sbom_data": json.dumps(_DUPLICATE_CYCLONEDX)},
    )
    assert resp.status_code == 201
    sbom_id = resp.json()["id"]

    # 2. Export original mode (default / original)
    export_orig_resp = client.get(f"/api/sboms/{sbom_id}/export?export_mode=original")
    assert export_orig_resp.status_code == 200
    orig_data = export_orig_resp.json()
    # Should contain exactly 3 component definitions as uploaded (app + 2 lodash)
    assert len(orig_data["components"]) == 3

    # 3. Export normalized mode (deduplicated)
    export_norm_resp = client.get(f"/api/sboms/{sbom_id}/export?export_mode=normalized")
    assert export_norm_resp.status_code == 200
    norm_data = export_norm_resp.json()
    # Should contain 2 component definitions (app + canonical lodash)
    assert len(norm_data["components"]) == 2
    
    # Check that licenses are merged in the raw exported JSON for lodash
    lodash_comp = next(c for c in norm_data["components"] if c["name"] == "lodash")
    license_names = []
    for lic in lodash_comp.get("licenses", []):
        name = lic.get("license", {}).get("name") or lic.get("license", {}).get("id")
        if name:
            license_names.append(name)
    assert "MIT" in license_names
    assert "Apache-2.0" in license_names

    # Check dependency remapping in raw exported JSON
    deps = norm_data.get("dependencies", [])
    assert len(deps) == 2
    # The application component (pkg:generic/phase2-valid@1.0.0) should now depend on only one Lodash reference
    app_dep = next(d for d in deps if d.get("ref") == "pkg:generic/phase2-valid@1.0.0")
    assert app_dep["dependsOn"] == ["ref-lodash-1"]

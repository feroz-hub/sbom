from __future__ import annotations

import json
import uuid

from app.normalization.component_deduplicator import ComponentDeduplicator
from app.normalization.component_normalizer import normalize_component
from app.normalization.cpe_normalizer import normalize_cpes
from app.normalization.purl_normalizer import normalize_purl
from app.normalization.version_normalizer import normalize_version
from app.validation.pipeline import default_stages


def _duplicate_doc() -> dict:
    return {
        "bomFormat": "CycloneDX",
        "specVersion": "1.5",
        "serialNumber": "urn:uuid:11111111-2222-3333-4444-555555555555",
        "version": 1,
        "metadata": {"timestamp": "2026-06-29T10:00:00Z"},
        "components": [
            {
                "type": "library",
                "bom-ref": "lodash-a",
                "name": "Lodash",
                "version": "v4.17.21",
                "purl": "pkg:npm/lodash@4.17.21?z=9&a=1",
                "licenses": [{"license": {"id": "MIT"}}],
            },
            {
                "type": "library",
                "bom-ref": "lodash-b",
                "name": "lodash",
                "version": "4.17.21",
                "purl": "pkg:npm/lodash@4.17.21?a=1&z=9",
                "hashes": [{"alg": "SHA-1", "content": "1234567890abcdef1234567890abcdef12345678"}],
            },
            {
                "type": "library",
                "bom-ref": "requests",
                "name": "requests",
                "version": "2.32.0",
                "purl": "pkg:pypi/requests@2.32.0",
            },
        ],
        "dependencies": [{"ref": "requests", "dependsOn": ["lodash-a", "lodash-b"]}],
    }


def test_stage9_appears_after_signature():
    names = [stage.name for stage in default_stages()]
    assert names[-2:] == ["signature", "normalization"]


def test_purl_qualifier_sorting_and_version_normalization():
    result = normalize_purl("pkg:NPM/Lodash@v4.17.21?z=9&a=1")
    assert result.valid is True
    assert result.normalized_purl == "pkg:npm/lodash@4.17.21?a=1&z=9"
    assert normalize_version("0.105-33").normalized_version == "0.105-33"
    assert normalize_version("3.0.3A").normalized_version == "3.0.3A"


def test_cpe_23_normalization_deduplicates_exact_variants():
    result = normalize_cpes(
        " cpe:2.3:a:PostgreSQL:PostgreSQL:14.1:*:*:*:*:*:*:* ",
        "cpe:2.3:a:postgresql:postgresql:14.1:*:*:*:*:*:*:*",
    )
    assert result.primary_cpe == "cpe:2.3:a:postgresql:postgresql:14.1:*:*:*:*:*:*:*"
    assert len(result.normalized_cpes) == 1


def test_low_confidence_name_only_components_are_not_merged():
    components = [{"name": "same"}, {"name": "same"}]
    canonical, duplicates, *_ = ComponentDeduplicator.deduplicate(components, [])
    assert len(canonical) == 2
    assert duplicates == []


def test_same_name_different_ecosystem_not_merged():
    components = [
        {"name": "core", "version": "1.0.0", "ecosystem": "npm"},
        {"name": "core", "version": "1.0.0", "ecosystem": "pypi"},
    ]
    canonical, duplicates, *_ = ComponentDeduplicator.deduplicate(components, [])
    assert len(canonical) == 2
    assert duplicates == []


def test_deduplicator_groups_by_normalized_purl_and_remaps_relationships():
    components = [
        {"name": "Lodash", "version": "v4.17.21", "purl": "pkg:npm/lodash@4.17.21?z=9&a=1", "bom_ref": "a"},
        {"name": "lodash", "version": "4.17.21", "purl": "pkg:npm/lodash@4.17.21?a=1&z=9", "bom_ref": "b"},
    ]
    deps = [{"ref": "app", "dependsOn": ["a", "b"]}]
    canonical, duplicates, mapping, report, warnings = ComponentDeduplicator.deduplicate(components, deps)
    assert len(canonical) == 1
    assert len(duplicates) == 1
    assert mapping == {"b": "a"}
    assert report["summary"]["relationship_duplicates"] == 1
    assert warnings


def test_normalize_component_preserves_os_package_versions():
    normalized = normalize_component(
        {"name": "openssl", "version": "1:3.0.2-0ubuntu1", "ecosystem": "debian"}
    ).component
    assert normalized["normalized_version"] == "1:3.0.2-0ubuntu1"


def test_components_api_and_normalization_report(client):
    response = client.post(
        "/api/sboms",
        json={"sbom_name": f"stage9-api-{uuid.uuid4().hex[:8]}", "sbom_data": json.dumps(_duplicate_doc())},
    )
    assert response.status_code == 201, response.text
    sbom_id = response.json()["id"]

    hidden = client.get(f"/api/sboms/{sbom_id}/components")
    assert hidden.status_code == 200
    hidden_payload = hidden.json()
    assert hidden_payload["duplicate_count"] == 1
    assert len(hidden_payload["items"]) == 2
    assert all(not item.get("is_duplicate") for item in hidden_payload["items"])
    assert hidden_payload["items"][0].get("normalized_name")

    visible = client.get(f"/api/sboms/{sbom_id}/components?include_duplicates=true")
    assert visible.status_code == 200
    assert any(item.get("is_duplicate") for item in visible.json()["items"])

    report = client.get(f"/api/sboms/{sbom_id}/normalization-report")
    assert report.status_code == 200
    body = report.json()
    assert body["stage_number"] == 9
    assert body["summary"]["duplicate_components"] == 1
    assert body["duplicate_groups"]

    first = client.post(f"/api/sboms/{sbom_id}/normalize-deduplicate?force=true")
    second = client.post(f"/api/sboms/{sbom_id}/normalize-deduplicate?force=true")
    assert first.status_code == 200
    assert second.status_code == 200
    assert second.json()["report"]["summary"]["duplicate_components"] == 1

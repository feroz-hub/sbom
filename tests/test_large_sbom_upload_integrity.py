from __future__ import annotations

import json
import uuid
from pathlib import Path

import pytest
from app.db import SessionLocal
from app.models import SBOMSource
from app.parsing.extract import extract_components
from app.services.sbom_document_service import content_sha256, verify_upload_integrity


def _large_cyclonedx(component_count: int) -> dict:
    components = [
        {
            "type": "library",
            "bom-ref": f"pkg:generic/component-{index}@1.0.0",
            "name": f"component-{index}",
            "version": "1.0.0",
            "purl": f"pkg:generic/component-{index}@1.0.0",
        }
        for index in range(component_count)
    ]
    dependencies = [
        {"ref": components[index]["bom-ref"], "dependsOn": [components[index + 1]["bom-ref"]]}
        for index in range(component_count - 1)
    ]
    return {
        "bomFormat": "CycloneDX",
        "specVersion": "1.5",
        "serialNumber": f"urn:uuid:{uuid.uuid4()}",
        "version": 1,
        "metadata": {"timestamp": "2026-06-24T00:00:00Z"},
        "components": components,
        "dependencies": dependencies,
    }


@pytest.fixture()
def db(client):
    session = SessionLocal()
    try:
        yield session
    finally:
        session.rollback()
        session.close()


def test_large_cyclonedx_upload_preserves_content_and_components(client, db, tmp_path):
    doc = _large_cyclonedx(250)
    raw = json.dumps(doc, indent=2)
    path = tmp_path / "large.cdx.json"
    path.write_text(raw, encoding="utf-8")

    name = f"large-upload-{uuid.uuid4().hex[:8]}"
    response = client.post(
        "/api/sboms/upload",
        data={
            "sbom_name": name,
        },
        files={"file": ("large.cdx.json", raw.encode("utf-8"), "application/json")},
    )
    assert response.status_code == 202, response.text
    sbom_id = response.json()["sbom_id"]
    assert response.json()["components"] == 250

    stats = client.get(f"/api/sboms/{sbom_id}/stats")
    assert stats.status_code == 200
    body = stats.json()
    assert body["line_count"] == len(raw.splitlines())
    assert body["parsed_component_count"] == 250
    assert body["component_count"] == 250
    assert body["dependency_count"] == 249
    assert body["content_sha256"] == content_sha256(raw)

    raw_chunk = client.get(f"/api/sboms/{sbom_id}/raw?offset=0&limit=100")
    assert raw_chunk.status_code == 200
    chunk = raw_chunk.json()
    assert chunk["total_lines"] == len(raw.splitlines())
    assert len(chunk["lines"]) == 100
    assert chunk["preview"] is True
    assert chunk["truncated"] is True

    download = client.get(f"/api/sboms/{sbom_id}/download")
    assert download.status_code == 200
    assert download.content.decode("utf-8") == raw
    assert content_sha256(download.content.decode("utf-8")) == content_sha256(raw)

    detail = client.get(f"/api/sboms/{sbom_id}")
    assert detail.status_code == 200
    assert detail.json().get("sbom_data") is None

    components = client.get(f"/api/sboms/{sbom_id}/components?page=1&page_size=10")
    assert components.status_code == 200
    payload = components.json()
    assert len(payload["items"]) == 10
    assert payload["total_count"] == 250

    report = verify_upload_integrity(db, sbom_id, original_path=str(path))
    assert report["sha256_match"] is True
    assert report["line_count_match"] is True
    assert report["component_count_match"] is True
    assert report["truncation_detected"] is False


def test_large_spdx_sample_integrity(client, db):
    sample = Path("samples/RI_HIP_v1-novex_spdx.json")
    if not sample.exists():
        pytest.skip("large SPDX sample not available")
    raw = sample.read_text(encoding="utf-8")
    expected_components = len(extract_components(raw))

    name = f"large-spdx-{uuid.uuid4().hex[:8]}"
    response = client.post(
        "/api/sboms/upload",
        data={"sbom_name": name},
        files={"file": (sample.name, raw.encode("utf-8"), "application/json")},
    )
    assert response.status_code == 202, response.text
    sbom_id = response.json()["sbom_id"]

    stats = client.get(f"/api/sboms/{sbom_id}/stats").json()
    assert stats["parsed_component_count"] == expected_components
    assert stats["component_count"] == expected_components
    assert stats["relationship_count"] >= 900

    report = verify_upload_integrity(db, sbom_id, original_path=str(sample))
    assert report["truncation_detected"] is False


def test_get_sbom_include_raw_returns_full_document(client):
    doc = _large_cyclonedx(3)
    raw = json.dumps(doc)
    name = f"include-raw-{uuid.uuid4().hex[:8]}"
    upload = client.post(
        "/api/sboms/upload",
        data={"sbom_name": name},
        files={"file": ("tiny.cdx.json", raw.encode("utf-8"), "application/json")},
    )
    sbom_id = upload.json()["sbom_id"]

    without_raw = client.get(f"/api/sboms/{sbom_id}")
    with_raw = client.get(f"/api/sboms/{sbom_id}?include_raw=true")
    assert without_raw.json().get("sbom_data") is None
    assert with_raw.json().get("sbom_data") == raw


def test_list_sboms_omits_raw_payload(client, db):
    sbom = SBOMSource(
        sbom_name=f"list-omit-{uuid.uuid4().hex[:8]}",
        sbom_data='{"bomFormat":"CycloneDX"}',
        status="validated",
    )
    db.add(sbom)
    db.commit()

    listed = client.get("/api/sboms?page_size=500")
    assert listed.status_code == 200
    match = next(item for item in listed.json() if item["id"] == sbom.id)
    assert match.get("sbom_data") is None

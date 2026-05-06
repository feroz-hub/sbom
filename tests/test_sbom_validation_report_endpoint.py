"""Phase 3 — read endpoints for the persisted validation report.

Locks the contract for:

* ``GET /api/sboms/{id}/validation-report`` — full structured report
  with per-entry ``stage_number`` enrichment and pre-aggregated
  severity / stage summaries.
* ``GET /api/sboms?status=...&stage=...`` — list filters keyed off
  the columns added in migration 012.
"""

from __future__ import annotations

import json
import uuid

import pytest

_VALID_CYCLONEDX = {
    "bomFormat": "CycloneDX",
    "specVersion": "1.5",
    "serialNumber": "urn:uuid:11111111-2222-3333-4444-555555555555",
    "version": 1,
    "metadata": {
        "timestamp": "2026-04-30T12:00:00Z",
        "component": {
            "type": "application",
            "bom-ref": "pkg:generic/phase3-valid@1.0.0",
            "name": "phase3-valid",
            "version": "1.0.0",
        },
    },
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

_BAD_PURL_CYCLONEDX = {
    "bomFormat": "CycloneDX",
    "specVersion": "1.6",
    "serialNumber": "urn:uuid:99999999-aaaa-bbbb-cccc-dddddddddddd",
    "version": 1,
    "metadata": {"timestamp": "2026-04-30T12:00:00Z"},
    "components": [
        {
            "type": "library",
            "bom-ref": "x",
            "name": "x",
            "version": "1.0.0",
            "purl": "not-a-purl",
        }
    ],
    "dependencies": [],
}


def _unique(prefix: str) -> str:
    return f"{prefix}-{uuid.uuid4().hex[:8]}"


@pytest.fixture
def failed_sbom_id(client) -> int:
    resp = client.post(
        "/api/sboms",
        json={"sbom_name": _unique("phase3-fail"), "sbom_data": json.dumps(_BAD_PURL_CYCLONEDX)},
    )
    assert resp.status_code == 422, resp.text
    return resp.json()["detail"]["sbom_id"]


@pytest.fixture
def validated_sbom_id(client) -> int:
    resp = client.post(
        "/api/sboms",
        json={"sbom_name": _unique("phase3-ok"), "sbom_data": json.dumps(_VALID_CYCLONEDX)},
    )
    assert resp.status_code == 201, resp.text
    return resp.json()["id"]


def test_validation_report_for_failed_upload(client, failed_sbom_id: int):
    resp = client.get(f"/api/sboms/{failed_sbom_id}/validation-report")
    assert resp.status_code == 200, resp.text
    body = resp.json()

    assert body["sbom_id"] == failed_sbom_id
    assert body["status"] == "failed"
    assert body["failed_stage"] == "semantic"
    assert body["error_count"] >= 1
    assert body["spec_detected"] == "cyclonedx"
    assert body["spec_version_detected"] == "1.6"

    # Pre-aggregated summaries
    assert body["severity_summary"].get("error", 0) >= 1
    assert body["stage_summary"].get("semantic", 0) >= 1

    # Per-entry stage_number enrichment
    assert body["entries"], body
    semantic_entry = next(e for e in body["entries"] if e["stage"] == "semantic")
    assert semantic_entry["stage_number"] == 4
    assert semantic_entry["code"].startswith("SBOM_VAL_")
    # Field set the UI keys off
    assert {"code", "severity", "stage", "stage_number", "path", "message", "remediation"}.issubset(
        semantic_entry.keys()
    )


def test_validation_report_for_clean_upload(client, validated_sbom_id: int):
    resp = client.get(f"/api/sboms/{validated_sbom_id}/validation-report")
    assert resp.status_code == 200, resp.text
    body = resp.json()
    assert body["status"] == "validated"
    assert body["failed_stage"] is None
    assert body["error_count"] == 0
    # Warnings (NTIA) may exist; the report still reports them honestly.
    if body["warning_count"] > 0:
        assert body["severity_summary"].get("warning", 0) == body["warning_count"]


def test_validation_report_404_on_unknown_id(client):
    resp = client.get("/api/sboms/99999999/validation-report")
    assert resp.status_code == 404


def test_list_filter_by_status_failed(client, failed_sbom_id: int, validated_sbom_id: int):
    resp = client.get("/api/sboms?status=failed&page_size=500")
    assert resp.status_code == 200, resp.text
    rows = resp.json()
    ids = [r["id"] for r in rows]
    assert failed_sbom_id in ids
    assert validated_sbom_id not in ids
    for row in rows:
        assert row["status"] == "failed"


def test_list_filter_by_stage_semantic(client, failed_sbom_id: int):
    resp = client.get("/api/sboms?stage=semantic&page_size=500")
    assert resp.status_code == 200, resp.text
    rows = resp.json()
    assert failed_sbom_id in [r["id"] for r in rows]
    for row in rows:
        assert row["failed_stage"] == "semantic"


def test_list_filter_rejects_unknown_status(client):
    resp = client.get("/api/sboms?status=bogus")
    assert resp.status_code == 422


def test_list_filter_rejects_unknown_stage(client):
    resp = client.get("/api/sboms?stage=bogus")
    assert resp.status_code == 422

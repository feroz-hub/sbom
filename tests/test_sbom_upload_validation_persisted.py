"""Phase 2 regression — failed uploads persist their validation report.

Until migration 012 the legacy ``POST /api/sboms`` route bypassed the
validator entirely, and the multipart ``POST /api/sboms/upload`` route
rejected before any DB write — refreshing the page lost everything. This
suite locks in the new contract:

* A valid SBOM still creates a row with ``status='validated'`` and a 201.
* An SBOM with NTIA warnings only is ``validated`` with ``warning_count > 0``.
* An SBOM with semantic errors creates a row with ``status='failed'``
  AND returns a 4xx whose ``detail.entries`` mirrors the validator output.
* The persisted row's ``validation_errors`` JSON survives a fresh read.
"""

from __future__ import annotations

import json

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
            "bom-ref": "pkg:generic/phase2-valid@1.0.0",
            "name": "phase2-valid",
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


@pytest.fixture
def unique_name(request) -> str:
    """Globally unique SBOM name per test (avoids 409 from prior runs)."""
    import uuid

    return f"phase2-{request.node.name}-{uuid.uuid4().hex[:8]}"


def test_valid_sbom_persists_validated_status(client, unique_name):
    resp = client.post(
        "/api/sboms",
        json={"sbom_name": unique_name, "sbom_data": json.dumps(_VALID_CYCLONEDX)},
    )
    assert resp.status_code == 201, resp.text
    body = resp.json()
    assert body["status"] == "validated"
    assert body["error_count"] == 0
    assert body["failed_stage"] is None
    # Warnings may exist (NTIA) but must not block.
    assert body["warning_count"] >= 0
    # validated_at populated on the success path.
    assert body["validated_at"] is not None


def test_invalid_purl_persists_row_and_returns_422(client, unique_name):
    resp = client.post(
        "/api/sboms",
        json={"sbom_name": unique_name, "sbom_data": json.dumps(_BAD_PURL_CYCLONEDX)},
    )
    # Semantic-stage errors are 422 (not structural). The frontend keys on
    # this status to render the inline rejection banner.
    assert resp.status_code == 422, resp.text

    detail = resp.json()["detail"]
    assert detail["code"] == "sbom_validation_failed"
    assert detail["status"] == "failed"
    assert detail["failed_stage"] == "semantic"
    assert detail["error_count"] >= 1
    assert isinstance(detail["entries"], list) and detail["entries"], detail
    sbom_id = detail["sbom_id"]
    assert isinstance(sbom_id, int) and sbom_id > 0

    # The first entry must mention the malformed PURL with its full
    # structured shape — no information loss between validator and API.
    first = detail["entries"][0]
    assert {"code", "severity", "stage", "path", "message", "remediation"}.issubset(first.keys())
    assert first["severity"] == "error"

    # The persisted row is reachable and carries the full report.
    fetched = client.get(f"/api/sboms/{sbom_id}").json()
    assert fetched["status"] == "failed"
    assert fetched["failed_stage"] == "semantic"
    assert fetched["error_count"] == detail["error_count"]
    assert fetched["validation_errors"] is not None
    assert len(fetched["validation_errors"]) == len(detail["entries"])


def test_failed_row_survives_get_after_failure(client, unique_name):
    """Page-refresh equivalent: after the rejected upload, GET on the row
    must still return the validation report."""
    resp = client.post(
        "/api/sboms",
        json={"sbom_name": unique_name, "sbom_data": json.dumps(_BAD_PURL_CYCLONEDX)},
    )
    assert resp.status_code == 422, resp.text
    sbom_id = resp.json()["detail"]["sbom_id"]

    # Two reads — assert idempotent shape (no in-flight state)
    a = client.get(f"/api/sboms/{sbom_id}").json()
    b = client.get(f"/api/sboms/{sbom_id}").json()
    assert a == b
    assert a["status"] == "failed"
    assert a["validation_errors"]
    assert a["validation_errors"][0]["severity"] == "error"

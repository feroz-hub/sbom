"""
Endpoint-level tests for the CVE detail router.

Patches ``CveDetailService`` so we don't pull in the full source-fetch path
— that is covered separately in ``test_cve_clients.py`` and
``test_cve_service.py``. These tests assert the HTTP contract:

  * 400 on a malformed CVE ID
  * 200 with the expected payload shape on a known CVE
  * batch endpoint enforces size + returns the keyed map
  * scan-aware variant routes through and returns a 200 even when the scan
    doesn't carry that CVE (partial-data, never a 500)
"""

from __future__ import annotations

from datetime import datetime, timezone

import pytest

from app.integrations.cve.base import FetchOutcome, FetchResult
from app.schemas_cve import CveDetail, CveExploitation


def _stub_detail(cve_id: str) -> CveDetail:
    return CveDetail(
        cve_id=cve_id,
        summary="stub",
        sources_used=["osv"],
        is_partial=False,
        fetched_at=datetime.now(timezone.utc),
        exploitation=CveExploitation(),
    )


def test_get_cve_detail_400_on_bad_id(client):
    resp = client.get("/api/v1/cves/not-a-cve")
    assert resp.status_code == 400


def test_get_cve_detail_200_happy_path(client, monkeypatch):
    async def _fake_get(self, cve_id):  # noqa: ARG001
        return _stub_detail(cve_id)

    monkeypatch.setattr("app.services.cve_service.CveDetailService.get", _fake_get)

    resp = client.get("/api/v1/cves/CVE-2024-12345")
    assert resp.status_code == 200, resp.text
    body = resp.json()
    assert body["cve_id"] == "CVE-2024-12345"
    assert body["summary"] == "stub"
    assert body["sources_used"] == ["osv"]
    assert body["is_partial"] is False


def test_post_batch_returns_keyed_map(client, monkeypatch):
    async def _fake_get_many(self, ids):  # noqa: ARG001
        return {cve: _stub_detail(cve) for cve in ids}

    monkeypatch.setattr("app.services.cve_service.CveDetailService.get_many", _fake_get_many)

    resp = client.post("/api/v1/cves/batch", json={"ids": ["CVE-2024-1111", "cve-2024-2222"]})
    assert resp.status_code == 200, resp.text
    body = resp.json()
    assert set(body["items"].keys()) == {"CVE-2024-1111", "CVE-2024-2222"}


def test_post_batch_rejects_too_many_ids(client):
    too_many = [f"CVE-2024-{i:05d}" for i in range(60)]
    resp = client.post("/api/v1/cves/batch", json={"ids": too_many})
    assert resp.status_code == 422


def test_post_batch_rejects_all_garbage(client):
    resp = client.post("/api/v1/cves/batch", json={"ids": ["not-a-cve"]})
    # ID is well-formed-string but fails our normaliser; service path is
    # not even reached because all IDs are rejected at the validator.
    assert resp.status_code == 400


def test_get_scan_variant_200(client, monkeypatch):
    from app.schemas_cve import CveDetailWithContext, CveScanContext

    async def _fake(self, cve_id, scan_id):  # noqa: ARG001
        base = _stub_detail(cve_id).model_dump()
        return CveDetailWithContext(
            **base,
            component=CveScanContext(name="left-pad", version="1.2.0", ecosystem="npm", purl=None),
            current_version_status="vulnerable",
            recommended_upgrade="1.3.1",
        )

    monkeypatch.setattr(
        "app.services.cve_service.CveDetailService.get_with_scan_context", _fake
    )
    resp = client.get("/api/v1/scans/123/cves/CVE-2024-12345")
    assert resp.status_code == 200, resp.text
    body = resp.json()
    assert body["component"]["name"] == "left-pad"
    assert body["recommended_upgrade"] == "1.3.1"
    assert body["current_version_status"] == "vulnerable"

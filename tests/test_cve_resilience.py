"""
Backend resilience tests — extra permutations beyond test_cve_clients.py.

The Phase 2 client suite already covers OK / NOT_FOUND / 5xx-once / 4xx /
malformed-JSON / circuit-open. This file adds:

  * Retry exhaustion (every attempt 5xx) → ERROR
  * Pure timeout (transport never responds) → ERROR
  * GHSA GraphQL-level errors[] → ERROR (not OK with empty data)
  * NVD with auth header set → no apiKey-less throttle
"""

from __future__ import annotations

import httpx
import pytest

from app.integrations.cve.base import FetchOutcome
from app.integrations.cve.ghsa import GhsaClient
from app.integrations.cve.nvd import NvdClient
from app.integrations.cve.osv import OsvClient


def _patch_async_client(monkeypatch, handler):
    transport = httpx.MockTransport(handler)
    fake = httpx.AsyncClient(transport=transport)
    import app.http_client as http_mod
    import app.integrations.cve.ghsa as ghsa_mod
    import app.integrations.cve.nvd as nvd_mod
    import app.integrations.cve.osv as osv_mod

    def _get():
        return fake

    monkeypatch.setattr(http_mod, "get_async_http_client", _get)
    monkeypatch.setattr(osv_mod, "get_async_http_client", _get)
    monkeypatch.setattr(ghsa_mod, "get_async_http_client", _get)
    monkeypatch.setattr(nvd_mod, "get_async_http_client", _get)
    return fake


@pytest.mark.asyncio
async def test_osv_retries_exhaust_to_error(monkeypatch):
    """Every attempt 5xx → ERROR after retries-exhausted; transport hit (1+retries) times."""
    counter = {"calls": 0}

    def handler(req):
        counter["calls"] += 1
        return httpx.Response(500)

    _patch_async_client(monkeypatch, handler)

    res = await OsvClient().fetch("CVE-2099-0001")
    assert res.outcome == FetchOutcome.ERROR
    # OsvClient default retries=2 → 1 initial + 2 retries = 3 attempts.
    assert counter["calls"] == 3


@pytest.mark.asyncio
async def test_osv_timeout_is_error(monkeypatch):
    """Transport that always times out → ERROR after retries; never raises."""

    def handler(req):
        raise httpx.ReadTimeout("simulated timeout", request=req)

    _patch_async_client(monkeypatch, handler)

    res = await OsvClient().fetch("CVE-2099-0001")
    assert res.outcome == FetchOutcome.ERROR
    assert "timeout" in (res.error or "").lower()


@pytest.mark.asyncio
async def test_ghsa_graphql_error_payload_is_error(monkeypatch):
    """GraphQL errors[] block at the body level → ERROR, never OK."""
    monkeypatch.setenv("GITHUB_TOKEN", "fake-pat")
    from app.settings import reset_settings

    reset_settings()
    payload = {"errors": [{"message": "Field 'foo' doesn't exist"}], "data": None}
    _patch_async_client(monkeypatch, lambda req: httpx.Response(200, json=payload))

    res = await GhsaClient().fetch("CVE-2099-9001")
    assert res.outcome == FetchOutcome.ERROR
    assert "doesn't exist" in (res.error or "")


@pytest.mark.asyncio
async def test_ghsa_4xx_auth_error(monkeypatch):
    """A 401 from GHSA (revoked PAT) → ERROR with the http status surfaced."""
    monkeypatch.setenv("GITHUB_TOKEN", "fake-pat")
    from app.settings import reset_settings

    reset_settings()
    _patch_async_client(monkeypatch, lambda req: httpx.Response(401, json={"message": "Bad credentials"}))

    res = await GhsaClient().fetch("CVE-2099-9001")
    assert res.outcome == FetchOutcome.ERROR
    assert "401" in (res.error or "")


@pytest.mark.asyncio
async def test_nvd_uses_apikey_header_when_configured(monkeypatch):
    """Setting nvd_api_key flips throttle to the higher rate AND sends apiKey header."""
    monkeypatch.setenv("CVE_NVD_AUTH_THROTTLE_SECONDS", "0")
    monkeypatch.setenv("CVE_NVD_UNAUTH_THROTTLE_SECONDS", "0")
    monkeypatch.setenv("NVD_API_KEY", "test-key-1234")
    from app.settings import reset_settings

    reset_settings()

    seen = {"apiKey": None}

    def handler(req):
        seen["apiKey"] = req.headers.get("apiKey")
        return httpx.Response(200, json={"vulnerabilities": []})

    _patch_async_client(monkeypatch, handler)

    res = await NvdClient().fetch("CVE-2099-0099")
    assert res.outcome == FetchOutcome.NOT_FOUND
    assert seen["apiKey"] == "test-key-1234"


@pytest.mark.asyncio
async def test_nvd_response_without_metrics_block(monkeypatch):
    """A CVE with no CVSS metrics → OK with no scores set, no exception."""
    monkeypatch.setenv("CVE_NVD_UNAUTH_THROTTLE_SECONDS", "0")
    from app.settings import reset_settings

    reset_settings()
    payload = {
        "vulnerabilities": [
            {
                "cve": {
                    "descriptions": [{"lang": "en", "value": "no metrics on this row"}],
                    "metrics": {},
                    "weaknesses": [],
                    "references": [],
                }
            }
        ]
    }
    _patch_async_client(monkeypatch, lambda req: httpx.Response(200, json=payload))

    res = await NvdClient().fetch("CVE-2099-0099")
    assert res.outcome == FetchOutcome.OK
    assert "cvss_v3_score" not in res.data
    assert res.data["summary"] == "no metrics on this row"

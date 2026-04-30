"""
Source-client tests — exercise OSV / GHSA / NVD parsers and resilience.

We replace the shared async httpx client with a per-test ``httpx.AsyncClient``
backed by ``httpx.MockTransport`` so each test can script the upstream
response. No real network. The OsvClient / GhsaClient / NvdClient call
``app.http_client.get_async_http_client``, which we monkeypatch.
"""

from __future__ import annotations

import httpx
import pytest

from app.integrations.cve.base import FetchOutcome
from app.integrations.cve.ghsa import GhsaClient
from app.integrations.cve.nvd import NvdClient
from app.integrations.cve.osv import OsvClient


# ------------------------------------------------------------------ helpers


def _patch_async_client(monkeypatch, handler):
    """Install an httpx.AsyncClient backed by MockTransport(handler)."""
    transport = httpx.MockTransport(handler)
    fake = httpx.AsyncClient(transport=transport)
    import app.http_client as http_mod
    import app.integrations.cve.osv as osv_mod
    import app.integrations.cve.ghsa as ghsa_mod
    import app.integrations.cve.nvd as nvd_mod

    def _get():
        return fake

    monkeypatch.setattr(http_mod, "get_async_http_client", _get)
    monkeypatch.setattr(osv_mod, "get_async_http_client", _get)
    monkeypatch.setattr(ghsa_mod, "get_async_http_client", _get)
    monkeypatch.setattr(nvd_mod, "get_async_http_client", _get)
    return fake


# ------------------------------------------------------------------ OSV


@pytest.mark.asyncio
async def test_osv_parses_full_record(monkeypatch):
    payload = {
        "summary": "left-pad RCE",
        "details": "Long form details.",
        "aliases": ["GHSA-fake-osv", "CVE-2099-9001"],
        "published": "2024-01-15T00:00:00Z",
        "modified": "2024-01-20T00:00:00Z",
        "database_specific": {"cwe_ids": ["CWE-79"], "severity": "MODERATE"},
        "severity": [{"type": "CVSS_V3", "score": "CVSS:3.1/AV:N/AC:L"}],
        "affected": [
            {
                "package": {"ecosystem": "npm", "name": "left-pad"},
                "ranges": [
                    {
                        "type": "ECOSYSTEM",
                        "events": [{"introduced": "0.0.1"}, {"fixed": "1.3.1"}],
                    }
                ],
            }
        ],
        "references": [
            {"type": "ADVISORY", "url": "https://example.com/advisory"},
            {"type": "FIX", "url": "https://example.com/patch"},
        ],
    }
    _patch_async_client(monkeypatch, lambda req: httpx.Response(200, json=payload))

    res = await OsvClient().fetch("CVE-2099-9001")
    assert res.outcome == FetchOutcome.OK
    assert res.data["summary"] == "left-pad RCE"
    assert res.data["cwe_ids"] == ["CWE-79"]
    fixed = [fv["fixed_in"] for fv in res.data["fix_versions"]]
    assert fixed == ["1.3.1"]
    types = [r["type"] for r in res.data["references"]]
    assert "advisory" in types and "fix" in types


@pytest.mark.asyncio
async def test_osv_404_is_not_found(monkeypatch):
    _patch_async_client(monkeypatch, lambda req: httpx.Response(404, json={}))
    res = await OsvClient().fetch("CVE-2099-9999")
    assert res.outcome == FetchOutcome.NOT_FOUND


@pytest.mark.asyncio
async def test_osv_5xx_is_error(monkeypatch):
    _patch_async_client(monkeypatch, lambda req: httpx.Response(503, text="upstream"))
    res = await OsvClient().fetch("CVE-2099-9001")
    assert res.outcome == FetchOutcome.ERROR


@pytest.mark.asyncio
async def test_osv_malformed_json_is_error(monkeypatch):
    _patch_async_client(
        monkeypatch,
        lambda req: httpx.Response(200, content=b"not json", headers={"content-type": "application/json"}),
    )
    res = await OsvClient().fetch("CVE-2099-9001")
    assert res.outcome == FetchOutcome.ERROR


# ------------------------------------------------------------------ GHSA


@pytest.mark.asyncio
async def test_ghsa_disabled_when_no_token(monkeypatch):
    # Force-clear: setenv overrides the project's .env file (which carries
    # a real GITHUB_TOKEN for dev). delenv would leave .env intact.
    monkeypatch.setenv("GITHUB_TOKEN", "")
    from app.settings import reset_settings

    reset_settings()
    res = await GhsaClient().fetch("CVE-2099-9001")
    assert res.outcome == FetchOutcome.DISABLED


@pytest.mark.asyncio
async def test_ghsa_parses_record(monkeypatch):
    monkeypatch.setenv("GITHUB_TOKEN", "fake-pat")
    from app.settings import reset_settings

    reset_settings()
    payload = {
        "data": {
            "securityAdvisories": {
                "nodes": [
                    {
                        "ghsaId": "GHSA-fake-osv",
                        "summary": "Title",
                        "description": "Long prose",
                        "severity": "CRITICAL",
                        "publishedAt": "2024-01-15T00:00:00Z",
                        "updatedAt": "2024-01-20T00:00:00Z",
                        "cwes": {"nodes": [{"cweId": "CWE-79", "name": "XSS"}]},
                        "identifiers": [{"type": "CVE", "value": "CVE-2099-9001"}],
                        "references": [{"url": "https://github.com/advisories/x"}],
                        "vulnerabilities": {
                            "nodes": [
                                {
                                    "package": {"ecosystem": "NPM", "name": "left-pad"},
                                    "firstPatchedVersion": {"identifier": "1.3.1"},
                                    "vulnerableVersionRange": "<1.3.1",
                                }
                            ]
                        },
                    }
                ]
            }
        }
    }
    _patch_async_client(monkeypatch, lambda req: httpx.Response(200, json=payload))
    res = await GhsaClient().fetch("CVE-2099-9001")
    assert res.outcome == FetchOutcome.OK
    assert res.data["title"] == "Title"
    assert res.data["severity"] == "critical"
    assert res.data["cwe_ids"] == ["CWE-79"]
    assert res.data["fix_versions"][0]["fixed_in"] == "1.3.1"


@pytest.mark.asyncio
async def test_ghsa_no_advisories_is_not_found(monkeypatch):
    monkeypatch.setenv("GITHUB_TOKEN", "fake-pat")
    from app.settings import reset_settings

    reset_settings()
    _patch_async_client(
        monkeypatch,
        lambda req: httpx.Response(200, json={"data": {"securityAdvisories": {"nodes": []}}}),
    )
    res = await GhsaClient().fetch("CVE-2099-9999")
    assert res.outcome == FetchOutcome.NOT_FOUND


# ------------------------------------------------------------------ NVD


@pytest.mark.asyncio
async def test_nvd_parses_v3_metrics(monkeypatch):
    # Force the unauth throttle to ~0 so the test isn't slow.
    monkeypatch.setenv("CVE_NVD_UNAUTH_THROTTLE_SECONDS", "0")
    from app.settings import reset_settings

    reset_settings()
    payload = {
        "vulnerabilities": [
            {
                "cve": {
                    "descriptions": [{"lang": "en", "value": "NVD CVE description"}],
                    "published": "2024-01-15T00:00:00",
                    "lastModified": "2024-01-22T00:00:00",
                    "metrics": {
                        "cvssMetricV31": [
                            {
                                "cvssData": {
                                    "baseScore": 9.8,
                                    "vectorString": "CVSS:3.1/AV:N",
                                    "attackVector": "NETWORK",
                                    "attackComplexity": "LOW",
                                    "privilegesRequired": "NONE",
                                    "userInteraction": "NONE",
                                }
                            }
                        ]
                    },
                    "weaknesses": [
                        {"description": [{"value": "CWE-79"}, {"value": "CWE-89"}]}
                    ],
                    "references": [
                        {"url": "https://nvd.nist.gov/x", "tags": ["Vendor Advisory"]},
                        {"url": "https://example.com/patch", "tags": ["Patch"]},
                    ],
                }
            }
        ]
    }
    _patch_async_client(monkeypatch, lambda req: httpx.Response(200, json=payload))
    res = await NvdClient().fetch("CVE-2099-9001")
    assert res.outcome == FetchOutcome.OK
    assert res.data["cvss_v3_score"] == 9.8
    assert res.data["attack_vector"] == "NETWORK"
    assert sorted(res.data["cwe_ids"]) == ["CWE-79", "CWE-89"]
    types = {r["type"] for r in res.data["references"]}
    assert "patch" in types
    assert "advisory" in types


@pytest.mark.asyncio
async def test_nvd_429_is_error(monkeypatch):
    monkeypatch.setenv("CVE_NVD_UNAUTH_THROTTLE_SECONDS", "0")
    from app.settings import reset_settings

    reset_settings()
    _patch_async_client(monkeypatch, lambda req: httpx.Response(429, json={}))
    res = await NvdClient().fetch("CVE-2099-9001")
    assert res.outcome == FetchOutcome.ERROR
    assert res.error == "rate-limited"


@pytest.mark.asyncio
async def test_nvd_empty_vulnerabilities_is_not_found(monkeypatch):
    monkeypatch.setenv("CVE_NVD_UNAUTH_THROTTLE_SECONDS", "0")
    from app.settings import reset_settings

    reset_settings()
    _patch_async_client(monkeypatch, lambda req: httpx.Response(200, json={"vulnerabilities": []}))
    res = await NvdClient().fetch("CVE-2099-9999")
    assert res.outcome == FetchOutcome.NOT_FOUND


# ------------------------------------------------------------ circuit breaker


@pytest.mark.asyncio
async def test_circuit_breaker_opens_after_consecutive_failures(monkeypatch):
    """Five consecutive 5xx → next call short-circuits without HTTP."""
    counter = {"calls": 0}

    def handler(req):
        counter["calls"] += 1
        return httpx.Response(503)

    _patch_async_client(monkeypatch, handler)

    client = OsvClient()
    # Drive the breaker to its threshold.
    for _ in range(5):
        await client.fetch("CVE-2099-0001")
    calls_before = counter["calls"]

    # Sixth call — circuit is open; OsvClient should NOT hit the transport.
    res = await client.fetch("CVE-2099-0002")
    assert res.outcome == FetchOutcome.CIRCUIT_OPEN
    assert counter["calls"] == calls_before, "circuit-open should skip the HTTP call"

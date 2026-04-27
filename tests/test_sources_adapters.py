"""
Phase-2 smoke tests for the new ``app.sources`` adapter package.

These verify the *call shape* and the registry contract — not the
underlying source-fetcher behaviour, which is locked by the snapshot
tests in test_sboms_analyze_snapshot.py.

The point of these tests is to give Phase 3 / Phase 4 a green light:
if the adapter classes can be instantiated and ``query()`` produces a
``SourceResult``, the cut-overs can start.
"""

from __future__ import annotations

import asyncio

import pytest
from app.sources import (
    SOURCE_REGISTRY,
    GhsaSource,
    NvdSource,
    OsvSource,
    VulnDbSource,
    VulnSource,
    empty_result,
    get_source,
)


def test_registry_contains_all_sources():
    assert set(SOURCE_REGISTRY) == {"NVD", "OSV", "GITHUB", "VULNDB"}


def test_get_source_is_case_insensitive():
    assert get_source("nvd") is NvdSource
    assert get_source("Osv") is OsvSource
    assert get_source("GITHUB") is GhsaSource
    assert get_source("vulndb") is VulnDbSource


def test_get_source_unknown_raises():
    with pytest.raises(KeyError, match="Unknown vulnerability source"):
        get_source("snyk")


def test_every_adapter_satisfies_protocol():
    """
    The Protocol is runtime-checkable, so isinstance() should accept any
    adapter instance. This catches accidental drift in the contract
    (e.g., someone removing the ``name`` attribute or renaming ``query``).
    """
    assert isinstance(NvdSource(api_key="x"), VulnSource)
    assert isinstance(OsvSource(), VulnSource)
    assert isinstance(GhsaSource(token="x"), VulnSource)
    assert isinstance(VulnDbSource(api_key="x"), VulnSource)


def test_adapters_short_circuit_on_empty_components():
    """
    All adapters MUST short-circuit when components is empty so the
    orchestrator can call them blindly without checking. This is also the
    only ``query()`` path we can exercise here without monkeypatching the
    underlying analysis.* coroutines.
    """
    cfg = object()  # adapters never touch settings on the empty path

    async def _run():
        return [
            await NvdSource(api_key=None).query([], cfg),
            await OsvSource().query([], cfg),
            await GhsaSource(token=None).query([], cfg),
            await VulnDbSource(api_key=None).query([], cfg),
        ]

    results = asyncio.run(_run())
    for r in results:
        # SourceResult is a TypedDict at runtime — it's a plain dict.
        assert isinstance(r, dict)
        assert r == empty_result() == {"findings": [], "errors": [], "warnings": []}
        assert set(r) == {"findings", "errors", "warnings"}


def test_adapters_route_through_underlying_analysis_functions(monkeypatch):
    """
    Patch the underlying analysis.* coroutines that each adapter delegates
    to, then assert the adapter (a) calls them with the expected args and
    (b) wraps the (findings, errors, warnings) tuple into a SourceResult.

    This is the contract Phase 3 / 4 will lean on.
    """
    captured: dict = {}

    async def fake_nvd(components, settings, nvd_api_key=None):
        captured["nvd_args"] = (components, settings, nvd_api_key)
        return [{"vuln_id": "CVE-X"}], [{"source": "NVD", "error": "warn"}], []

    async def fake_osv(components, settings):
        captured["osv_args"] = (components, settings)
        return [{"vuln_id": "OSV-Y"}], [], [{"warn": True}]

    async def fake_ghsa(components, settings):
        # The adapter should have spliced its constructor token into
        # settings.gh_token_override before calling us.
        captured["ghsa_args"] = (components, settings)
        return [{"vuln_id": "GHSA-Z"}], [], []

    import app.analysis as analysis_mod

    monkeypatch.setattr(analysis_mod, "nvd_query_by_components_async", fake_nvd)
    monkeypatch.setattr(analysis_mod, "osv_query_by_components", fake_osv)
    monkeypatch.setattr(analysis_mod, "github_query_by_components", fake_ghsa)

    cfg = analysis_mod.get_analysis_settings_multi()
    components = [{"name": "x", "version": "1"}]

    async def _run():
        return (
            await NvdSource(api_key="key-123").query(components, cfg),
            await OsvSource().query(components, cfg),
            await GhsaSource(token="ghp_abc").query(components, cfg),
        )

    nvd_result, osv_result, ghsa_result = asyncio.run(_run())

    # NVD: api key threaded explicitly, no os.environ involved
    assert captured["nvd_args"] == (components, cfg, "key-123")
    assert nvd_result == {
        "findings": [{"vuln_id": "CVE-X"}],
        "errors": [{"source": "NVD", "error": "warn"}],
        "warnings": [],
    }

    # OSV: settings passed through unchanged
    assert captured["osv_args"] == (components, cfg)
    assert osv_result["findings"] == [{"vuln_id": "OSV-Y"}]
    assert osv_result["warnings"] == [{"warn": True}]

    # GHSA: token spliced onto settings.gh_token_override (proves the
    # constructor-bound token is honoured without touching os.environ)
    ghsa_components, ghsa_settings = captured["ghsa_args"]
    assert ghsa_components == components
    assert getattr(ghsa_settings, "gh_token_override", None) == "ghp_abc"
    assert ghsa_result["findings"] == [{"vuln_id": "GHSA-Z"}]


def test_vulndb_adapter_skips_without_api_key():
    cfg = type("Cfg", (), {"vulndb_api_key_env": "VULNDB_API_KEY"})()

    async def _run():
        return await VulnDbSource(api_key=None).query([{"name": "openssl", "version": "1.1.1"}], cfg)

    result = asyncio.run(_run())
    assert result["findings"] == []
    assert result["errors"] == []
    assert result["warnings"] == [{"source": "VULNDB", "warning": "Missing API key env: VULNDB_API_KEY"}]


def test_vulndb_adapter_maps_api_results(monkeypatch):
    import app.sources.vulndb as vulndb_mod

    captured: dict = {}

    async def fake_post(url: str, data: dict, timeout: int):
        captured["url"] = url
        captured["data"] = data
        captured["timeout"] = timeout
        return {
            "status": 200,
            "request": {"apikey": "valid"},
            "result": [
                {
                    "entry": {
                        "id": "67685",
                        "title": "OpenSSL 1.1.1 example vulnerability",
                    },
                    "vulnerability": {
                        "risk": {"name": "high"},
                        "cwe": "CWE-295",
                        "cvss2": {"nvd": {"basescore": "7.5"}},
                    },
                    "advisory": {"date": "1704067200"},
                    "source": {"cve": {"id": "CVE-2099-0001"}},
                }
            ],
        }

    monkeypatch.setattr(vulndb_mod, "_post_vulndb_form", fake_post)
    cfg = type(
        "Cfg",
        (),
        {
            "vulndb_api_base_url": "https://vuldb.test/api",
            "vulndb_api_version": 3,
            "vulndb_limit": 5,
            "vulndb_max_components": 10,
            "vulndb_request_timeout_seconds": 12,
            "vulndb_request_delay_seconds": 0,
            "vulndb_details": False,
        },
    )()
    components = [{"name": "openssl", "version": "1.1.1", "cpe": "cpe:2.3:a:openssl:openssl:1.1.1:*:*:*:*:*:*:*"}]

    async def _run():
        return await VulnDbSource(api_key="vuldb-key").query(components, cfg)

    result = asyncio.run(_run())
    assert captured["url"] == "https://vuldb.test/api"
    assert captured["data"]["apikey"] == "vuldb-key"
    assert captured["data"]["version"] == "3"
    assert captured["data"]["search"].startswith("cpe:2.3:a:openssl")
    assert captured["timeout"] == 12

    assert result["errors"] == []
    assert result["warnings"] == []
    assert result["findings"] == [
        {
            "vuln_id": "CVE-2099-0001",
            "aliases": ["CVE-2099-0001", "VULDB-67685"],
            "sources": ["VULNDB"],
            "description": "OpenSSL 1.1.1 example vulnerability",
            "severity": "HIGH",
            "score": 7.5,
            "vector": None,
            "attack_vector": None,
            "cvss_version": "2.0",
            "published": "2024-01-01T00:00:00+00:00",
            "references": ["https://vuldb.com/?id.67685", "https://nvd.nist.gov/vuln/detail/CVE-2099-0001"],
            "url": "https://vuldb.com/?id.67685",
            "cwe": ["CWE-295"],
            "fixed_versions": [],
            "component_name": "openssl",
            "component_version": "1.1.1",
            "cpe": "cpe:2.3:a:openssl:openssl:1.1.1:*:*:*:*:*:*:*",
        }
    ]


def test_osv_fallback_query_endpoint_used_when_batch_empty(monkeypatch):
    """
    If OSV `/v1/querybatch` returns zero vuln ids (common "missing OSV" symptom),
    the implementation should fall back to `/v1/query` per-PURL and still emit
    canonical findings.
    """
    import app.analysis as analysis_mod

    async def fake_post(url: str, json_body: dict, headers=None, timeout: int = 60):
        if url.endswith("/v1/querybatch"):
            return {"results": [{"vulns": []}]}
        if url.endswith("/v1/query"):
            # Minimal OSV "vuln" object; scoring is optional.
            return {
                "vulns": [
                    {
                        "id": "OSV-FAKE-1",
                        "summary": "Example vuln",
                        "published": "2025-01-01T00:00:00Z",
                        "references": [{"url": "https://example.invalid/osv"}],
                        "database_specific": {"severity": "HIGH", "cwe_ids": ["CWE-79"]},
                        "affected": [
                            {
                                "ranges": [
                                    {"events": [{"introduced": "0"}, {"fixed": "1.2.3"}]},
                                ]
                            }
                        ],
                    }
                ]
            }
        raise AssertionError(f"Unexpected OSV POST url: {url}")

    monkeypatch.setattr(analysis_mod, "_async_post", fake_post)

    cfg = analysis_mod.get_analysis_settings_multi()
    components = [{"name": "lodash", "version": "4.17.15", "purl": "pkg:npm/lodash@4.17.15"}]

    async def _run():
        return await analysis_mod.osv_query_by_components(components, cfg)

    findings, errors, warnings = asyncio.run(_run())
    assert errors == []
    assert warnings == []
    assert len(findings) == 1
    assert findings[0]["vuln_id"] == "OSV-FAKE-1"
    assert findings[0]["component_name"] == "lodash"
    assert findings[0]["component_version"] == "4.17.15"
    assert findings[0]["severity"] in {"HIGH", "CRITICAL", "MEDIUM", "LOW", "UNKNOWN"}

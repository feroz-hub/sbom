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
    GhsaSource,
    NvdSource,
    OsvSource,
    SOURCE_REGISTRY,
    SourceResult,
    VulnSource,
    empty_result,
    get_source,
)


def test_registry_contains_all_three_sources():
    assert set(SOURCE_REGISTRY) == {"NVD", "OSV", "GITHUB"}


def test_get_source_is_case_insensitive():
    assert get_source("nvd") is NvdSource
    assert get_source("Osv") is OsvSource
    assert get_source("GITHUB") is GhsaSource


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


def test_adapters_short_circuit_on_empty_components():
    """
    All three adapters MUST short-circuit when components is empty so the
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

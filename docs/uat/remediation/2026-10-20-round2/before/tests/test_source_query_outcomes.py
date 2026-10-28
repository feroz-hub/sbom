from __future__ import annotations

import pytest
from app.analysis import _augment_components_with_cpe, enrich_component_for_osv, get_analysis_settings_multi
from app.services.analysis_service import normalize_details
from app.services.nvd_enrichment_service import collect_nvd_identifiers
from app.sources.base import SourceResult
from app.sources.ghsa import GhsaSource
from app.sources.nvd import NvdSource
from app.sources.routing import count_authoritative_cpes, queryable_components
from app.sources.runner import run_sources_concurrently


def test_npm_purl_without_cpe_is_heuristic_candidate_not_authoritative_cpe():
    components, generated = _augment_components_with_cpe(
        [{"type": "library", "name": "left-pad", "version": "1.3.0", "purl": "pkg:npm/left-pad@1.3.0"}]
    )

    assert generated == 1
    assert components[0].get("cpe") is None
    assert components[0]["heuristic_cpe"].startswith("cpe:2.3:a:left-pad:left-pad:1.3.0:")
    assert count_authoritative_cpes(components) == 0

    identifiers = collect_nvd_identifiers(components, [])
    assert identifiers.trusted_cpes == []
    assert identifiers.skipped_generated_cpe == 1


def test_scoped_npm_package_gets_purl_for_osv_and_ghsa_routing():
    component = enrich_component_for_osv({"type": "library", "name": "@scope/widget", "version": "2.0.0"})

    assert component["ecosystem"] == "npm"
    assert component["purl"] == "pkg:npm/%40scope/widget@2.0.0"


def test_platform_specific_optional_dependency_is_queryable_when_named_and_versioned():
    components, skipped = queryable_components(
        [
            {
                "type": "library",
                "name": "fsevents",
                "version": "2.3.3",
                "scope": "optional",
                "purl": "pkg:npm/fsevents@2.3.3?os=darwin&cpu=x64",
            }
        ]
    )

    assert len(components) == 1
    assert skipped == []


def test_package_json_placeholder_without_version_is_skipped_not_error():
    components, skipped = queryable_components([{"type": "file", "name": "package.json"}])

    assert components == []
    assert skipped[0]["outcome"] == "SKIPPED"
    assert skipped[0]["reason"] == "not_queryable_component"


@pytest.mark.asyncio
async def test_osv_empty_result_is_no_match_not_source_error():
    class EmptyOsv:
        name = "OSV"

        async def query(self, components, settings):
            assert len(components) == 1
            return SourceResult(findings=[], errors=[], warnings=[])

    findings, errors, warnings = await run_sources_concurrently(
        [EmptyOsv()],
        [{"type": "library", "name": "left-pad", "version": "1.3.0", "purl": "pkg:npm/left-pad@1.3.0"}],
        get_analysis_settings_multi(),
    )

    assert findings == []
    assert errors == []
    summary = next(w["source_summary"] for w in warnings if "source_summary" in w)
    assert summary["queried"] == 1
    assert summary["no_match"] == 1
    assert summary["errors"] == 0


@pytest.mark.asyncio
async def test_provider_timeout_and_429_are_errors_with_duplicate_suppression():
    class ErrorSource:
        name = "NVD"

        async def query(self, components, settings):
            return SourceResult(
                findings=[],
                errors=[
                    {
                        "source": "NVD",
                        "component_id": "left-pad@1.3.0",
                        "error": "Timeout while querying provider",
                    },
                    {
                        "source": "NVD",
                        "component_id": "left-pad@1.3.0",
                        "error": "Timeout while querying provider",
                    },
                    {
                        "source": "NVD",
                        "component_id": "react@18.2.0",
                        "status": 429,
                        "error": "HTTP 429 rate limit",
                    },
                ],
                warnings=[],
            )

    _, errors, warnings = await run_sources_concurrently(
        [ErrorSource()],
        [
            {"type": "library", "name": "left-pad", "version": "1.3.0"},
            {"type": "library", "name": "react", "version": "18.2.0"},
        ],
        get_analysis_settings_multi(),
    )

    assert [error["error_type"] for error in errors] == ["timeout", "rate_limited"]
    summary = next(w["source_summary"] for w in warnings if "source_summary" in w)
    assert summary["errors"] == 2


@pytest.mark.asyncio
async def test_ghsa_missing_token_is_skipped_not_source_error(monkeypatch):
    monkeypatch.delenv("GITHUB_TOKEN", raising=False)

    result = await GhsaSource(token=None).query(
        [{"type": "library", "name": "lodash", "version": "4.17.21", "purl": "pkg:npm/lodash@4.17.21"}],
        get_analysis_settings_multi(),
    )

    assert result["errors"] == []
    assert result["warnings"][0]["provider_status"]["status"] == "skipped"
    assert result["warnings"][0]["provider_status"]["reason"] == "missing_credentials"


@pytest.mark.asyncio
async def test_nvd_does_not_cve_enrich_purl_only_components(monkeypatch):
    captured = {}

    class DummySession:
        def close(self):
            pass

    class FakeNvdEnrichmentService:
        def __init__(self, db, settings):
            pass

        def enrich(self, components, vulnerabilities):
            captured["vulnerabilities"] = vulnerabilities
            return {
                "records": [],
                "provider_status": {
                    "provider": "NVD",
                    "status": "skipped",
                    "total_identifiers": 0,
                    "queried": 0,
                    "skipped_generated_cpe": 1,
                    "skipped_untrusted_cpe": 0,
                    "skipped_missing_cpe": 0,
                    "failures": 0,
                    "error_message": None,
                },
            }

    import app.db as db_module
    import app.services.nvd_enrichment_service as nvd_enrichment_module

    monkeypatch.setattr(db_module, "SessionLocal", lambda: DummySession())
    monkeypatch.setattr(nvd_enrichment_module, "NvdEnrichmentService", FakeNvdEnrichmentService)

    result = await NvdSource().query_with_vulnerabilities(
        [{"type": "library", "name": "left-pad", "version": "1.3.0", "heuristic_cpe": "cpe:2.3:a:left-pad:left-pad:1.3.0:*:*:*:*:*:*:*"}],
        [{"vuln_id": "CVE-2099-0001", "aliases": ["CVE-2099-0001"]}],
        get_analysis_settings_multi(),
    )

    assert captured["vulnerabilities"] == []
    assert result["errors"] == []
    assert result["warnings"][0]["provider_status"]["total_identifiers"] == 0


def test_normalize_details_counts_only_authoritative_cpes_and_dedupes_errors():
    details = normalize_details(
        {
            "query_errors": [
                {"source": "NVD", "component_id": "a", "error": "HTTP 429 rate limit"},
                {"source": "NVD", "component_id": "a", "error": "HTTP 429 rate limit"},
                {"source": "NVD", "reason": "missing_authoritative_cpe", "outcome": "SKIPPED"},
            ],
            "findings": [],
        },
        [
            {"name": "direct", "version": "1", "cpe": "cpe:2.3:a:vendor:direct:1:*:*:*:*:*:*:*", "cpe_source": "sbom_provided"},
            {"name": "heuristic", "version": "1", "heuristic_cpe": "cpe:2.3:a:x:y:1:*:*:*:*:*:*:*"},
        ],
    )

    assert details["components_with_cpe"] == 1
    assert len(details["query_errors"]) == 1
    assert details["query_errors"][0]["error_type"] == "rate_limited"

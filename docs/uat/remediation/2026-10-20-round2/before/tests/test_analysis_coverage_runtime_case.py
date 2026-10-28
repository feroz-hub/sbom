"""End-to-end coverage verdict for the reported 69-component SBOM.

Sources selected NVD, OSV and GITHUB. The SBOM has no PURLs and no
authoritative CPEs, so OSV and NVD skip every component while GITHUB
completes with no matches. Zero findings, zero errors — which used to
persist as ``OK`` and render "Clean / All clear".

This drives ``AnalysisOrchestrator.execute_providers`` (the single place
run status and the ``(partial)`` source label are decided) with the real
adapters and the real runner, mocking only the outbound provider calls.
"""

from __future__ import annotations

import asyncio
from typing import Any

import pytest
from app.services.analysis_orchestrator import AnalysisOrchestrator
from app.services.analysis_service import RUN_STATUS_OK, RUN_STATUS_PARTIAL

_COMPONENT_COUNT = 69


def _library_components() -> list[dict[str, Any]]:
    """PURL-less, CPE-less components with the SBOM classification in
    ``ecosystem`` — the shape that leaves OSV and NVD nothing to query."""
    return [
        {
            "type": "library",
            "name": f"vendor-component-{index}",
            "version": "Unknown",
            "ecosystem": "library",
            "purl": None,
            "cpe": None,
        }
        for index in range(_COMPONENT_COUNT)
    ]


def _npm_components() -> list[dict[str, Any]]:
    """Components every source can assess (real PURLs)."""
    return [
        {
            "type": "library",
            "name": f"pkg-{index}",
            "version": "1.0.0",
            "purl": f"pkg:npm/pkg-{index}@1.0.0",
            "cpe": f"cpe:2.3:a:pkg-{index}:pkg-{index}:1.0.0:*:*:*:*:*:*:*",
            "cpe_source": "sbom_provided",
        }
        for index in range(3)
    ]


class _DummySession:
    def close(self) -> None:
        pass


@pytest.fixture()
def offline_providers(monkeypatch: pytest.MonkeyPatch) -> dict[str, Any]:
    """No network. NVD reports whatever ``nvd_status`` the test sets."""
    import app.analysis as analysis_mod
    import app.db as db_module
    import app.services.nvd_enrichment_service as nvd_module

    state: dict[str, Any] = {
        "nvd_status": {
            "provider": "NVD",
            "status": "skipped",
            "total_identifiers": 0,
            "queried": 0,
            "skipped_generated_cpe": 0,
            "skipped_untrusted_cpe": 0,
            "skipped_missing_cpe": 0,
            "failures": 0,
            "reason": "missing_authoritative_cpe",
            "error_message": None,
        }
    }

    async def _no_findings(*_args, **_kwargs):
        return [], [], []

    async def _empty_osv_post(url, json_body=None, headers=None, timeout=None):
        if url.endswith("/v1/querybatch"):
            queries = (json_body or {}).get("queries") or []
            return {"results": [{"vulns": []} for _ in queries]}
        if url.endswith("/v1/query"):
            return {"vulns": []}
        raise AssertionError(f"unexpected OSV POST: {url}")

    async def _empty_osv_get(url, params=None, headers=None, timeout=None):
        raise AssertionError(f"unexpected OSV GET: {url}")

    class _FakeNvdEnrichmentService:
        def __init__(self, db, settings):
            pass

        def enrich(self, components, vulnerabilities):
            return {"records": [], "provider_status": dict(state["nvd_status"])}

    # GITHUB completes with no matches; OSV runs its real eligibility gate.
    monkeypatch.setattr(analysis_mod, "github_query_by_components", _no_findings)
    monkeypatch.setattr(analysis_mod, "_async_post", _empty_osv_post)
    monkeypatch.setattr(analysis_mod, "_async_get", _empty_osv_get)
    monkeypatch.setattr(db_module, "SessionLocal", lambda: _DummySession())
    monkeypatch.setattr(nvd_module, "NvdEnrichmentService", _FakeNvdEnrichmentService)
    monkeypatch.setenv("NVD_ENABLED", "true")
    return state


def _execute(components: list[dict[str, Any]], sources: list[str] | None = None):
    orchestrator = AnalysisOrchestrator(_DummySession())
    return asyncio.run(
        orchestrator.execute_providers(components=components, sources=sources or ["NVD", "OSV", "GITHUB"])
    )


def _summary_by_source(execution) -> dict[str, dict]:
    return {item["source"]: item for item in execution.details["source_summary"]}


def test_reported_runtime_case_is_partial_with_named_coverage_gaps(offline_providers):
    execution = _execute(_library_components())

    assert execution.findings == []
    assert execution.errors == []
    assert execution.run_status == RUN_STATUS_PARTIAL, (
        "zero findings with OSV and NVD assessing nothing must not report as OK/clean"
    )
    assert execution.source_label.endswith(" (partial)")

    summaries = _summary_by_source(execution)

    assert summaries["GITHUB"]["status"] == "complete"
    assert summaries["GITHUB"]["queried"] == _COMPONENT_COUNT
    assert summaries["GITHUB"]["skipped"] == 0

    assert summaries["OSV"]["status"] == "skipped"
    assert summaries["OSV"]["queried"] == 0
    assert summaries["OSV"]["skipped"] == _COMPONENT_COUNT
    assert summaries["OSV"]["reason"] == "missing_supported_package_identity"

    assert summaries["NVD"]["status"] == "skipped"
    assert summaries["NVD"]["queried"] == 0
    assert summaries["NVD"]["reason"] == "missing_authoritative_cpe"


def test_full_coverage_with_no_findings_is_still_ok(offline_providers):
    """Every selected source assessed every component and found nothing —
    the only state that may render as clean."""
    execution = _execute(_npm_components(), sources=["OSV", "GITHUB"])

    assert execution.findings == []
    assert execution.errors == []
    assert execution.run_status == RUN_STATUS_OK
    assert "(partial)" not in execution.source_label

    summaries = _summary_by_source(execution)
    assert {name: item["status"] for name, item in summaries.items()} == {
        "GITHUB": "complete",
        "OSV": "complete",
    }
    assert summaries["OSV"]["queried"] == len(_npm_components())
    assert summaries["OSV"]["skipped"] == 0

"""OSV query-eligibility gate (app/sources/osv_eligibility.py).

Regression cover for the HTTP 400 that took OSV out on PURL-less SBOMs:
components carrying the CycloneDX classification ``library`` in
``ecosystem`` were sent to ``/v1/querybatch`` as
``{"package": {"name": ..., "ecosystem": "library"}}``. OSV validates the
whole request body, so one such query failed the entire batch and the run
recorded OSV as ERROR.

The tests below pin the four behaviours that fix has to hold:
  * a real package identity (valid PURL, or name + recognised ecosystem)
    still reaches the network unchanged;
  * an unusable identity is skipped, never guessed at;
  * a mixed batch sends the valid queries only — one bad component cannot
    poison the others;
  * an all-unusable batch makes NO request and reports ``skipped``,
    not ``error``.
"""

from __future__ import annotations

import asyncio
from dataclasses import replace as dataclass_replace
from typing import Any

import pytest
from app.analysis import get_analysis_settings_multi, osv_query_by_components
from app.sources.osv import OsvSource
from app.sources.osv_eligibility import (
    SKIP_REASON_NO_IDENTITY,
    SKIP_REASON_PLACEHOLDER_VERSION,
    SKIP_REASON_UNSUPPORTED_ECOSYSTEM,
    canonical_osv_ecosystem,
    is_osv_query_eligible,
    is_placeholder_version,
    osv_query_for_component,
    partition_osv_eligible,
)
from app.sources.runner import run_sources_concurrently

# ---------------------------------------------------------------------------
# Fixtures / helpers
# ---------------------------------------------------------------------------

_LODASH_VULN = {
    "id": "OSV-FAKE-LODASH",
    "summary": "lodash advisory",
    "published": "2024-01-15T12:00:00Z",
    "references": [{"url": "https://example.invalid/osv-lodash"}],
    "database_specific": {"severity": "HIGH"},
    "affected": [{"package": {"name": "lodash", "ecosystem": "npm"}}],
}


def _settings() -> Any:
    # Cache off: this suite is about request construction, and the cache
    # path is covered by tests/test_source_cache_osv_integration.py.
    return dataclass_replace(get_analysis_settings_multi(), source_cache_enabled=False)


class _OsvSpy:
    """Records every OSV request; fails loudly on unexpected endpoints."""

    def __init__(self, vulns_by_purl: dict[str, list[str]] | None = None) -> None:
        self.querybatch_bodies: list[dict] = []
        self.query_bodies: list[dict] = []
        self.vuln_ids: list[str] = []
        self.vulns_by_purl = vulns_by_purl or {}
        self.vuln_payloads: dict[str, dict] = {"OSV-FAKE-LODASH": _LODASH_VULN}

    @property
    def request_count(self) -> int:
        return len(self.querybatch_bodies) + len(self.query_bodies) + len(self.vuln_ids)

    def queries(self) -> list[dict]:
        return [q for body in self.querybatch_bodies for q in (body.get("queries") or [])]

    async def post(self, url, json_body=None, headers=None, timeout=None):
        if url.endswith("/v1/querybatch"):
            self.querybatch_bodies.append(json_body or {})
            results = []
            for query in (json_body or {}).get("queries") or []:
                purl = ((query or {}).get("package") or {}).get("purl") or ""
                ids = self.vulns_by_purl.get(purl, [])
                results.append({"vulns": [{"id": vid} for vid in ids]})
            return {"results": results}
        if url.endswith("/v1/query"):
            self.query_bodies.append(json_body or {})
            return {"vulns": []}
        raise AssertionError(f"unexpected OSV POST: {url}")

    async def get(self, url, params=None, headers=None, timeout=None):
        marker = "/v1/vulns/"
        idx = url.find(marker)
        if idx == -1:
            raise AssertionError(f"unexpected OSV GET: {url}")
        vid = url[idx + len(marker) :]
        self.vuln_ids.append(vid)
        return dict(self.vuln_payloads.get(vid, {"id": vid}))


@pytest.fixture()
def osv_spy(monkeypatch: pytest.MonkeyPatch) -> _OsvSpy:
    import app.analysis as analysis_mod

    spy = _OsvSpy(vulns_by_purl={"pkg:npm/lodash@4.17.15": ["OSV-FAKE-LODASH"]})
    monkeypatch.setattr(analysis_mod, "_async_post", spy.post)
    monkeypatch.setattr(analysis_mod, "_async_get", spy.get)
    return spy


@pytest.fixture()
def no_network(monkeypatch: pytest.MonkeyPatch) -> None:
    """Any OSV HTTP call at all is a test failure."""
    import app.analysis as analysis_mod

    async def _forbidden(*args, **kwargs):
        raise AssertionError(f"OSV must not be called: args={args!r} kwargs={kwargs!r}")

    monkeypatch.setattr(analysis_mod, "_async_post", _forbidden)
    monkeypatch.setattr(analysis_mod, "_async_get", _forbidden)


def _sbom1_like_components() -> list[dict]:
    """Shape of the SBOM that reproduced the bug: no PURLs, the component
    classification sitting in ``ecosystem``, placeholder versions."""
    return [
        {"type": "library", "name": "OpenSSL", "version": "Unknown", "ecosystem": "library"},
        {"type": "library", "name": "zlib", "version": "Integrated", "ecosystem": "library"},
        {"type": "library", "name": "SQLite", "version": "Bundled with Windows 11", "ecosystem": "library"},
    ]


# ---------------------------------------------------------------------------
# Unit level — the eligibility function itself
# ---------------------------------------------------------------------------


def test_valid_purl_is_eligible_and_queried_by_purl():
    decision = osv_query_for_component(
        {"type": "library", "name": "lodash", "version": "4.17.15", "purl": "pkg:npm/lodash@4.17.15"}
    )

    assert decision.eligible is True
    # PURL carries the version, so no separate version field is sent.
    assert decision.query == {"package": {"purl": "pkg:npm/lodash@4.17.15"}}


def test_versionless_purl_sends_component_version_alongside():
    decision = osv_query_for_component({"name": "lodash", "version": "4.17.15", "purl": "pkg:npm/lodash"})

    assert decision.query == {"package": {"purl": "pkg:npm/lodash"}, "version": "4.17.15"}


def test_recognized_ecosystem_name_and_version_is_eligible():
    decision = osv_query_for_component({"type": "library", "name": "requests", "version": "2.20.0", "ecosystem": "pypi"})

    assert decision.eligible is True
    # Canonical OSV spelling, not the lowercase form the SBOM recorded.
    assert decision.query == {"package": {"name": "requests", "ecosystem": "PyPI"}, "version": "2.20.0"}


def test_distro_ecosystem_release_suffix_is_preserved():
    assert canonical_osv_ecosystem("debian:11") == "Debian:11"
    assert canonical_osv_ecosystem("Alpine:v3.16") == "Alpine:v3.16"


@pytest.mark.parametrize(
    "ecosystem",
    [
        "library",
        "application",
        "framework",
        "firmware",
        "file",
        "device",
        "operating-system",
        "container",
        "unknown",
        "",
        "   ",
    ],
)
def test_component_classifications_are_not_ecosystems(ecosystem):
    component = {"type": "library", "name": "OpenSSL", "version": "3.0.8", "ecosystem": ecosystem}

    assert canonical_osv_ecosystem(ecosystem) is None
    decision = osv_query_for_component(component)
    assert decision.eligible is False
    assert decision.query is None


def test_null_ecosystem_is_skipped_with_no_identity_reason():
    decision = osv_query_for_component({"name": "OpenSSL", "version": "3.0.8", "ecosystem": None})

    assert decision.eligible is False
    assert decision.reason == SKIP_REASON_NO_IDENTITY


def test_unsupported_ecosystem_value_is_reported_as_such():
    decision = osv_query_for_component({"name": "OpenSSL", "version": "3.0.8", "ecosystem": "library"})

    assert decision.reason == SKIP_REASON_UNSUPPORTED_ECOSYSTEM


@pytest.mark.parametrize("version", ["Unknown", "Integrated", "Bundled with Windows 11", "N/A", "", None])
def test_placeholder_versions_are_not_versions(version):
    assert is_placeholder_version(version) is True

    decision = osv_query_for_component({"name": "requests", "version": version, "ecosystem": "PyPI"})
    assert decision.eligible is False
    assert decision.reason == SKIP_REASON_PLACEHOLDER_VERSION


def test_placeholder_version_does_not_disqualify_a_valid_purl():
    # The PURL is a real identity on its own; requirement is that valid
    # PURLs keep reaching OSV.
    decision = osv_query_for_component(
        {"name": "lodash", "version": "Unknown", "purl": "pkg:npm/lodash@4.17.15"}
    )

    assert decision.eligible is True
    assert decision.query == {"package": {"purl": "pkg:npm/lodash@4.17.15"}}
    assert "version" not in decision.query


def test_malformed_purl_is_never_sent():
    decision = osv_query_for_component({"name": "OpenSSL", "version": "3.0.8", "purl": "library"})

    assert decision.eligible is False
    assert decision.query is None


def test_no_ecosystem_is_invented_from_group_or_scope():
    # Maven-looking group / npm-looking scope are NOT ecosystems. The
    # deterministic PURL reconstruction lives in enrich_component_for_osv;
    # the query builder never guesses.
    assert is_osv_query_eligible({"name": "commons-io", "version": "2.11.0", "group": "org.apache.commons"}) is False
    assert is_osv_query_eligible({"name": "@scope/widget", "version": "2.0.0"}) is False


def test_missing_name_without_purl_is_skipped():
    assert is_osv_query_eligible({"version": "1.0.0", "ecosystem": "npm"}) is False


def test_partition_counts_every_ineligible_component():
    eligible, skipped = partition_osv_eligible(
        [*_sbom1_like_components(), {"name": "lodash", "version": "4.17.15", "purl": "pkg:npm/lodash@4.17.15"}]
    )

    assert [c["name"] for c in eligible] == ["lodash"]
    assert len(skipped) == 3
    assert {s["outcome"] for s in skipped} == {"SKIPPED"}
    assert {s["reason"] for s in skipped} == {SKIP_REASON_UNSUPPORTED_ECOSYSTEM}


# ---------------------------------------------------------------------------
# osv_query_by_components — request construction
# ---------------------------------------------------------------------------


def test_valid_purl_still_reaches_querybatch_and_returns_findings(osv_spy: _OsvSpy):
    components = [{"type": "library", "name": "lodash", "version": "4.17.15", "purl": "pkg:npm/lodash@4.17.15"}]

    findings, errors, warnings = asyncio.run(osv_query_by_components(components, _settings()))

    assert osv_spy.queries() == [{"package": {"purl": "pkg:npm/lodash@4.17.15"}}]
    assert errors == []
    assert warnings == []
    assert [f["vuln_id"] for f in findings] == ["OSV-FAKE-LODASH"]


def test_recognized_ecosystem_component_is_queried_by_name(osv_spy: _OsvSpy):
    components = [{"type": "library", "name": "requests", "version": "2.20.0", "ecosystem": "PyPI"}]

    _findings, errors, _warnings = asyncio.run(osv_query_by_components(components, _settings()))

    assert osv_spy.queries() == [{"package": {"name": "requests", "ecosystem": "PyPI"}, "version": "2.20.0"}]
    assert errors == []


def test_library_ecosystem_component_is_never_sent(no_network: None):
    components = [{"type": "library", "name": "OpenSSL", "version": "3.0.8", "ecosystem": "library"}]

    findings, errors, warnings = asyncio.run(osv_query_by_components(components, _settings()))

    assert findings == []
    assert errors == []
    provider_status = warnings[0]["provider_status"]
    assert provider_status["status"] == "skipped"
    assert provider_status["queried"] == 0
    assert provider_status["skipped"] == 1


def test_no_purl_and_no_supported_ecosystem_makes_no_request(no_network: None):
    """``no_network`` asserts it: neither querybatch, nor the /v1/query
    fallback, nor vuln hydration may fire."""
    findings, errors, warnings = asyncio.run(osv_query_by_components(_sbom1_like_components(), _settings()))

    assert (findings, errors) == ([], [])
    assert len(warnings) == 1


def test_mixed_batch_sends_only_the_eligible_queries(osv_spy: _OsvSpy):
    components = [
        *_sbom1_like_components(),
        {"type": "library", "name": "lodash", "version": "4.17.15", "purl": "pkg:npm/lodash@4.17.15"},
        {"type": "library", "name": "requests", "version": "2.20.0", "ecosystem": "pypi"},
    ]

    findings, errors, warnings = asyncio.run(osv_query_by_components(components, _settings()))

    assert osv_spy.queries() == [
        {"package": {"purl": "pkg:npm/lodash@4.17.15"}},
        {"package": {"name": "requests", "ecosystem": "PyPI"}, "version": "2.20.0"},
    ]
    assert errors == []
    assert [f["vuln_id"] for f in findings] == ["OSV-FAKE-LODASH"]

    provider_status = next(w["provider_status"] for w in warnings if "provider_status" in w)
    assert provider_status["queried"] == 2
    assert provider_status["skipped"] == 3
    # A partially-usable batch is not a skipped source.
    assert "status" not in provider_status


def test_all_invalid_components_report_skipped_not_error(no_network: None):
    components = _sbom1_like_components()

    findings, errors, warnings = asyncio.run(osv_query_by_components(components, _settings()))

    assert findings == []
    assert errors == [], "an unqueryable SBOM is not an OSV failure"
    provider_status = warnings[0]["provider_status"]
    assert provider_status == {
        "provider": "OSV",
        "queried": 0,
        "skipped": 3,
        "failures": 0,
        "status": "skipped",
        "reason": SKIP_REASON_NO_IDENTITY,
        "matched": 0,
        "errors": 0,
    }
    assert len(warnings[0]["skipped_components"]) == 3


# ---------------------------------------------------------------------------
# Source summary as the run actually records it (through the runner)
# ---------------------------------------------------------------------------


def test_source_summary_reports_skipped_status_for_unqueryable_sbom(no_network: None):
    findings, errors, warnings = asyncio.run(
        run_sources_concurrently([OsvSource()], _sbom1_like_components(), _settings())
    )

    assert findings == []
    assert errors == []
    summary = next(w["source_summary"] for w in warnings if "source_summary" in w)
    assert summary == {
        "source": "OSV",
        "queried": 0,
        "matched": 0,
        "no_match": 0,
        "skipped": 3,
        "errors": 0,
        "status": "skipped",
        "reason": SKIP_REASON_NO_IDENTITY,
    }


def test_source_summary_counts_partial_eligibility(osv_spy: _OsvSpy):
    components = [
        *_sbom1_like_components(),
        {"type": "library", "name": "lodash", "version": "4.17.15", "purl": "pkg:npm/lodash@4.17.15"},
    ]

    _findings, errors, warnings = asyncio.run(run_sources_concurrently([OsvSource()], components, _settings()))

    assert errors == []
    summary = next(w["source_summary"] for w in warnings if "source_summary" in w)
    assert summary["queried"] == 1
    assert summary["matched"] == 1
    assert summary["skipped"] == 3
    assert summary["errors"] == 0
    assert summary["status"] == "complete"

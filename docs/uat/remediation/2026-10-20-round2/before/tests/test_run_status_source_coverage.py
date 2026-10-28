"""Run status must distinguish "clean" from "nobody looked".

A run with zero findings is only ``OK`` when every selected source actually
assessed the components. When a source errored, or skipped the components it
was handed (OSV without a supported package identity, NVD without an
authoritative CPE), the run is ``PARTIAL`` — incomplete coverage — because
zero findings says nothing about whether the SBOM is vulnerability-free.

Reproduces the confirmed runtime case: 69 components, GITHUB complete,
OSV and NVD skipped, no findings, no errors → previously ``OK`` ("Clean /
All clear"), now ``PARTIAL``.
"""

from __future__ import annotations

import pytest
from app.services.analysis_service import (
    RUN_STATUS_FINDINGS,
    RUN_STATUS_OK,
    RUN_STATUS_PARTIAL,
    compute_report_status,
    source_summary_from_details,
)
from app.sources.routing import (
    coverage_gap_sources,
    has_incomplete_source_coverage,
    source_has_coverage_gap,
    summarize_source,
)


def _complete(source: str, *, queried: int = 69, matched: int = 0) -> dict:
    return summarize_source(source, queried=queried, matched=matched, skipped=0, errors=0)


def _skipped_all(source: str, *, skipped: int = 69, reason: str | None = None) -> dict:
    return summarize_source(
        source,
        queried=0,
        matched=0,
        skipped=skipped,
        errors=0,
        status="skipped",
        reason=reason,
    )


def _confirmed_runtime_case() -> list[dict]:
    """The exact summary trio from the reported run."""
    return [
        _complete("GITHUB"),
        _skipped_all("OSV", reason="missing_supported_package_identity"),
        _skipped_all("NVD", reason="missing_authoritative_cpe"),
    ]


# ---------------------------------------------------------------------------
# A — fully covered, nothing found
# ---------------------------------------------------------------------------


def test_zero_findings_with_all_sources_complete_is_ok():
    summary = [_complete("NVD"), _complete("OSV"), _complete("GITHUB")]

    assert has_incomplete_source_coverage(summary) is False
    assert compute_report_status(0, [], summary) == RUN_STATUS_OK


def test_zero_findings_without_any_summary_still_ok():
    """Legacy payloads carry no source_summary — behaviour must not change."""
    assert compute_report_status(0, []) == RUN_STATUS_OK
    assert compute_report_status(0, [], None) == RUN_STATUS_OK
    assert compute_report_status(0, [], []) == RUN_STATUS_OK


def test_partial_skips_with_queried_components_are_not_a_gap():
    """Some components skipped but the source still assessed the rest."""
    summary = [summarize_source("OSV", queried=60, matched=0, skipped=9, errors=0)]

    assert has_incomplete_source_coverage(summary) is False
    assert compute_report_status(0, [], summary) == RUN_STATUS_OK


# ---------------------------------------------------------------------------
# B / C — a source assessed nothing
# ---------------------------------------------------------------------------


def test_zero_findings_with_osv_skipping_everything_is_partial():
    summary = [_complete("GITHUB"), _skipped_all("OSV", reason="missing_supported_package_identity")]

    assert coverage_gap_sources(summary) == ["OSV"]
    assert compute_report_status(0, [], summary) == RUN_STATUS_PARTIAL


def test_zero_findings_with_nvd_skipping_everything_is_partial():
    summary = [_complete("GITHUB"), _skipped_all("NVD", reason="missing_authoritative_cpe")]

    assert coverage_gap_sources(summary) == ["NVD"]
    assert compute_report_status(0, [], summary) == RUN_STATUS_PARTIAL


def test_confirmed_runtime_case_is_partial_not_ok():
    summary = _confirmed_runtime_case()

    assert coverage_gap_sources(summary) == ["OSV", "NVD"]
    assert compute_report_status(0, [], summary) == RUN_STATUS_PARTIAL


def test_disabled_source_is_a_coverage_gap():
    summary = [summarize_source("NVD", queried=0, matched=0, skipped=0, errors=0, status="disabled")]

    assert compute_report_status(0, [], summary) == RUN_STATUS_PARTIAL


def test_zero_queried_and_zero_skipped_without_status_is_not_a_gap():
    """An empty SBOM has nothing to assess — that is not a coverage gap."""
    summary = [summarize_source("OSV", queried=0, matched=0, skipped=0, errors=0)]

    assert source_has_coverage_gap(summary) is False
    assert compute_report_status(0, [], summary) == RUN_STATUS_OK


# ---------------------------------------------------------------------------
# D — source errors
# ---------------------------------------------------------------------------


def test_zero_findings_with_query_errors_is_partial():
    assert compute_report_status(0, [{"source": "NVD", "error": "HTTP 429"}]) == RUN_STATUS_PARTIAL


def test_source_summary_errors_alone_are_a_coverage_gap():
    summary = [summarize_source("NVD", queried=69, matched=0, skipped=0, errors=3)]

    assert compute_report_status(0, [], summary) == RUN_STATUS_PARTIAL


# ---------------------------------------------------------------------------
# E — findings win
# ---------------------------------------------------------------------------


def test_findings_with_normal_coverage_is_findings():
    summary = [_complete("NVD", matched=4), _complete("OSV"), _complete("GITHUB")]

    assert compute_report_status(4, [], summary) == RUN_STATUS_FINDINGS


def test_findings_outrank_coverage_gaps_and_errors():
    summary = _confirmed_runtime_case()

    assert compute_report_status(7, [], summary) == RUN_STATUS_FINDINGS
    assert compute_report_status(7, [{"source": "NVD", "error": "boom"}], summary) == RUN_STATUS_FINDINGS


# ---------------------------------------------------------------------------
# Gap classification is never an ERROR verdict
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    "reason",
    ["missing_supported_package_identity", "missing_authoritative_cpe", "missing_credentials"],
)
def test_intentional_skips_never_produce_error_status(reason):
    summary = [_skipped_all("OSV", reason=reason)]

    assert compute_report_status(0, [], summary) == RUN_STATUS_PARTIAL


# ---------------------------------------------------------------------------
# Details extraction — the status recompute in persist_analysis_run reads this
# ---------------------------------------------------------------------------


def test_source_summary_read_from_top_level_details():
    details = {"source_summary": _confirmed_runtime_case()}

    assert compute_report_status(0, [], source_summary_from_details(details)) == RUN_STATUS_PARTIAL


def test_source_summary_read_from_analysis_metadata_fallback():
    details = {"analysis_metadata": {"source_summary": _confirmed_runtime_case()}}

    assert source_summary_from_details(details)
    assert compute_report_status(0, [], source_summary_from_details(details)) == RUN_STATUS_PARTIAL


def test_source_summary_missing_or_malformed_degrades_quietly():
    assert source_summary_from_details(None) == []
    assert source_summary_from_details({}) == []
    assert source_summary_from_details({"source_summary": "nope"}) == []
    assert source_summary_from_details({"source_summary": [1, {"source": "OSV"}]}) == [{"source": "OSV"}]


def test_non_dict_summary_entries_are_ignored():
    assert source_has_coverage_gap(None) is False
    assert source_has_coverage_gap("skipped") is False
    assert has_incomplete_source_coverage("not-a-list") is False
    assert coverage_gap_sources(None) == []

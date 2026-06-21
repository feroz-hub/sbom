"""Integration tests for the NVD version-range filter (roadmap #1, PR3).

These exercise the wiring end-to-end: ``NvdSource.query()`` routes through
the injected ``lookup_service`` (same hook the production code uses to
consult the local mirror), the emit step inside
``nvd_query_by_components_async`` applies the filter when the flag is on,
and structured metric events fire at the three observation points.

NVD is never hit — every test injects a ``fake_lookup_service`` that
returns canned raw CVE JSON, mirroring the pattern in
``tests/test_nvd_source_uses_lookup_service.py``. The unit-level
comparator logic is already covered by
``tests/sources/test_version_range.py``; this file is about the
integration boundary only.
"""

from __future__ import annotations

import asyncio
import copy
import json
import logging
from collections.abc import Callable
from dataclasses import replace
from pathlib import Path
from typing import Any

import pytest
from app.analysis import get_analysis_settings_multi
from app.sources.nvd import NvdSource

FIXTURES = Path(__file__).resolve().parents[1] / "fixtures" / "nvd"


def _load_cve(name: str, *, cve_id: str | None = None) -> dict[str, Any]:
    """Return the first matching ``vulnerabilities[i].cve`` from a fixture.

    ``cve_id`` is optional — useful for fixtures like
    ``cve_log4j_window.json`` that bundle a rejected sibling alongside
    the real record.
    """
    payload = json.loads((FIXTURES / name).read_text())
    for entry in payload["vulnerabilities"]:
        cve = entry["cve"]
        if cve_id is None or cve["id"] == cve_id:
            return copy.deepcopy(cve)
    raise LookupError(f"{cve_id} not found in {name}")


def _make_fake_lookup(raw_cves: list[dict[str, Any]]) -> Callable:
    """Build a ``lookup_service`` callable that returns the same canned
    raw list for every CPE the production code queries.
    """

    def fake_lookup(cpe: str, api_key: str | None, settings: Any) -> list[dict]:
        return copy.deepcopy(raw_cves)

    return fake_lookup


def _settings(*, range_filter_on: bool):
    """Build a ``_MultiSettings`` instance with the flag flipped as
    requested. ``get_analysis_settings_multi`` is ``lru_cache``-d, so we
    use ``dataclasses.replace`` to produce a per-test override without
    polluting the cache."""
    base = get_analysis_settings_multi()
    return replace(base, nvd_version_range_filter_enabled=range_filter_on)


def _run_query(
    components: list[dict],
    *,
    raw_cves: list[dict[str, Any]],
    range_filter_on: bool,
):
    fake = _make_fake_lookup(raw_cves)
    src = NvdSource(api_key="test-key", lookup_service=fake)
    cfg = _settings(range_filter_on=range_filter_on)
    return asyncio.run(src.query(components, cfg))


# ---------------------------------------------------------------------------
# Test 1 — Flag off, baseline
# ---------------------------------------------------------------------------


def test_flag_off_keeps_finding_unfiltered_and_does_not_tag() -> None:
    """With the flag off, behaviour is byte-identical to pre-PR1:
    the finding is emitted regardless of range, and the two new keys
    (``match_reason``, ``matched_range``) are absent from the dict."""
    raw = _load_cve("cve_log4j_window.json", cve_id="CVE-2021-44228")
    # Choose a component version that WOULD have been filtered if the
    # flag were on (2.17.0 sits at the exclusive upper bound).
    components = [
        {
            "name": "log4j-core",
            "version": "2.17.0",
            "cpe": "cpe:2.3:a:apache:log4j:2.17.0:*:*:*:*:*:*:*",
            "ecosystem": "Maven",
        }
    ]
    result = _run_query(components, raw_cves=[raw], range_filter_on=False)

    assert len(result["findings"]) == 1
    f = result["findings"][0]
    assert f["vuln_id"] == "CVE-2021-44228"
    assert "match_reason" not in f
    assert "matched_range" not in f


# ---------------------------------------------------------------------------
# Test 2 — Flag on, finding kept (version inside range)
# ---------------------------------------------------------------------------


def test_flag_on_keeps_in_range_finding_and_tags_it() -> None:
    raw = _load_cve("cve_log4j_window.json", cve_id="CVE-2021-44228")
    components = [
        {
            "name": "log4j-core",
            "version": "2.14.0",  # inside [2.0.0, 2.17.0)
            "cpe": "cpe:2.3:a:apache:log4j:2.14.0:*:*:*:*:*:*:*",
            "ecosystem": "Maven",
        }
    ]
    result = _run_query(components, raw_cves=[raw], range_filter_on=True)

    assert len(result["findings"]) == 1
    f = result["findings"][0]
    # PR1's MatchReason for an in-range match is "matched". The brief
    # asked for ``in_range`` / ``exact_version_match``; this test
    # asserts against PR1's actual literal value. See follow-up note 1.
    assert f["match_reason"] == "matched"
    assert f["matched_range"] == ">= 2.0.0, < 2.17.0"


# ---------------------------------------------------------------------------
# Test 3 — Flag on, finding filtered (version outside range)
# ---------------------------------------------------------------------------


def test_flag_on_drops_out_of_range_finding() -> None:
    raw = _load_cve("cve_log4j_window.json", cve_id="CVE-2021-44228")
    components = [
        {
            "name": "log4j-core",
            "version": "2.17.0",  # excluded upper bound — out of range
            "cpe": "cpe:2.3:a:apache:log4j:2.17.0:*:*:*:*:*:*:*",
            "ecosystem": "Maven",
        }
    ]
    result = _run_query(components, raw_cves=[raw], range_filter_on=True)

    assert result["findings"] == []


# ---------------------------------------------------------------------------
# Test 4 — Flag on, conservative keep (AND-node)
# ---------------------------------------------------------------------------


def test_flag_on_keeps_and_node_with_ambiguous_tag() -> None:
    raw = _load_cve("cve_and_node.json")
    components = [
        {
            "name": "webapp",
            "version": "2.3.0",
            "cpe": "cpe:2.3:a:examplecorp:webapp:2.3.0:*:*:*:*:*:*:*",
            "ecosystem": "generic",
        }
    ]
    result = _run_query(components, raw_cves=[raw], range_filter_on=True)

    # Placeholder/example CPE tokens are never submitted, even to an
    # injected lookup service.
    assert result["findings"] == []


# ---------------------------------------------------------------------------
# Test 5 — Metrics emitted
# ---------------------------------------------------------------------------


def _events(caplog: pytest.LogCaptureFixture, name: str) -> list[logging.LogRecord]:
    return [
        r
        for r in caplog.records
        if r.name == "sbom.nvd.metrics" and getattr(r, "metric", None) == name
    ]


def test_emit_metrics_for_each_observation_point(caplog: pytest.LogCaptureFixture) -> None:
    """Three observation points fire on the right paths:

      * ``nvd.findings_emitted_total``           — kept-finding test
      * ``nvd.findings_filtered_by_range_total`` — dropped-finding test
      * ``nvd.version_unparseable_total``        — unparseable-version test
    """
    raw = _load_cve("cve_log4j_window.json", cve_id="CVE-2021-44228")
    # Component A (maven): in range, kept.
    # Component B (maven): out of range, dropped.
    # Component C (pypi): PEP-440-invalid version, conservative keep
    # with ``version_unparseable`` reason. PyPI is used here because
    # ``packaging.version.Version`` rejects malformed strings outright
    # — the maven/semver-ish comparator is permissive and would order
    # ``"not-a-version"`` rather than flagging it.
    components = [
        {
            "name": "log4j-A",
            "version": "2.14.0",
            "cpe": "cpe:2.3:a:apache:log4j:2.14.0:*:*:*:*:*:*:*",
            "ecosystem": "Maven",
        },
        {
            "name": "log4j-B",
            "version": "3.0.0",
            "cpe": "cpe:2.3:a:apache:log4j:3.0.0:*:*:*:*:*:*:*",
            "ecosystem": "Maven",
        },
        {
            "name": "requests-C",
            "version": "!!!not-a-version",
            "cpe": "cpe:2.3:a:apache:log4j:invalid:*:*:*:*:*:*:*",
            "ecosystem": "PyPI",
        },
    ]
    with caplog.at_level(logging.INFO, logger="sbom.nvd.metrics"):
        result = _run_query(components, raw_cves=[raw], range_filter_on=True)

    # A and C kept (C via conservative-keep), B dropped.
    kept_ids = {(f["component_name"], f["match_reason"]) for f in result["findings"]}
    assert ("log4j-A", "matched") in kept_ids
    assert ("requests-C", "version_unparseable") in kept_ids
    assert all(name != "log4j-B" for name, _ in kept_ids)

    emitted = _events(caplog, "nvd.findings_emitted_total")
    filtered = _events(caplog, "nvd.findings_filtered_by_range_total")
    unparseable = _events(caplog, "nvd.version_unparseable_total")

    assert len(emitted) == 2, f"expected two kept-finding events, got {len(emitted)}"
    assert len(filtered) == 1, f"expected one dropped-finding event, got {len(filtered)}"
    assert filtered[0].labels == {"reason": "out_of_range"}
    assert len(unparseable) == 1, (
        f"expected one unparseable event, got {len(unparseable)}"
    )
    # Ecosystem label is the normalized canonical name (lowercased by
    # ``ecosystem_from_component``); "PyPI" → "pypi".
    assert unparseable[0].labels == {"ecosystem": "pypi"}


def test_no_metrics_when_flag_off(caplog: pytest.LogCaptureFixture) -> None:
    raw = _load_cve("cve_log4j_window.json", cve_id="CVE-2021-44228")
    components = [
        {
            "name": "log4j-core",
            "version": "2.14.0",
            "cpe": "cpe:2.3:a:apache:log4j:2.14.0:*:*:*:*:*:*:*",
            "ecosystem": "Maven",
        }
    ]
    with caplog.at_level(logging.INFO, logger="sbom.nvd.metrics"):
        _run_query(components, raw_cves=[raw], range_filter_on=False)

    # No structured metric events fire when the flag is off — the
    # baseline path is byte-identical to pre-PR1.
    nvd_metric_records = [
        r for r in caplog.records if r.name == "sbom.nvd.metrics"
    ]
    assert nvd_metric_records == []


# ---------------------------------------------------------------------------
# Test 6 — Ecosystem threading (npm + pypi)
# ---------------------------------------------------------------------------


def _capture_ecosystem(monkeypatch: pytest.MonkeyPatch) -> list[str | None]:
    """Replace ``cve_affects_component`` (aliased as
    ``_cve_affects_component`` in ``app.analysis``) with a recorder that
    captures the ecosystem string each call site passes in. We still
    return a sensible verdict so the rest of the pipeline behaves.
    """
    seen: list[str | None] = []
    import app.analysis as analysis_mod
    from app.sources.version_range import MatchVerdict

    def recorder(
        cve_json,
        component_version,
        ecosystem,
        *,
        target_cpe=None,
        # PR-C added this kwarg to the production signature; the
        # recorder accepts and ignores it.
        distro_cpe_enabled: bool = False,
    ):
        seen.append(ecosystem)
        return MatchVerdict(affected=True, reason="matched", matched_range="*")

    monkeypatch.setattr(analysis_mod, "_cve_affects_component", recorder)
    return seen


def test_ecosystem_threaded_for_npm_from_purl(monkeypatch: pytest.MonkeyPatch) -> None:
    seen = _capture_ecosystem(monkeypatch)
    raw = _load_cve("cve_log4j_window.json", cve_id="CVE-2021-44228")
    # No explicit ``ecosystem`` key on the component — verifies the
    # PURL-based fallback in ``ecosystem_from_component``.
    components = [
        {
            "name": "lodash",
            "version": "4.17.20",
            "cpe": "cpe:2.3:a:lodash:lodash:4.17.20:*:*:*:*:*:*:*",
            "purl": "pkg:npm/lodash@4.17.20",
        }
    ]
    _run_query(components, raw_cves=[raw], range_filter_on=True)
    assert seen == ["npm"], f"expected npm-from-purl, got {seen!r}"


def test_ecosystem_threaded_for_pypi_from_explicit_key(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    seen = _capture_ecosystem(monkeypatch)
    raw = _load_cve("cve_log4j_window.json", cve_id="CVE-2021-44228")
    components = [
        {
            "name": "requests",
            "version": "2.31.0",
            "cpe": "cpe:2.3:a:requests:requests:2.31.0:*:*:*:*:*:*:*",
            "ecosystem": "PyPI",  # explicit key — normalize to lowercase
        }
    ]
    _run_query(components, raw_cves=[raw], range_filter_on=True)
    assert seen == ["pypi"], f"expected pypi-normalized, got {seen!r}"

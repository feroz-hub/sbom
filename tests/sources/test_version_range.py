"""Tests for ``app/sources/version_range.py``.

Four buckets per the PR1 brief:

1. Real NVD JSON fixtures — Log4Shell, OpenSSL multi-range, Spring4Shell,
   AND-node, exact-version-pinned CPE.
2. Ecosystem comparators — npm numeric ordering, PEP 440 pre-release,
   Maven SNAPSHOT.
3. Edge cases — open-ended ranges, inclusive/exclusive boundaries,
   unparseable versions, missing configurations.
4. ``MatchVerdict.reason`` populated correctly for every path.

Fixtures follow the existing ``tests/fixtures/nvd/`` convention: full
NVD 2.0 response envelopes with a single CVE inside. ``_load_cve``
unwraps to the inner ``cve`` document, which is the shape
``cve_affects_component`` consumes.
"""

from __future__ import annotations

import json
import logging
from pathlib import Path
from typing import Any

import pytest
from app.sources.version_range import (
    MatchVerdict,
    VersionRange,
    cve_affects_component,
    parse_range,
    version_in_range,
)

FIXTURES = Path(__file__).resolve().parents[1] / "fixtures" / "nvd"


def _load_cve(name: str) -> dict[str, Any]:
    """Load a fixture and return the first ``vulnerabilities[].cve`` object."""
    payload = json.loads((FIXTURES / name).read_text())
    return payload["vulnerabilities"][0]["cve"]


# Convenience constructor — every test that builds a bounds object inline
# would otherwise duplicate the five-field signature, and the
# ``criteria_version=None`` default carries the wildcard semantics.
def _bounds(
    *,
    start_inc: str | None = None,
    start_exc: str | None = None,
    end_inc: str | None = None,
    end_exc: str | None = None,
    pinned: str | None = None,
) -> VersionRange:
    return VersionRange(
        start_including=start_inc,
        start_excluding=start_exc,
        end_including=end_inc,
        end_excluding=end_exc,
        criteria_version=pinned,
    )


# =============================================================================
# Bucket 1 — Real NVD JSON fixtures
# =============================================================================


class TestLog4Shell:
    """CVE-2021-44228 — range [2.0.0, 2.17.0) on apache:log4j."""

    CPE = "cpe:2.3:a:apache:log4j:2.14.0:*:*:*:*:*:*:*"

    def test_in_range_version_matches(self) -> None:
        cve = _load_cve("cve_log4j_window.json")
        v = cve_affects_component(cve, "2.14.0", "maven", target_cpe=self.CPE)
        assert v.affected is True
        assert v.reason == "matched"
        assert v.matched_range == ">= 2.0.0, < 2.17.0"

    def test_boundary_lower_inclusive(self) -> None:
        cve = _load_cve("cve_log4j_window.json")
        v = cve_affects_component(cve, "2.0.0", "maven", target_cpe=self.CPE)
        assert v.affected is True
        assert v.reason == "matched"

    def test_boundary_upper_exclusive(self) -> None:
        cve = _load_cve("cve_log4j_window.json")
        v = cve_affects_component(cve, "2.17.0", "maven", target_cpe=self.CPE)
        assert v.affected is False
        assert v.reason == "out_of_range"

    def test_below_range(self) -> None:
        cve = _load_cve("cve_log4j_window.json")
        v = cve_affects_component(cve, "1.9.0", "maven", target_cpe=self.CPE)
        assert v.affected is False
        assert v.reason == "out_of_range"

    def test_above_range(self) -> None:
        cve = _load_cve("cve_log4j_window.json")
        v = cve_affects_component(cve, "2.17.1", "maven", target_cpe=self.CPE)
        assert v.affected is False
        assert v.reason == "out_of_range"

    def test_stem_mismatch_is_no_configurations(self) -> None:
        # An unrelated CPE stem should not pick up this CVE at all —
        # callers rely on the no_configurations conservative-keep so
        # un-narrowed queries don't silently drop.
        cve = _load_cve("cve_log4j_window.json")
        v = cve_affects_component(
            cve,
            "1.0.0",
            "maven",
            target_cpe="cpe:2.3:a:other:other:1.0.0:*:*:*:*:*:*:*",
        )
        assert v.affected is True
        assert v.reason == "no_configurations"


class TestOpenSSLMultiRange:
    """CVE-2023-0286 — three OR'd ranges across the openssl:openssl product."""

    CPE_WILDCARD = "cpe:2.3:a:openssl:openssl:*:*:*:*:*:*:*:*"

    @pytest.mark.parametrize(
        "version",
        ["1.0.2zd", "1.1.1r", "3.0.7"],
    )
    def test_version_inside_some_range_matches(self, version: str) -> None:
        cve = _load_cve("cve_openssl_multirange.json")
        v = cve_affects_component(cve, version, "generic", target_cpe=self.CPE_WILDCARD)
        assert v.affected is True
        assert v.reason == "matched"

    @pytest.mark.parametrize(
        "version",
        # Below the lowest range (1.0.0 < 1.0.2), in the gap between
        # ranges (2.0.0 sits between the 1.x and 3.x bands), and above
        # the highest range (3.0.8 is the excluding upper of the third
        # band). Letter-suffix orderings like ``1.0.1zz`` are NOT in
        # this list because the semver-ish comparator does not model
        # OpenSSL's letter-release suffix correctly — see the
        # follow-up note in the PR description.
        ["1.0.0", "2.0.0", "3.0.8", "3.1.0"],
    )
    def test_version_outside_all_ranges_dropped(self, version: str) -> None:
        cve = _load_cve("cve_openssl_multirange.json")
        v = cve_affects_component(cve, version, "generic", target_cpe=self.CPE_WILDCARD)
        assert v.affected is False
        assert v.reason == "out_of_range"


class TestSpring4Shell:
    """CVE-2022-22965 — mix of two-bound and open-ended ranges."""

    CPE = "cpe:2.3:a:vmware:spring_framework:5.3.17:*:*:*:*:*:*:*"

    def test_in_5_3_range(self) -> None:
        cve = _load_cve("cve_spring4shell.json")
        v = cve_affects_component(cve, "5.3.17", "maven", target_cpe=self.CPE)
        assert v.affected is True
        assert v.reason == "matched"

    def test_open_ended_lower_below_5_2(self) -> None:
        # The third cpeMatch has only versionEndExcluding=5.2.0 (open
        # lower bound). Anything below 5.2.0 is in range.
        cve = _load_cve("cve_spring4shell.json")
        v = cve_affects_component(cve, "4.3.0", "maven", target_cpe=self.CPE)
        assert v.affected is True
        assert v.reason == "matched"
        assert v.matched_range == "< 5.2.0"

    def test_patched_version_dropped(self) -> None:
        cve = _load_cve("cve_spring4shell.json")
        v = cve_affects_component(cve, "5.3.18", "maven", target_cpe=self.CPE)
        assert v.affected is False
        assert v.reason == "out_of_range"


class TestAndNode:
    """A CVE whose configuration uses ``operator: "AND"`` — we cannot
    decide from a single component, so we conservatively keep and tag.
    """

    def test_and_node_is_ambiguous_keep(self) -> None:
        cve = _load_cve("cve_and_node.json")
        v = cve_affects_component(
            cve,
            "2.3.0",
            "generic",
            target_cpe="cpe:2.3:a:examplecorp:webapp:2.3.0:*:*:*:*:*:*:*",
        )
        assert v.affected is True
        assert v.reason == "and_node_ambiguous"
        assert v.matched_range is None


class TestExactPinned:
    """An ``a:examplecorp:thing:1.2.3`` criteria with no range bounds."""

    CPE = "cpe:2.3:a:examplecorp:thing:1.2.3:*:*:*:*:*:*:*"

    def test_exact_match(self) -> None:
        cve = _load_cve("cve_exact_pinned.json")
        v = cve_affects_component(cve, "1.2.3", "generic", target_cpe=self.CPE)
        assert v.affected is True
        assert v.reason == "matched"
        assert v.matched_range == "= 1.2.3"

    def test_exact_mismatch_dropped(self) -> None:
        cve = _load_cve("cve_exact_pinned.json")
        v = cve_affects_component(cve, "1.2.4", "generic", target_cpe=self.CPE)
        assert v.affected is False
        assert v.reason == "exact_version_mismatch"
        assert v.matched_range == "= 1.2.3"


# =============================================================================
# Bucket 2 — Ecosystem comparator unit tests
# =============================================================================


class TestNpmNumericOrdering:
    """``1.10.0 > 1.9.0`` — the classic lexicographic-trap test."""

    def test_1_10_0_is_above_1_9_0(self) -> None:
        # range [1.9.0, 1.10.0): 1.10.0 should be excluded.
        bounds = _bounds(start_inc="1.9.0", end_exc="1.10.0")
        v = version_in_range("1.10.0", "npm", bounds)
        assert v.affected is False
        assert v.reason == "out_of_range"

    def test_1_9_5_is_inside(self) -> None:
        bounds = _bounds(start_inc="1.9.0", end_exc="1.10.0")
        v = version_in_range("1.9.5", "npm", bounds)
        assert v.affected is True
        assert v.reason == "matched"

    def test_v_prefix_accepted(self) -> None:
        bounds = _bounds(start_inc="1.0.0", end_exc="2.0.0")
        v = version_in_range("v1.5.0", "npm", bounds)
        assert v.affected is True
        assert v.reason == "matched"


class TestPep440PreRelease:
    """``1.0.0rc1 < 1.0.0`` — handled natively by ``packaging.version``."""

    def test_rc1_is_below_final(self) -> None:
        bounds = _bounds(end_exc="1.0.0")
        v = version_in_range("1.0.0rc1", "pypi", bounds)
        assert v.affected is True
        assert v.reason == "matched"

    def test_final_excluded_at_boundary(self) -> None:
        bounds = _bounds(end_exc="1.0.0")
        v = version_in_range("1.0.0", "pypi", bounds)
        assert v.affected is False
        assert v.reason == "out_of_range"

    def test_post_release_ordering(self) -> None:
        # 1.0.0.post1 > 1.0.0 under PEP 440.
        bounds = _bounds(start_inc="1.0.0", end_inc="1.0.0.post5")
        v = version_in_range("1.0.0.post1", "pypi", bounds)
        assert v.affected is True
        assert v.reason == "matched"


class TestMavenSnapshot:
    """``1.0-SNAPSHOT < 1.0`` — Maven's release-precedes-snapshot rule."""

    def test_snapshot_is_below_release(self) -> None:
        # Range: anything strictly before 1.0. SNAPSHOT qualifies.
        bounds = _bounds(end_exc="1.0")
        v = version_in_range("1.0-SNAPSHOT", "maven", bounds)
        assert v.affected is True
        assert v.reason == "matched"

    def test_release_at_boundary_excluded(self) -> None:
        bounds = _bounds(end_exc="1.0")
        v = version_in_range("1.0", "maven", bounds)
        assert v.affected is False
        assert v.reason == "out_of_range"

    def test_snapshot_in_open_range(self) -> None:
        # Range [0.9, 1.0]: 1.0-SNAPSHOT sits below the upper bound.
        bounds = _bounds(start_inc="0.9", end_inc="1.0")
        v = version_in_range("1.0-SNAPSHOT", "maven", bounds)
        assert v.affected is True
        assert v.reason == "matched"


class TestEcosystemNormalization:
    """Common ecosystem aliases must route to the right comparator."""

    @pytest.mark.parametrize(
        "alias",
        ["pypi", "PyPI", "pip", "python"],
    )
    def test_pypi_aliases(self, alias: str) -> None:
        bounds = _bounds(end_exc="1.0.0")
        v = version_in_range("1.0.0rc1", alias, bounds)
        assert v.reason == "matched", f"alias={alias!r}"

    @pytest.mark.parametrize(
        "alias",
        ["maven", "java"],
    )
    def test_maven_aliases(self, alias: str) -> None:
        bounds = _bounds(end_exc="1.0")
        v = version_in_range("1.0-SNAPSHOT", alias, bounds)
        assert v.reason == "matched", f"alias={alias!r}"

    @pytest.mark.parametrize(
        "alias",
        ["npm", "node", "nodejs"],
    )
    def test_npm_aliases(self, alias: str) -> None:
        bounds = _bounds(start_inc="1.9.0", end_exc="1.10.0")
        v = version_in_range("1.10.0", alias, bounds)
        assert v.reason == "out_of_range", f"alias={alias!r}"


# =============================================================================
# Bucket 3 — Edge cases
# =============================================================================


class TestOpenEndedRanges:
    def test_only_lower_inclusive(self) -> None:
        bounds = _bounds(start_inc="2.0.0")
        assert version_in_range("2.0.0", "npm", bounds).reason == "matched"
        assert version_in_range("100.0.0", "npm", bounds).reason == "matched"
        assert version_in_range("1.99.99", "npm", bounds).reason == "out_of_range"

    def test_only_upper_exclusive(self) -> None:
        bounds = _bounds(end_exc="2.0.0")
        assert version_in_range("0.0.1", "npm", bounds).reason == "matched"
        assert version_in_range("1.99.99", "npm", bounds).reason == "matched"
        assert version_in_range("2.0.0", "npm", bounds).reason == "out_of_range"

    def test_only_lower_exclusive(self) -> None:
        bounds = _bounds(start_exc="2.0.0")
        assert version_in_range("2.0.0", "npm", bounds).reason == "out_of_range"
        assert version_in_range("2.0.1", "npm", bounds).reason == "matched"

    def test_only_upper_inclusive(self) -> None:
        bounds = _bounds(end_inc="2.0.0")
        assert version_in_range("2.0.0", "npm", bounds).reason == "matched"
        assert version_in_range("2.0.1", "npm", bounds).reason == "out_of_range"


class TestInclusiveExclusiveBoundary:
    """Boundary values for every combination of inclusive/exclusive bounds."""

    def test_both_inclusive(self) -> None:
        bounds = _bounds(start_inc="1.0.0", end_inc="2.0.0")
        assert version_in_range("1.0.0", "npm", bounds).reason == "matched"
        assert version_in_range("2.0.0", "npm", bounds).reason == "matched"

    def test_both_exclusive(self) -> None:
        bounds = _bounds(start_exc="1.0.0", end_exc="2.0.0")
        assert version_in_range("1.0.0", "npm", bounds).reason == "out_of_range"
        assert version_in_range("2.0.0", "npm", bounds).reason == "out_of_range"
        assert version_in_range("1.5.0", "npm", bounds).reason == "matched"

    def test_mixed(self) -> None:
        bounds = _bounds(start_inc="1.0.0", end_exc="2.0.0")
        assert version_in_range("1.0.0", "npm", bounds).reason == "matched"
        assert version_in_range("2.0.0", "npm", bounds).reason == "out_of_range"


class TestUnparseableVersions:
    def test_unparseable_component_version_keeps_finding(
        self,
        caplog: pytest.LogCaptureFixture,
    ) -> None:
        bounds = _bounds(start_inc="1.0.0", end_exc="2.0.0")
        with caplog.at_level(logging.WARNING, logger="app.sources.version_range"):
            # Drive the unparseable path through ``cve_affects_component``
            # so the structured warning fires from the node walker.
            cve = {
                "configurations": [
                    {
                        "nodes": [
                            {
                                "operator": "OR",
                                "negate": False,
                                "cpeMatch": [
                                    {
                                        "vulnerable": True,
                                        "criteria": "cpe:2.3:a:e:p:*:*:*:*:*:*:*:*",
                                        "versionStartIncluding": bounds.start_including,
                                        "versionEndExcluding": bounds.end_excluding,
                                    }
                                ],
                            }
                        ]
                    }
                ]
            }
            v = cve_affects_component(cve, "not-a-version-!!!", "pypi")
        assert v.affected is True
        assert v.reason == "version_unparseable"
        assert v.matched_range == ">= 1.0.0, < 2.0.0"
        # Structured warning fired so operators can find silent-drop bugs.
        assert any(
            "unparseable version" in r.getMessage() for r in caplog.records
        ), "expected unparseable-version warning to be emitted"

    def test_empty_component_version_keeps_finding(self) -> None:
        bounds = _bounds(start_inc="1.0.0", end_exc="2.0.0")
        v = version_in_range("", "npm", bounds)
        assert v.affected is True
        assert v.reason == "version_unparseable"

    def test_unparseable_bound_keeps_finding(self) -> None:
        # PEP 440 will reject `not-a-version` on the bound side.
        bounds = _bounds(start_inc="not-a-version", end_exc="2.0.0")
        v = version_in_range("1.5.0", "pypi", bounds)
        assert v.affected is True
        assert v.reason == "version_unparseable"


class TestMissingConfigurations:
    def test_configurations_key_absent(self) -> None:
        v = cve_affects_component({}, "1.0.0", "npm")
        assert v.affected is True
        assert v.reason == "no_configurations"

    def test_configurations_empty_list(self) -> None:
        v = cve_affects_component({"configurations": []}, "1.0.0", "npm")
        assert v.affected is True
        assert v.reason == "no_configurations"

    def test_configurations_with_no_nodes(self) -> None:
        v = cve_affects_component(
            {"configurations": [{"nodes": []}]}, "1.0.0", "npm"
        )
        assert v.affected is True
        assert v.reason == "no_configurations"


class TestNonVulnerableMatchIgnored:
    def test_vulnerable_false_skipped(self) -> None:
        cve = {
            "configurations": [
                {
                    "nodes": [
                        {
                            "operator": "OR",
                            "negate": False,
                            "cpeMatch": [
                                {
                                    "vulnerable": False,
                                    "criteria": "cpe:2.3:a:e:p:1.0.0:*:*:*:*:*:*:*",
                                }
                            ],
                        }
                    ]
                }
            ]
        }
        v = cve_affects_component(cve, "1.0.0", "generic")
        # No applicable cpeMatch (the only one is non-vulnerable) →
        # conservative no_configurations keep.
        assert v.affected is True
        assert v.reason == "no_configurations"


class TestUnsupportedEcosystem:
    """Distro / Conan ecosystem behaviour — dual mode after roadmap #5 PR-C.

    Flag OFF (default): conservative-keep with ``ecosystem_unsupported``.
    Byte-identical to pre-#5 behaviour — any regression here would be
    a silent change in flag-off semantics.

    Flag ON: distro versions normalise to upstream and route through
    the default semver-ish comparator. Verdict becomes
    ``matched`` / ``out_of_range`` per the comparison result.
    """

    # ----- Flag OFF — legacy conservative-keep ------------------------------

    @pytest.mark.parametrize("eco", ["deb", "rpm", "apk", "conan", "alpine"])
    def test_flag_off_distro_ecosystems_are_conservative_keep(
        self, eco: str
    ) -> None:
        bounds = _bounds(start_inc="1.0", end_exc="2.0")
        v = version_in_range("1.5", eco, bounds)
        assert v.affected is True
        assert v.reason == "ecosystem_unsupported"

    @pytest.mark.parametrize("eco", ["deb", "rpm", "apk", "conan", "alpine"])
    def test_flag_off_explicit_false_matches_default(self, eco: str) -> None:
        # Passing ``distro_cpe_enabled=False`` explicitly must give
        # the same result as the default — guards against drift in
        # the default value.
        bounds = _bounds(start_inc="1.0", end_exc="2.0")
        v = version_in_range("1.5", eco, bounds, distro_cpe_enabled=False)
        assert v.reason == "ecosystem_unsupported"

    # ----- Flag ON, in-range — matched -------------------------------------

    def test_flag_on_deb_in_range_matches(self) -> None:
        # Realistic Debian PURL: ``pkg:deb/debian/openssl@2:3.0.2-1``
        # normalises to ``3.0.2`` and compares against an NVD range
        # ``< 3.0.7`` — affected.
        bounds = _bounds(end_exc="3.0.7")
        v = version_in_range(
            "2:3.0.2-1", "deb", bounds, distro_cpe_enabled=True,
        )
        assert v.affected is True
        assert v.reason == "matched"

    def test_flag_on_rpm_in_range_matches(self) -> None:
        # ``3.0.2-1.el8`` strips to ``3.0.2`` and falls inside.
        bounds = _bounds(start_inc="3.0.0", end_exc="3.0.7")
        v = version_in_range(
            "3.0.2-1.el8", "rpm", bounds, distro_cpe_enabled=True,
        )
        assert v.reason == "matched"

    def test_flag_on_apk_in_range_matches(self) -> None:
        # ``3.0.2-r0`` strips to ``3.0.2``.
        bounds = _bounds(end_exc="3.0.7")
        v = version_in_range(
            "3.0.2-r0", "apk", bounds, distro_cpe_enabled=True,
        )
        assert v.reason == "matched"

    def test_flag_on_conan_in_range_matches(self) -> None:
        # Conan versions pass through; ``1.81.0`` compares directly.
        bounds = _bounds(start_inc="1.80.0", end_exc="2.0.0")
        v = version_in_range(
            "1.81.0", "conan", bounds, distro_cpe_enabled=True,
        )
        assert v.reason == "matched"

    # ----- Flag ON, out-of-range — dropped ---------------------------------

    def test_flag_on_deb_above_range_drops(self) -> None:
        # ``3.0.8-1`` normalises to ``3.0.8``; NVD range ``< 3.0.7``
        # → above → out_of_range (the finding is dropped).
        bounds = _bounds(end_exc="3.0.7")
        v = version_in_range(
            "3.0.8-1", "deb", bounds, distro_cpe_enabled=True,
        )
        assert v.affected is False
        assert v.reason == "out_of_range"

    def test_flag_on_apk_below_range_drops(self) -> None:
        bounds = _bounds(start_inc="2.0.0", end_exc="3.0.0")
        v = version_in_range(
            "1.9.9-r5", "apk", bounds, distro_cpe_enabled=True,
        )
        assert v.affected is False
        assert v.reason == "out_of_range"

    # ----- Flag ON, normalisation stripping --------------------------------

    def test_flag_on_deb_epoch_plus_revision_normalises_to_upstream(
        self,
    ) -> None:
        # ``2:3.0.2-1+deb11u5`` — epoch ``2:`` AND revision ``-1+deb11u5``.
        # After normalisation: ``3.0.2``. Range ``< 3.0.7`` → matched.
        bounds = _bounds(end_exc="3.0.7")
        v = version_in_range(
            "2:3.0.2-1+deb11u5", "deb", bounds, distro_cpe_enabled=True,
        )
        assert v.reason == "matched"
        # Confirm the matched_range label uses the bound (proves the
        # comparison ran, not a degenerate path).
        assert v.matched_range == "< 3.0.7"

    def test_flag_on_rpm_release_strip_includes_dist_suffix(self) -> None:
        # ``1:3.0.2-1.el8`` — epoch + release with .el8 dist suffix.
        bounds = _bounds(end_exc="3.0.7")
        v = version_in_range(
            "1:3.0.2-1.el8", "rpm", bounds, distro_cpe_enabled=True,
        )
        assert v.reason == "matched"

    # ----- Flag ON, non-distro ecosystem unchanged --------------------------

    def test_flag_on_non_distro_ecosystem_unchanged(self) -> None:
        # npm under flag-on must produce the same comparison result as
        # under flag-off — the distro branch never fires for it.
        bounds = _bounds(start_inc="1.0.0", end_exc="2.0.0")
        v_off = version_in_range("1.5.0", "npm", bounds)
        v_on = version_in_range(
            "1.5.0", "npm", bounds, distro_cpe_enabled=True,
        )
        assert v_off == v_on
        assert v_on.reason == "matched"

    def test_flag_on_pypi_unchanged(self) -> None:
        bounds = _bounds(end_exc="1.0.0")
        v_off = version_in_range("1.0.0rc1", "pypi", bounds)
        v_on = version_in_range(
            "1.0.0rc1", "pypi", bounds, distro_cpe_enabled=True,
        )
        assert v_off == v_on
        assert v_on.reason == "matched"

    # ----- Flag ON edge cases -----------------------------------------------

    def test_flag_on_empty_upstream_after_strip_is_unparseable(self) -> None:
        # A pathological deb version that's ONLY an epoch + revision
        # — after stripping, the upstream slot is empty. The
        # normalize-and-compare path treats this as unparseable
        # (conservative-keep), not a successful match.
        bounds = _bounds(end_exc="3.0.7")
        v = version_in_range(
            "1:-1", "deb", bounds, distro_cpe_enabled=True,
        )
        # ``1:-1`` → strip epoch → ``-1`` → rsplit("-",1)[0] → ""
        # → falls into the empty-after-normalise branch.
        assert v.affected is True
        assert v.reason == "version_unparseable"


class TestParseRange:
    def test_parses_all_four_bounds(self) -> None:
        bounds = parse_range(
            {
                "criteria": "cpe:2.3:a:v:p:*:*:*:*:*:*:*:*",
                "versionStartIncluding": "1.0.0",
                "versionStartExcluding": "0.9.0",
                "versionEndIncluding": "2.0.0",
                "versionEndExcluding": "2.1.0",
            }
        )
        assert bounds is not None
        assert bounds.start_including == "1.0.0"
        assert bounds.start_excluding == "0.9.0"
        assert bounds.end_including == "2.0.0"
        assert bounds.end_excluding == "2.1.0"
        assert bounds.criteria_version is None  # criteria is wildcarded

    def test_pinned_criteria_yields_criteria_version(self) -> None:
        bounds = parse_range({"criteria": "cpe:2.3:a:v:p:1.2.3:*:*:*:*:*:*:*"})
        assert bounds is not None
        assert bounds.criteria_version == "1.2.3"
        assert bounds.start_including is None
        assert bounds.end_excluding is None

    def test_malformed_match_returns_none(self) -> None:
        assert parse_range({}) is None
        assert parse_range({"criteria": ""}) is None
        assert parse_range({"criteria": None}) is None  # type: ignore[arg-type]


# =============================================================================
# Bucket 4 — Every reason value is reachable
# =============================================================================


class TestEveryReasonReachable:
    """Confirms each ``MatchReason`` value can be produced by a realistic
    input. Acts as a load-bearing test against the Literal — if a new
    reason is added without a test case, this class needs a new entry,
    and that's the gate that forces the brief's ``forward-compat with
    roadmap #6`` discipline to hold.
    """

    def test_matched(self) -> None:
        v = version_in_range("1.5.0", "npm", _bounds(start_inc="1.0.0", end_exc="2.0.0"))
        assert v == MatchVerdict(affected=True, reason="matched", matched_range=">= 1.0.0, < 2.0.0")

    def test_out_of_range(self) -> None:
        v = version_in_range("3.0.0", "npm", _bounds(start_inc="1.0.0", end_exc="2.0.0"))
        assert v == MatchVerdict(affected=False, reason="out_of_range", matched_range=">= 1.0.0, < 2.0.0")

    def test_no_configurations(self) -> None:
        v = cve_affects_component({}, "1.0.0", "npm")
        assert v.reason == "no_configurations"
        assert v.affected is True

    def test_version_unparseable(self) -> None:
        v = version_in_range("???", "pypi", _bounds(end_exc="1.0.0"))
        assert v.reason == "version_unparseable"
        assert v.affected is True

    def test_ecosystem_unsupported(self) -> None:
        v = version_in_range("1.0", "deb", _bounds(end_exc="2.0"))
        assert v.reason == "ecosystem_unsupported"
        assert v.affected is True

    def test_and_node_ambiguous(self) -> None:
        cve = _load_cve("cve_and_node.json")
        v = cve_affects_component(cve, "2.3.0", "generic")
        assert v.reason == "and_node_ambiguous"
        assert v.affected is True

    def test_exact_version_mismatch(self) -> None:
        cve = _load_cve("cve_exact_pinned.json")
        v = cve_affects_component(
            cve, "9.9.9", "generic",
            target_cpe="cpe:2.3:a:examplecorp:thing:9.9.9:*:*:*:*:*:*:*",
        )
        assert v.reason == "exact_version_mismatch"
        assert v.affected is False

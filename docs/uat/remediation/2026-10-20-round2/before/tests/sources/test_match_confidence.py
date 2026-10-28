"""Tests for ``app/sources/match_confidence.py``.

Six buckets per the PR-B brief:

1. Strong match — name + version + vendor all in cve_text → high (>= 0.9).
2. Per-field isolation — name-only, version-only, vendor-only each
   contribute roughly their (renormalized) weight.
3. No overlap → ~0.0.
4. Vendor-None renormalization (load-bearing) — vendor=None scores
   the SAME as vendor-provided-but-absent-from-text.
5. Tokenization edge cases — scoped npm names, hyphenated names,
   alphanumeric tokens like ``log4j2``.
6. Empty ``component_name`` short-circuit to 0.0.
"""

from __future__ import annotations

import pytest
from app.sources.match_confidence import (
    NAME_WEIGHT,
    VENDOR_WEIGHT,
    VERSION_WEIGHT,
    ConfidenceResult,
    score_match,
)

# When vendor renormalizes away, name/version pick up its weight
# proportionally. Used in several test classes below for the expected
# renormalized weights.
_RENORM_NAME = NAME_WEIGHT / (NAME_WEIGHT + VERSION_WEIGHT)
_RENORM_VERSION = VERSION_WEIGHT / (NAME_WEIGHT + VERSION_WEIGHT)


# =============================================================================
# Bucket 1 — Strong match
# =============================================================================


class TestStrongMatch:
    def test_log4shell_all_three_signals_present_scores_at_least_0_9(self) -> None:
        # Realistic CVE text mentioning name (log4j-core via its tokens),
        # the exact version 2.14.0, and the vendor apache.
        result = score_match(
            component_name="log4j-core",
            component_version="2.14.0",
            component_vendor="apache",
            cve_text=(
                "Apache Log4j2 versions 2.0-beta9 through 2.14.0 JNDI "
                "features used in configuration of log4j-core are "
                "vulnerable to remote code execution."
            ),
        )
        assert result.confidence >= 0.9, f"strong-signal match should score >=0.9, got {result.confidence}"
        assert result.name_score == 1.0
        assert result.version_score == 1.0
        assert result.vendor_score == 1.0


# =============================================================================
# Bucket 2 — Per-field isolation
# =============================================================================


class TestPerFieldIsolation:
    """Each sub-score, in isolation, contributes roughly its weight.

    Note the renormalization effect: when vendor evidence is absent,
    name and version pick up vendor's weight proportionally, so the
    "name-only" expected value is ``NAME_WEIGHT / (NAME + VERSION)`` —
    higher than the bare ``NAME_WEIGHT``. The vendor-only case is the
    only one where vendor evidence IS present, so weights stay at
    their base values.
    """

    def test_name_only_scores_renormalized_name_weight(self) -> None:
        result = score_match(
            component_name="log4j-core",
            component_version="2.14.0",
            component_vendor="apache",
            cve_text="log4j-core appears here, nothing else relevant",
        )
        assert result.name_score == 1.0
        assert result.version_score == 0.0
        assert result.vendor_score == 0.0
        # Vendor renormalized away → name picks up extra weight.
        assert result.confidence == pytest.approx(round(_RENORM_NAME, 3), abs=1e-3)

    def test_version_only_scores_renormalized_version_weight(self) -> None:
        result = score_match(
            component_name="log4j-core",
            component_version="2.14.0",
            component_vendor="apache",
            cve_text="A vulnerability fixed in 2.14.0 of an unrelated thing",
        )
        assert result.name_score == 0.0
        assert result.version_score == 1.0
        assert result.vendor_score == 0.0
        assert result.confidence == pytest.approx(round(_RENORM_VERSION, 3), abs=1e-3)

    def test_vendor_only_scores_base_vendor_weight(self) -> None:
        # Vendor IS present in text → no renormalization, base weights apply.
        result = score_match(
            component_name="log4j-core",
            component_version="2.14.0",
            component_vendor="apache",
            cve_text="apache published an advisory about an unrelated artifact",
        )
        assert result.name_score == 0.0
        assert result.version_score == 0.0
        assert result.vendor_score == 1.0
        assert result.confidence == pytest.approx(VENDOR_WEIGHT, abs=1e-3)


# =============================================================================
# Bucket 3 — No overlap
# =============================================================================


class TestNoOverlap:
    def test_zero_signal_text_scores_zero(self) -> None:
        result = score_match(
            component_name="log4j-core",
            component_version="2.14.0",
            component_vendor="apache",
            cve_text="This advisory concerns an entirely different ecosystem.",
        )
        assert result.confidence == 0.0
        assert result.name_score == 0.0
        assert result.version_score == 0.0
        assert result.vendor_score == 0.0


# =============================================================================
# Bucket 4 — Vendor-None renormalization (load-bearing)
# =============================================================================


class TestVendorNoneRenormalization:
    """The brief calls this out as load-bearing: a missing vendor must
    NOT cap the achievable confidence below 1.0, and the vendor=None
    case must score the SAME as vendor-provided-but-not-in-text.
    """

    CVE_TEXT = "log4j-core 2.14.0 is affected per this advisory"

    def test_vendor_none_and_vendor_not_in_text_score_identically(self) -> None:
        without_vendor = score_match(
            component_name="log4j-core",
            component_version="2.14.0",
            component_vendor=None,
            cve_text=self.CVE_TEXT,
        )
        with_unmatched_vendor = score_match(
            component_name="log4j-core",
            component_version="2.14.0",
            component_vendor="some-vendor-not-in-text",
            cve_text=self.CVE_TEXT,
        )
        assert without_vendor == with_unmatched_vendor

    def test_vendor_none_does_not_cap_below_with_vendor_ceiling(self) -> None:
        # Strong name + strong version, no vendor → must reach the same
        # 1.0 ceiling that a strong name + version + vendor match reaches.
        result = score_match(
            component_name="log4j-core",
            component_version="2.14.0",
            component_vendor=None,
            cve_text=self.CVE_TEXT,
        )
        assert result.confidence == 1.0

    def test_empty_string_vendor_treated_as_none(self) -> None:
        empty_vendor = score_match(
            component_name="log4j-core",
            component_version="2.14.0",
            component_vendor="",
            cve_text=self.CVE_TEXT,
        )
        none_vendor = score_match(
            component_name="log4j-core",
            component_version="2.14.0",
            component_vendor=None,
            cve_text=self.CVE_TEXT,
        )
        assert empty_vendor == none_vendor


# =============================================================================
# Bucket 5 — Tokenization edge cases
# =============================================================================


class TestTokenizationEdgeCases:
    def test_scoped_npm_name_splits_on_slash_and_at(self) -> None:
        # ``@angular/core`` is a real scoped npm name. The PURL parser
        # would surface vendor=angular, name=core; this test exercises
        # tokenization of the raw string forms as well, since callers
        # may pass either shape.
        result = score_match(
            component_name="core",
            component_version="14.0.0",
            component_vendor="angular",
            cve_text=("An issue in @angular/core 14.0.0 allows prototype pollution under specific conditions."),
        )
        # angular + core both appear in the text; version 14.0.0 too.
        assert result.name_score == 1.0
        assert result.version_score == 1.0
        assert result.vendor_score == 1.0
        assert result.confidence == 1.0

    def test_hyphenated_name_tokenizes_into_segments(self) -> None:
        # log4j-core → tokens {log4j, core}. Text contains BOTH tokens
        # separately ("log4j ... core ...") which should still hit 1.0.
        result = score_match(
            component_name="log4j-core",
            component_version="2.14.0",
            component_vendor=None,
            cve_text="Affected: log4j library; specifically the core artifact at 2.14.0.",
        )
        assert result.name_score == 1.0

    def test_alphanumeric_token_stays_intact(self) -> None:
        # log4j2 must tokenize to {log4j2}, not {log4j, 2} — the
        # non-alphanumeric splitter only breaks on non-alnum runs, so
        # an embedded digit stays attached.
        result_match = score_match(
            component_name="log4j2",
            component_version="2.14.0",
            component_vendor=None,
            cve_text="Apache log4j2 versions through 2.14.0 are vulnerable",
        )
        assert result_match.name_score == 1.0

        # And the reverse: if the text spells "log4j 2" (split), the
        # alphanumeric token does NOT match.
        result_miss = score_match(
            component_name="log4j2",
            component_version="2.14.0",
            component_vendor=None,
            cve_text="Apache log4j 2 historical versions",
        )
        assert result_miss.name_score == 0.0


# =============================================================================
# Bucket 5 (continued) — Version-token false-positive guard
# =============================================================================


class TestVersionSubscore:
    def test_full_version_matches_with_word_boundary(self) -> None:
        result = score_match(
            component_name="thing",
            component_version="1.0",
            component_vendor=None,
            cve_text="The thing at 1.0 is affected",
        )
        assert result.version_score == 1.0

    def test_full_version_does_not_match_a_longer_version_substring(self) -> None:
        # Word-boundary guard: "1.0" must NOT match "10.0".
        result = score_match(
            component_name="thing",
            component_version="1.0",
            component_vendor=None,
            cve_text="The thing at 10.0 is affected; 1.0 is fine",
        )
        # "1.0" IS in the text as a standalone token here, so this
        # asserts the GOOD case after the prior bad-case verification.
        # The bad-case (10.0 only) is checked next.
        assert result.version_score == 1.0

    def test_full_version_does_not_match_only_when_subsumed(self) -> None:
        result = score_match(
            component_name="thing",
            component_version="1.0",
            component_vendor=None,
            cve_text="The thing at 10.0 is affected.",
        )
        # No standalone 1.0 — only embedded inside 10.0. Must score 0.
        assert result.version_score == 0.0

    def test_partial_major_minor_credit(self) -> None:
        # Full "2.14.0" not in text; "2.14" is.
        result = score_match(
            component_name="thing",
            component_version="2.14.0",
            component_vendor=None,
            cve_text="Versions 2.14 series are affected",
        )
        assert result.version_score == 0.5


# =============================================================================
# Bucket 6 — Empty component name
# =============================================================================


class TestEmptyComponentName:
    @pytest.mark.parametrize("name", ["", "   "])
    def test_blank_name_short_circuits_to_zero(self, name: str) -> None:
        result = score_match(
            component_name=name,
            component_version="2.14.0",
            component_vendor="apache",
            cve_text="Apache log4j 2.14.0 is affected",
        )
        assert result == ConfidenceResult(confidence=0.0, name_score=0.0, version_score=0.0, vendor_score=0.0)


# =============================================================================
# Sanity — output bounds
# =============================================================================


class TestOutputBounds:
    @pytest.mark.parametrize(
        "name,version,vendor,text",
        [
            ("log4j-core", "2.14.0", "apache", "Apache log4j-core 2.14.0 RCE"),
            ("requests", "2.31.0", None, "requests 2.31.0 fixed an issue"),
            ("foo", "1.0.0", "bar", "completely unrelated text"),
            ("", None, None, ""),
        ],
    )
    def test_confidence_is_in_unit_interval_and_3_decimals(
        self, name: str, version: str | None, vendor: str | None, text: str
    ) -> None:
        result = score_match(
            component_name=name,
            component_version=version,
            component_vendor=vendor,
            cve_text=text,
        )
        assert 0.0 <= result.confidence <= 1.0
        # Round-trip through 3-decimal rounding is idempotent.
        assert result.confidence == round(result.confidence, 3)

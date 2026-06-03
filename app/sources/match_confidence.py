"""
Per-finding match-confidence scoring (roadmap #3).

Pure-functional module. No I/O, no DB, no network, no clock — every
input is passed in and every output is returned. Mirrors the posture
of ``app/sources/version_range.py``: frozen result dataclass,
module-level logger, deterministic, no third-party deps.

Why this exists
---------------
Findings produced by NVD's *keyword-search* fallback today are all
treated equally regardless of how well the component actually matches
the CVE. A package called "spring" hit by a CVE that mentions "spring"
generically (the verb, the season) ends up indistinguishable from a
package called "spring" hit by an advisory naming the same artifact
explicitly. A token-overlap heuristic gives analysts a triage signal.

This module is the single source of truth for the confidence number
written into ``analysis_finding.match_confidence`` (migration 017).
Wiring (which finding gets scored, how ``cve_text`` is assembled per
source) is PR-C's job — strategy decisions (e.g. "should CPE-strategy
matches get a confidence floor instead of pure token scoring?")
layer on top.

Scoring model
-------------
Three sub-scores, each a token-overlap presence ratio in ``[0.0, 1.0]``:

  * ``name_score``    — fraction of component-name tokens present in the
                        tokenized CVE text.
  * ``version_score`` — 1.0 if the full version string is a word-boundary
                        match in ``cve_text``; ``PARTIAL_VERSION_CREDIT``
                        (0.5) if only ``major.minor`` matches; 0.0
                        otherwise. **Token-presence only — version-range
                        comparison is roadmap #1's job (do NOT import or
                        duplicate that logic here).**
  * ``vendor_score``  — fraction of vendor tokens present in the
                        tokenized CVE text.

Combined by named weights (``NAME_WEIGHT`` / ``VERSION_WEIGHT`` /
``VENDOR_WEIGHT``), summing to 1.0. The weights are a first-pass
heuristic — see the calibration follow-up note below.

Vendor-None renormalization (load-bearing)
------------------------------------------
Many PURLs have no usable vendor namespace (PyPI without org,
generic ecosystems). To prevent a missing or unmatched vendor from
capping the achievable confidence below 1.0, ``VENDOR_WEIGHT`` is
redistributed proportionally to ``NAME_WEIGHT`` and ``VERSION_WEIGHT``
whenever ``vendor_score == 0.0`` — regardless of *why* it is zero.
That covers two cases the brief calls out as equivalent:

  * ``component_vendor`` is ``None`` / empty → no vendor input at all.
  * ``component_vendor`` was provided but its tokens do not appear in
    ``cve_text`` → vendor evidence is informationally absent.

Treating both as "no useful vendor signal" means a strong name+version
match against an unmatched vendor scores identically to the same
name+version match without any vendor input. The trade-off: an
incorrect vendor input (e.g. PURL namespace mis-derived) is NOT
penalized as weakly-negative evidence. The calibration pass should
revisit this if dogfooding shows false-positive bursts.

A vendor sub-score that is renormalized away is still recorded as
``vendor_score = 0.0`` on the result. Consumers wanting "was vendor
renormalized away?" can test that field directly — but the headline
``confidence`` already reflects the renormalization, so the UI doesn't
need to know unless it wants to surface "scored without vendor signal"
in explainability copy.

Calibration & known false-positive risk (follow-ups, not in scope)
-----------------------------------------------------------------
* The three weights and the stop-token list are heuristic; they should
  be tuned against the dogfood data once roadmap #3 ships. Both are
  intentionally exposed as module-level ``Final`` constants so a
  calibration PR is a one-file change.
* Generic-name false positives: a single-token name that doubles as an
  English word (``requests``, ``express``, ``spring``, ``maven``) will
  over-match CVE descriptions that use the word generically. The
  calibration pass should consider per-token specificity weighting
  (IDF-style) or a domain-specific stop-token extension; the simple
  presence ratio here does not.
"""

from __future__ import annotations

import logging
import re
from dataclasses import dataclass
from typing import Final

log = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Tunables — first-pass heuristics; the calibration follow-up tunes here.
# ---------------------------------------------------------------------------

NAME_WEIGHT: Final[float] = 0.5
VERSION_WEIGHT: Final[float] = 0.3
VENDOR_WEIGHT: Final[float] = 0.2

# Partial credit when only the component's ``major.minor`` segment
# appears in ``cve_text`` (e.g. CVE description says "Versions 2.14
# through 2.16" but the component is 2.14.0 — major.minor matches,
# the patch level does not).
PARTIAL_VERSION_CREDIT: Final[float] = 0.5

# Minimum token length to keep after splitting. Single-character tokens
# (``v`` prefix, ``x`` placeholders, single digits) are too noisy as
# match evidence.
_MIN_TOKEN_LEN: Final[int] = 2

# Stop-tokens dropped from BOTH the component identity and the CVE
# evidence text. Deliberately conservative — over-aggressive stopping
# loses distinguishing signal. Tunable; see calibration follow-up.
#
# Why NOT in the list: "core" (real artifact name suffix —
# ``log4j-core``), "client" / "server" / "api" (often part of real
# package names), "node" (real ecosystem name).
_STOPLIST: Final[frozenset[str]] = frozenset(
    {
        # Articles, prepositions, conjunctions
        "the", "an", "of", "for", "in", "on", "to", "and", "or", "is", "by",
        "as", "at", "be", "it", "if",
        # Generic CVE-text noise — appears so often it carries no signal
        "library", "package", "module",
    }
)

# Sanity: a typo in the weight constants is a load-time error rather
# than a silently-skewed score.
assert abs((NAME_WEIGHT + VERSION_WEIGHT + VENDOR_WEIGHT) - 1.0) < 1e-9, (
    f"weights must sum to 1.0; got "
    f"{NAME_WEIGHT} + {VERSION_WEIGHT} + {VENDOR_WEIGHT}"
)


@dataclass(frozen=True, slots=True)
class ConfidenceResult:
    """Score breakdown for one (component, CVE) candidate.

    ``confidence`` is the actionable number — clamped to ``[0.0, 1.0]``
    and rounded to 3 decimals. The three sub-scores are exposed for
    explainability surfaces (UI tooltip, CSV/SARIF/XLSX export). A
    ``vendor_score`` of exactly 0.0 means vendor evidence was renormalized
    away (either no vendor input, or input not found in CVE text);
    ``confidence`` already reflects that.
    """

    confidence: float
    name_score: float
    version_score: float
    vendor_score: float


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------


def score_match(
    *,
    component_name: str,
    component_version: str | None,
    component_vendor: str | None,
    cve_text: str,
) -> ConfidenceResult:
    """Score one (component, CVE) candidate by token overlap.

    ``cve_text`` is whatever evidence the caller assembled for this
    candidate (description + matched CPE criteria + keyword query +
    any source-specific hints). PR-C decides the per-source assembly
    rule; this module is strategy-agnostic.

    Returns a frozen ``ConfidenceResult``. Empty / blank
    ``component_name`` short-circuits to all-zeros (no basis to
    score) — every other case flows through the normal three-subscore
    path with vendor-None renormalization applied as documented at the
    module level.
    """
    if not component_name or not component_name.strip():
        return ConfidenceResult(
            confidence=0.0, name_score=0.0, version_score=0.0, vendor_score=0.0
        )

    text_tokens = _tokenize(cve_text)
    text_lc = cve_text.lower()

    name_score = _presence_ratio(_tokenize(component_name), text_tokens)
    version_score = _version_subscore(component_version, text_lc)
    vendor_score = _presence_ratio(_tokenize(component_vendor or ""), text_tokens)

    # Vendor-None renormalization: when vendor evidence carries no
    # signal (either absent input or not found in text), redistribute
    # its weight to name and version so the achievable confidence
    # ceiling stays at 1.0.
    if vendor_score == 0.0:
        remaining = NAME_WEIGHT + VERSION_WEIGHT
        name_w = NAME_WEIGHT / remaining
        version_w = VERSION_WEIGHT / remaining
        vendor_w = 0.0
    else:
        name_w = NAME_WEIGHT
        version_w = VERSION_WEIGHT
        vendor_w = VENDOR_WEIGHT

    raw = name_w * name_score + version_w * version_score + vendor_w * vendor_score
    confidence = round(max(0.0, min(1.0, raw)), 3)

    return ConfidenceResult(
        confidence=confidence,
        name_score=round(name_score, 3),
        version_score=round(version_score, 3),
        vendor_score=round(vendor_score, 3),
    )


# ---------------------------------------------------------------------------
# Internals
# ---------------------------------------------------------------------------


_NON_ALNUM_SPLIT_RE = re.compile(r"[^a-z0-9]+")


def _tokenize(s: str | None) -> frozenset[str]:
    """Lowercase, split on non-alphanumerics, drop short and stopword tokens.

    Returns a ``frozenset`` so callers can take set operations cheaply.
    Examples (with the default stoplist):
        ``"log4j-core"``      → {"log4j", "core"}
        ``"@angular/core"``   → {"angular", "core"}
        ``"log4j2"``          → {"log4j2"}
        ``"the library"``     → frozenset()  (both stopworded)
    """
    if not s:
        return frozenset()
    parts = _NON_ALNUM_SPLIT_RE.split(s.lower())
    return frozenset(
        p for p in parts
        if len(p) >= _MIN_TOKEN_LEN and p not in _STOPLIST
    )


def _presence_ratio(needle_tokens: frozenset[str], hay_tokens: frozenset[str]) -> float:
    """Fraction of ``needle_tokens`` that appear in ``hay_tokens``."""
    if not needle_tokens:
        return 0.0
    hits = sum(1 for t in needle_tokens if t in hay_tokens)
    return hits / len(needle_tokens)


_VERSION_WORD_BOUNDARY_CACHE: dict[str, re.Pattern[str]] = {}


def _version_pattern(version: str) -> re.Pattern[str]:
    """Compile (and cache) a word-boundary pattern for a literal version.

    ``re.escape`` first, then wrap with ``\\b`` so ``"1.0"`` does NOT
    match the ``"10"`` inside ``"10.0"``. Word boundaries around the
    digit/dot sequence rule out the substring false-positive.
    """
    cached = _VERSION_WORD_BOUNDARY_CACHE.get(version)
    if cached is not None:
        return cached
    pattern = re.compile(rf"\b{re.escape(version)}\b")
    _VERSION_WORD_BOUNDARY_CACHE[version] = pattern
    return pattern


def _version_subscore(version: str | None, cve_text_lc: str) -> float:
    """Word-boundary substring match against lowercased CVE text."""
    if not version or not version.strip():
        return 0.0
    v = version.strip().lower()
    if _version_pattern(v).search(cve_text_lc):
        return 1.0
    parts = v.split(".")
    if len(parts) >= 2:
        major_minor = f"{parts[0]}.{parts[1]}"
        # Guard against degenerate "majors only" (e.g. "1." with no
        # minor) which would emit an empty boundary pattern.
        if parts[0] and parts[1] and _version_pattern(major_minor).search(cve_text_lc):
            return PARTIAL_VERSION_CREDIT
    return 0.0


# ---------------------------------------------------------------------------
# Structured-match floor (roadmap #3, applied by the emit layer in PR-D)
# ---------------------------------------------------------------------------
#
# Token-overlap scoring is the right primary signal for keyword-style
# matches but undershoots for findings produced by structured-key joins
# (exact CPE, exact PURL, GHSA package). For those, the join itself is
# high-precision evidence — the structural match is already strong
# corroboration, regardless of how many CVE-description tokens overlap
# the component identity.
#
# ``apply_strategy_floor`` is a thin composable post-processor: given
# the scorer's token confidence and the source-tagged strategy (from
# roadmap #6), it lifts the final number to at least the floor for
# that strategy. The scorer stays strategy-agnostic — this helper
# layers on top.
#
# Defaults (first-pass heuristic, fold into the same calibration
# follow-up as the weights and stoplist above):
#   * ``cpe_name`` / ``virtual_match_string`` → 0.5 — exact-CPE is
#     strong evidence, but the CPE dictionary has known false
#     positives (vendor/product collisions) so the floor is moderate.
#   * ``purl_direct`` / ``ghsa_alias`` → 0.6 — PURL-keyed matches are
#     exact package coordinates; GHSA's (ecosystem, package) join is
#     similarly anchored. Slightly above CPE.
#   * ``keyword_search`` → 0.0 — no structural anchor; the token
#     score IS the signal. Floor disabled.
#
# Unknown / unmapped strategies fall back to no floor (0.0). That
# keeps roadmap #6's "future strategy values can land without a
# migration" property — adding a new strategy is a one-line entry to
# this map, not a code freeze.

STRATEGY_FLOORS: Final[dict[str, float]] = {
    "cpe_name": 0.5,
    "virtual_match_string": 0.5,
    "purl_direct": 0.6,
    "ghsa_alias": 0.6,
    "keyword_search": 0.0,
}


def apply_strategy_floor(token_confidence: float, strategy: str | None) -> float:
    """Lift ``token_confidence`` to at least the floor for ``strategy``.

    Returns ``max(token_confidence, STRATEGY_FLOORS.get(strategy, 0.0))``,
    clamped to ``[0.0, 1.0]`` and rounded to 3 decimals. Pure function,
    no logging, no I/O. The caller writes the result onto the finding
    dict; persistence and exports follow PR-C's column-add pattern.
    """
    floor = STRATEGY_FLOORS.get(strategy or "", 0.0)
    raw = max(float(token_confidence), float(floor))
    return round(max(0.0, min(1.0, raw)), 3)


__all__ = [
    "ConfidenceResult",
    "NAME_WEIGHT",
    "VERSION_WEIGHT",
    "VENDOR_WEIGHT",
    "PARTIAL_VERSION_CREDIT",
    "STRATEGY_FLOORS",
    "apply_strategy_floor",
    "score_match",
]

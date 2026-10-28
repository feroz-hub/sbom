"""
NVD CVE version-range matching.

Pure-functional module. No I/O, no DB, no network — every input is
passed in and every output is returned. The only side effect is a
``logging.warning`` on the unparseable-version branch so operators
can find silent-drop bugs in logs; that matches the conservative-
keep contract (we never silently drop a finding we could not reason
about).

Why this exists
---------------
NVD's CVE 2.0 records carry a ``configurations.nodes.cpeMatch`` block
with four optional version bounds (``versionStartIncluding`` /
``versionStartExcluding`` / ``versionEndIncluding`` /
``versionEndExcluding``) plus an exact-version slot in the criteria
CPE 2.3 string itself. The NVD lookup path queries with a wildcard
version (``cpe:2.3:a:apache:log4j:*:*:...``) and therefore receives
every CVE for the product regardless of the component's actual
version. The live emit step then over-reports findings whose actual
version is outside the affected range. This module is the filter
that runs at the emit step (PR3 wires it in).

Ecosystem dispatch
------------------
Comparator selection is by PURL ecosystem string:

  * ``npm`` / ``golang`` / ``go`` / generic → semver-ish numeric-aware
  * ``pypi``                                → PEP 440 (``packaging.version``)
  * ``maven``                               → Maven order (``-SNAPSHOT`` < release)

Distro ecosystems (``deb`` / ``rpm`` / ``apk`` / ``conan``) are out of
scope for this PR (roadmap #5). They fall through to a
conservative-keep verdict (``ecosystem_unsupported``) so the caller
keeps the finding and tags it for follow-up.

Conservative defaults
---------------------
Unparseable versions, AND-node operators, and unsupported ecosystems
all return ``affected=True`` with a non-``"matched"`` reason. The
caller keeps the finding AND records why. The filter never silently
drops a finding it could not reason about.

Forward-compat
--------------
``MatchVerdict.matched_range`` is the human-readable label of the
range the verdict pertains to (``"≥ 2.0.0, < 2.17.0"`` /
``"= 1.2.3"`` / ``"*"``). Roadmap #6 surfaces this on the
finding-detail UI.
"""

from __future__ import annotations

import logging
import re
from collections.abc import Iterator, Mapping
from dataclasses import dataclass
from enum import Enum
from typing import Any, Final, Literal

from packaging.version import InvalidVersion, Version

from .cpe import trusted_cpe23_from_purl

log = logging.getLogger(__name__)


MatchReason = Literal[
    "matched",
    "out_of_range",
    "no_configurations",
    "version_unparseable",
    "ecosystem_unsupported",
    "and_node_ambiguous",
    "exact_version_mismatch",
]


@dataclass(frozen=True, slots=True)
class MatchVerdict:
    """Result of comparing a component version to a CVE's affected range.

    ``affected`` is the actionable bit: when ``False`` the caller drops
    the finding; when ``True`` the caller keeps it. ``reason`` carries
    the *why* — including the conservative-keep reasons
    (``version_unparseable``, ``and_node_ambiguous``,
    ``ecosystem_unsupported``, ``no_configurations``) that distinguish
    "this finding genuinely applies" from "we could not rule it out".
    ``matched_range`` is the human-readable bound string for UI display.
    """

    affected: bool
    reason: MatchReason
    matched_range: str | None = None


class ApplicabilityStatus(str, Enum):
    AFFECTED = "affected"
    NOT_AFFECTED = "not_affected"
    UNKNOWN = "unknown"


@dataclass(frozen=True, slots=True)
class ApplicabilityResult:
    status: ApplicabilityStatus
    reason: str
    matched_criteria: str | None = None
    matched_range: str | dict[str, str | None] | None = None
    fixed_version: str | None = None


class TriState(str, Enum):
    TRUE = "true"
    FALSE = "false"
    UNKNOWN = "unknown"


@dataclass(frozen=True, slots=True)
class VersionRange:
    """Bounds from one ``cpeMatch`` entry.

    ``criteria_version`` is the literal version slot from the CPE 2.3
    criteria string itself (e.g. ``"2.14.0"`` from
    ``cpe:2.3:a:apache:log4j:2.14.0:*:...``), or ``None`` when that
    slot is a wildcard (``*`` / ``-`` / ``ANY``).
    """

    start_including: str | None
    start_excluding: str | None
    end_including: str | None
    end_excluding: str | None
    criteria_version: str | None


# ---------------------------------------------------------------------------
# Ecosystem routing
# ---------------------------------------------------------------------------

_SEMVER_ECOSYSTEMS: Final[frozenset[str]] = frozenset({"npm", "go", "golang", "generic"})
_PEP440_ECOSYSTEMS: Final[frozenset[str]] = frozenset({"pypi"})
_MAVEN_ECOSYSTEMS: Final[frozenset[str]] = frozenset({"maven"})

# Distro/Conan ecosystems — roadmap #5. When ``distro_cpe_enabled`` is
# OFF the comparator returns a conservative-keep
# (``ecosystem_unsupported``) verdict so the caller never silently
# drops. When ON, the component version is first normalised to its
# UPSTREAM form via ``distro_cpe.normalize_upstream_version`` (strip
# epoch + distro revision/release/-rN) and then compared through the
# default semver-ish path — the NVD bounds are already upstream
# versions because PR-B's resolver emits ``cpe:2.3:a:<upstream>:...``.
#
# **Backport unawareness (load-bearing limitation)** — the same caveat
# from PR-A applies once this flag is flipped on: a distro that
# patched a CVE WITHOUT bumping the upstream version
# (``3.0.2-1+deb11u5`` → ``3.0.2``) will look affected here even
# though the binary has the fix. Closing the gap needs distro
# security feeds (DSA/RHSA/USN/ASA) that map ``(cve_id, distro,
# package, fixed_revision)``; that's a separate feature. Downstream
# UI / reports should mark distro findings as "may be backported —
# verify against distro advisory" until those feeds land.
_UNSUPPORTED_ECOSYSTEMS: Final[frozenset[str]] = frozenset({"deb", "rpm", "apk", "conan", "alpine", "debian", "redhat"})

# Subset of ``_UNSUPPORTED_ECOSYSTEMS`` that PR-C's normalize-and-compare
# branch can handle when the flag is on. Conan is included even though
# its version normalisation is a passthrough — the routing still
# bypasses the ``ecosystem_unsupported`` short-circuit and lets Conan
# versions reach ``_cmp_semver`` cleanly (Conan versions are already
# upstream-shaped per PR-A).
_DISTRO_NORMALIZE_ECOSYSTEMS: Final[frozenset[str]] = _UNSUPPORTED_ECOSYSTEMS

_INCOMPARABLE: Final[object] = object()


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------


def parse_range(cpe_match: Mapping[str, Any]) -> VersionRange | None:
    """Extract bounds from one ``configurations.nodes.cpeMatch`` entry.

    Returns ``None`` only when the entry has no ``criteria`` field — a
    malformed match block. Returns a ``VersionRange`` with all bounds
    ``None`` for an exact-pinned criteria (no range bounds, version
    slot is a literal).
    """
    criteria = cpe_match.get("criteria")
    if not isinstance(criteria, str) or not criteria:
        return None
    return VersionRange(
        start_including=_str_or_none(cpe_match.get("versionStartIncluding")),
        start_excluding=_str_or_none(cpe_match.get("versionStartExcluding")),
        end_including=_str_or_none(cpe_match.get("versionEndIncluding")),
        end_excluding=_str_or_none(cpe_match.get("versionEndExcluding")),
        criteria_version=_cpe_version_slot(criteria),
    )


def version_in_range(
    version: str | None,
    ecosystem: str | None,
    bounds: VersionRange,
    *,
    distro_cpe_enabled: bool = False,
) -> MatchVerdict:
    """Decide whether ``version`` falls within ``bounds`` under ``ecosystem``'s ordering.

    Conservative on every failure mode: ``affected=True`` with a
    distinctive ``reason`` so the caller can keep the finding and
    record why.

    Roadmap #5 PR-C: when ``distro_cpe_enabled`` is True AND the
    ecosystem is one of ``deb``/``rpm``/``apk``/``conan`` (or aliases
    ``debian``/``redhat``/``alpine``), the component version is first
    normalised to its UPSTREAM form via
    ``distro_cpe.normalize_upstream_version`` and then compared
    through the default semver-ish path. The NVD bounds are already
    upstream (PR-B's resolver emits upstream CPEs) so no normalisation
    on the bound side. Flag OFF → distros short-circuit as
    ``ecosystem_unsupported`` (byte-identical to today).
    """
    if not version:
        return MatchVerdict(affected=True, reason="version_unparseable", matched_range=_fmt_range(bounds))

    eco = _normalize_ecosystem(ecosystem)
    if eco in _UNSUPPORTED_ECOSYSTEMS:
        # Roadmap #5 PR-C — distro/Conan get a normalize-and-compare
        # path when the flag is on; otherwise short-circuit as
        # ``ecosystem_unsupported`` (legacy behaviour).
        if distro_cpe_enabled and eco in _DISTRO_NORMALIZE_ECOSYSTEMS:
            from .distro_cpe import normalize_upstream_version

            normalised = normalize_upstream_version(version, eco)
            if not normalised:
                # No usable upstream version after stripping → treat
                # as unparseable rather than mis-comparing an empty
                # string. The caller still keeps the finding.
                return MatchVerdict(
                    affected=True,
                    reason="version_unparseable",
                    matched_range=_fmt_range(bounds),
                )
            version = normalised
            # Fall through to comparison below. ``_compare`` already
            # routes unmapped ecosystems (deb/rpm/apk/conan) into
            # ``_cmp_semver`` so the normalised upstream version
            # compares cleanly against the NVD upstream bounds.
        else:
            return MatchVerdict(
                affected=True,
                reason="ecosystem_unsupported",
                matched_range=_fmt_range(bounds),
            )

    has_bounds = any(
        b is not None
        for b in (
            bounds.start_including,
            bounds.start_excluding,
            bounds.end_including,
            bounds.end_excluding,
        )
    )

    # Exact-pinned CPE: no range bounds, the criteria itself carries
    # the affected version (or a wildcard meaning "any version").
    if not has_bounds:
        if bounds.criteria_version is None:
            return MatchVerdict(affected=True, reason="matched", matched_range="*")
        cmp_eq = _compare(version, bounds.criteria_version, eco)
        if cmp_eq is _INCOMPARABLE:
            return MatchVerdict(
                affected=True,
                reason="version_unparseable",
                matched_range=f"= {bounds.criteria_version}",
            )
        if cmp_eq == 0:
            return MatchVerdict(
                affected=True,
                reason="matched",
                matched_range=f"= {bounds.criteria_version}",
            )
        return MatchVerdict(
            affected=False,
            reason="exact_version_mismatch",
            matched_range=f"= {bounds.criteria_version}",
        )

    label = _fmt_range(bounds)
    for bound_value, op in (
        (bounds.start_including, "ge"),
        (bounds.start_excluding, "gt"),
        (bounds.end_including, "le"),
        (bounds.end_excluding, "lt"),
    ):
        if bound_value is None:
            continue
        c = _compare(version, bound_value, eco)
        if c is _INCOMPARABLE:
            return MatchVerdict(
                affected=True,
                reason="version_unparseable",
                matched_range=label,
            )
        if op == "ge" and c < 0:
            return MatchVerdict(affected=False, reason="out_of_range", matched_range=label)
        if op == "gt" and c <= 0:
            return MatchVerdict(affected=False, reason="out_of_range", matched_range=label)
        if op == "le" and c > 0:
            return MatchVerdict(affected=False, reason="out_of_range", matched_range=label)
        if op == "lt" and c >= 0:
            return MatchVerdict(affected=False, reason="out_of_range", matched_range=label)

    return MatchVerdict(affected=True, reason="matched", matched_range=label)


def compare_versions(ecosystem: str | None, left: str, right: str) -> int:
    eco = _normalize_ecosystem(ecosystem)
    cmp = _compare(left, right, eco)
    if cmp is _INCOMPARABLE:
        raise InvalidVersion(f"Cannot compare {left!r} to {right!r} for ecosystem {ecosystem!r}")
    return int(cmp)


def evaluate_version_bounds(
    installed_version: str | None,
    ecosystem: str | None,
    match: Mapping[str, Any],
) -> ApplicabilityResult:
    bounds = parse_range(match)
    criteria = str(match.get("criteria") or "") or None
    if bounds is None:
        return ApplicabilityResult(ApplicabilityStatus.UNKNOWN, "cpe_criteria_missing", criteria)
    if not installed_version:
        return ApplicabilityResult(
            ApplicabilityStatus.UNKNOWN,
            "installed_version_missing",
            criteria,
            _range_dict(bounds),
        )
    eco = _normalize_ecosystem(ecosystem)
    if eco in _UNSUPPORTED_ECOSYSTEMS:
        return ApplicabilityResult(
            ApplicabilityStatus.UNKNOWN,
            "ecosystem_unsupported",
            criteria,
            _range_dict(bounds),
        )

    has_bounds = any(
        value is not None
        for value in (
            bounds.start_including,
            bounds.start_excluding,
            bounds.end_including,
            bounds.end_excluding,
        )
    )
    if not has_bounds:
        if bounds.criteria_version is None:
            return ApplicabilityResult(
                ApplicabilityStatus.UNKNOWN,
                "wildcard_version_without_range",
                criteria,
                _range_dict(bounds),
            )
        try:
            cmp = compare_versions(eco, installed_version, bounds.criteria_version)
        except InvalidVersion:
            log.warning(
                "version_range: rejecting candidate — unparseable version component=%r range=%s cpe=%r ecosystem=%r",
                installed_version,
                _fmt_range(bounds),
                criteria,
                ecosystem,
            )
            return ApplicabilityResult(
                ApplicabilityStatus.UNKNOWN,
                "installed_or_bound_version_invalid",
                criteria,
                _range_dict(bounds),
            )
        if cmp == 0:
            return ApplicabilityResult(
                ApplicabilityStatus.AFFECTED,
                "exact_version_match",
                criteria,
                _range_dict(bounds),
            )
        return ApplicabilityResult(
            ApplicabilityStatus.NOT_AFFECTED,
            "exact_version_mismatch",
            criteria,
            _range_dict(bounds),
        )

    checks = (
        (bounds.start_including, "version_start_including", lambda c: c < 0),
        (bounds.start_excluding, "version_start_excluding", lambda c: c <= 0),
        (bounds.end_including, "version_end_including", lambda c: c > 0),
        (bounds.end_excluding, "version_end_excluding", lambda c: c >= 0),
    )
    for bound, reason, outside in checks:
        if bound is None:
            continue
        try:
            cmp = compare_versions(eco, installed_version, bound)
        except InvalidVersion:
            log.warning(
                "version_range: rejecting candidate — unparseable version component=%r range=%s cpe=%r ecosystem=%r",
                installed_version,
                _fmt_range(bounds),
                criteria,
                ecosystem,
            )
            return ApplicabilityResult(
                ApplicabilityStatus.UNKNOWN,
                "installed_or_bound_version_invalid",
                criteria,
                _range_dict(bounds),
            )
        if outside(cmp):
            return ApplicabilityResult(
                ApplicabilityStatus.NOT_AFFECTED,
                reason,
                criteria,
                _range_dict(bounds),
            )

    return ApplicabilityResult(
        ApplicabilityStatus.AFFECTED,
        "version_in_range",
        criteria,
        _range_dict(bounds),
    )


def evaluate_nvd_cpe_match(
    component: Mapping[str, Any],
    cpe_match: Mapping[str, Any],
    *,
    target_cpe: str | None = None,
) -> ApplicabilityResult:
    criteria = str(cpe_match.get("criteria") or "")
    parsed = _parse_cpe23(criteria)
    if parsed is None:
        return ApplicabilityResult(ApplicabilityStatus.UNKNOWN, "cpe_criteria_invalid", criteria)
    if cpe_match.get("vulnerable") is not True:
        if parsed["part"] != "a":
            return ApplicabilityResult(ApplicabilityStatus.UNKNOWN, "environmental_cpe_unsupported", criteria)
        return ApplicabilityResult(ApplicabilityStatus.NOT_AFFECTED, "cpe_match_not_vulnerable", criteria)
    if parsed["part"] != "a":
        return ApplicabilityResult(ApplicabilityStatus.UNKNOWN, "environmental_cpe_unsupported", criteria)

    identity = _component_identity_matches(component, criteria, target_cpe=target_cpe)
    if identity.status is not ApplicabilityStatus.AFFECTED:
        return identity

    version_result = evaluate_version_bounds(
        _component_value(component, "version", "component_version"),
        _component_value(component, "ecosystem", "normalized_ecosystem"),
        cpe_match,
    )
    if version_result.status is ApplicabilityStatus.AFFECTED:
        return ApplicabilityResult(
            ApplicabilityStatus.AFFECTED,
            version_result.reason,
            criteria,
            version_result.matched_range,
        )
    return version_result


def evaluate_nvd_configurations(
    cve_json: Mapping[str, Any],
    component: Mapping[str, Any],
    *,
    target_cpe: str | None = None,
) -> ApplicabilityResult:
    configurations = cve_json.get("configurations")
    if not configurations:
        return ApplicabilityResult(ApplicabilityStatus.UNKNOWN, "no_configurations")

    states: list[tuple[TriState, ApplicabilityResult]] = []
    for cfg in configurations:
        if not isinstance(cfg, Mapping):
            continue
        node_states = [
            _evaluate_node(node, component, target_cpe=target_cpe)
            for node in (cfg.get("nodes") or [])
            if isinstance(node, Mapping)
        ]
        if not node_states:
            continue
        operator = str(cfg.get("operator") or "OR").upper()
        states.append(_combine_and(node_states) if operator == "AND" else _combine_or(node_states))

    if not states:
        return ApplicabilityResult(ApplicabilityStatus.UNKNOWN, "no_applicable_configurations")
    state, result = _combine_or(states)
    if state is TriState.TRUE:
        return result
    if state is TriState.FALSE:
        return ApplicabilityResult(ApplicabilityStatus.NOT_AFFECTED, result.reason, result.matched_criteria, result.matched_range)
    return ApplicabilityResult(ApplicabilityStatus.UNKNOWN, result.reason, result.matched_criteria, result.matched_range)


def applicability_to_match_verdict(result: ApplicabilityResult) -> MatchVerdict:
    if result.status is ApplicabilityStatus.AFFECTED:
        return MatchVerdict(True, "matched", _format_result_range(result))
    if result.status is ApplicabilityStatus.NOT_AFFECTED:
        reason = "out_of_range" if result.reason.startswith("version_") else "exact_version_mismatch"
        if result.reason in {"cpe_product_mismatch", "cpe_match_not_vulnerable"}:
            reason = "no_configurations"
        elif result.reason == "exact_version_mismatch":
            reason = "exact_version_mismatch"
        return MatchVerdict(False, reason, _format_result_range(result))
    if result.reason.startswith("environmental_"):
        reason = "and_node_ambiguous"
    elif "version" in result.reason:
        reason = "version_unparseable"
    else:
        reason = "no_configurations"
    return MatchVerdict(False, reason, _format_result_range(result))


def cve_affects_component(
    cve_json: Mapping[str, Any],
    component_version: str | None,
    ecosystem: str | None,
    *,
    target_cpe: str | None = None,
    distro_cpe_enabled: bool = False,
) -> MatchVerdict:
    """Walk a CVE's configurations and decide whether the component is affected.

    ``cve_json`` is the inner CVE document (the value under
    ``vulnerabilities[i].cve`` in an NVD 2.0 response), not the full
    response.

    ``target_cpe`` narrows ``cpeMatch`` entries to those whose
    ``vendor:product`` stem equals the target's stem. When ``None``,
    every ``cpeMatch`` in the CVE is considered. The narrow path is
    important when a single CVE covers multiple products (e.g. an
    ``apache:struts`` AND ``apache:tomcat`` CVE) and the caller asks
    about only one.

    Aggregation rules across applicable cpeMatch verdicts:

      1. Any ``matched`` → return matched (first wins).
      2. No ``matched`` but any conservative-keep (``and_node_ambiguous``,
         ``version_unparseable``, ``ecosystem_unsupported``) → return
         that conservative-keep verdict.
      3. All applicable verdicts are ``out_of_range`` /
         ``exact_version_mismatch`` → return the first such verdict
         with ``affected=False``.
      4. Nothing applicable (CVE has configurations but none target our
         CPE stem, or has no configurations at all) → conservative
         keep with reason ``no_configurations``.
    """
    del distro_cpe_enabled
    component = {"version": component_version, "ecosystem": ecosystem}
    if target_cpe:
        component["cpe"] = target_cpe
        component["cpe_source"] = "manual_verified"
    return applicability_to_match_verdict(
        evaluate_nvd_configurations(cve_json, component, target_cpe=target_cpe)
    )


# ---------------------------------------------------------------------------
# Node walker
# ---------------------------------------------------------------------------


def _walk_node(
    node: Mapping[str, Any],
    *,
    component_version: str | None,
    ecosystem: str | None,
    target_stem: str | None,
    distro_cpe_enabled: bool = False,
) -> Iterator[MatchVerdict]:
    """Yield verdicts for every applicable cpeMatch under ``node``.

    AND nodes (``operator == "AND"``) typically express "vulnerable on
    application X running under platform Y". A single component cannot
    satisfy both halves, so a single-criterion comparator cannot
    correctly decide. Yield a conservative-keep verdict and stop
    walking the AND subtree — partial evaluation would produce a
    misleading drop.
    """
    operator = str(node.get("operator", "OR")).upper()
    if operator == "AND" and (node.get("cpeMatch") or node.get("children")):
        yield MatchVerdict(
            affected=True,
            reason="and_node_ambiguous",
            matched_range=None,
        )
        return

    for match in node.get("cpeMatch") or []:
        if not isinstance(match, dict):
            continue
        if not match.get("vulnerable", True):
            continue
        bounds = parse_range(match)
        if bounds is None:
            continue
        criteria = str(match.get("criteria", ""))
        if target_stem is not None and _cpe_stem(criteria) != target_stem:
            continue
        verdict = version_in_range(
            component_version,
            ecosystem,
            bounds,
            distro_cpe_enabled=distro_cpe_enabled,
        )
        if verdict.reason == "version_unparseable":
            log.warning(
                "version_range: keeping finding — unparseable version component=%r range=%s cpe=%r ecosystem=%r",
                component_version,
                verdict.matched_range,
                criteria,
                ecosystem,
            )
        yield verdict

    for child in node.get("children") or []:
        if isinstance(child, dict):
            yield from _walk_node(
                child,
                component_version=component_version,
                ecosystem=ecosystem,
                target_stem=target_stem,
                distro_cpe_enabled=distro_cpe_enabled,
            )


# ---------------------------------------------------------------------------
# Ecosystem comparators
# ---------------------------------------------------------------------------


def _normalize_ecosystem(eco: str | None) -> str:
    if not eco:
        return "generic"
    s = eco.strip().lower()
    if s in {"pip", "python"}:
        return "pypi"
    if s in {"java"}:
        return "maven"
    if s in {"node", "nodejs"}:
        return "npm"
    return s


def _compare(a: str, b: str, ecosystem: str) -> int | object:
    """Return -1/0/1 if ``a`` sorts before/equal/after ``b`` under
    ``ecosystem``'s ordering, or ``_INCOMPARABLE`` if either side
    cannot be parsed.
    """
    if ecosystem in _PEP440_ECOSYSTEMS:
        return _cmp_pep440(a, b)
    if ecosystem in _MAVEN_ECOSYSTEMS:
        return _cmp_maven(a, b)
    if ecosystem in _SEMVER_ECOSYSTEMS:
        return _cmp_semver(a, b)
    # TODO(roadmap #5): per-ecosystem distro comparators (deb / rpm /
    # apk / conan). Distro versions are intercepted before this point
    # by the _UNSUPPORTED_ECOSYSTEMS frozenset, but any unmapped
    # ecosystem name still lands here. Falling through to semver-ish
    # numeric-aware ordering gives a non-trivial answer often enough
    # to be useful; the caller can override with their own dispatch.
    return _cmp_semver(a, b)


def _cmp_pep440(a: str, b: str) -> int | object:
    try:
        va, vb = Version(a), Version(b)
    except (InvalidVersion, TypeError):
        return _INCOMPARABLE
    if va < vb:
        return -1
    if va > vb:
        return 1
    return 0


# Maven's ``-SNAPSHOT`` qualifier sorts BEFORE the corresponding
# release: ``1.0-SNAPSHOT < 1.0``. A full Maven comparator is
# famously baroque (alpha / beta / milestone / rc / sp ordering,
# dot-vs-dash separators, the empty-qualifier release pseudo-rank);
# roadmap #5 is the place to graduate this to a spec-true
# implementation. For now we handle SNAPSHOT (the only Maven
# qualifier the brief calls out) and fall through to semver-ish
# numeric-aware ordering for everything else.
_MAVEN_SNAPSHOT_RE = re.compile(r"[-.]?snapshot$", re.IGNORECASE)


def _cmp_maven(a: str, b: str) -> int | object:
    a_base, a_snap = _strip_snapshot(a)
    b_base, b_snap = _strip_snapshot(b)
    base = _cmp_semver(a_base, b_base)
    if base is _INCOMPARABLE:
        return _INCOMPARABLE
    if base != 0:
        return base
    if a_snap and not b_snap:
        return -1
    if b_snap and not a_snap:
        return 1
    return 0


def _strip_snapshot(s: str) -> tuple[str, bool]:
    m = _MAVEN_SNAPSHOT_RE.search(s)
    if not m:
        return s, False
    return s[: m.start()], True


_SEMVER_NUM_RE = re.compile(r"^\d+$")


def _cmp_semver(a: str, b: str) -> int | object:
    """Numeric-aware semver-ish comparison.

    Handles: ``1.10.0 > 1.9.0`` (numeric not lexical), leading ``v``
    prefix (``v1.0.0`` == ``1.0.0``), build metadata after ``+``
    ignored, pre-release after ``-`` sorts BEFORE the release of the
    same main version (semver §11). Mixed alphanumeric segments fall
    back to lexicographic, which mirrors the existing behaviour in
    ``app/nvd_mirror/adapters/cve_repository.py``.
    """
    try:
        a_main, a_pre = _semver_split(a)
        b_main, b_pre = _semver_split(b)
    except ValueError:
        return _INCOMPARABLE

    n = max(len(a_main), len(b_main))
    a_padded = a_main + ((0,) * (n - len(a_main)))
    b_padded = b_main + ((0,) * (n - len(b_main)))
    for x, y in zip(a_padded, b_padded, strict=True):
        # ``int`` and ``str`` can't be compared directly in Py3 — coerce
        # to a sortable key. Numerics rank below strings of the same
        # main-segment slot, which matches semver §11 ordering.
        cmp = _cmp_keys(x, y)
        if cmp != 0:
            return cmp

    if not a_pre and b_pre:
        return 1
    if a_pre and not b_pre:
        return -1
    if not a_pre and not b_pre:
        return 0
    return _cmp_segments(a_pre, b_pre)


def _semver_split(s: str) -> tuple[tuple[int | str, ...], tuple[int | str, ...]]:
    if not s:
        raise ValueError("empty version")
    stripped = s.strip()
    if stripped.startswith(("v", "V")) and len(stripped) > 1 and stripped[1].isdigit():
        stripped = stripped[1:]
    if "+" in stripped:
        stripped = stripped.split("+", 1)[0]
    if not stripped:
        raise ValueError("empty after strip")
    if "-" in stripped:
        main_part, pre_part = stripped.split("-", 1)
    else:
        main_part, pre_part = stripped, ""
    main = tuple(_segment(seg) for seg in main_part.split("."))
    pre = tuple(_segment(seg) for seg in pre_part.split(".")) if pre_part else ()
    return main, pre


def _segment(seg: str) -> int | str:
    if _SEMVER_NUM_RE.match(seg):
        return int(seg)
    return seg


def _cmp_keys(x: int | str, y: int | str) -> int:
    x_is_num = isinstance(x, int)
    y_is_num = isinstance(y, int)
    if x_is_num and y_is_num:
        if x < y:
            return -1
        if x > y:
            return 1
        return 0
    if x_is_num and not y_is_num:
        return -1
    if y_is_num and not x_is_num:
        return 1
    # both strings
    if x < y:
        return -1
    if x > y:
        return 1
    return 0


def _cmp_segments(a: tuple[int | str, ...], b: tuple[int | str, ...]) -> int:
    n = max(len(a), len(b))
    for i in range(n):
        if i >= len(a):
            return -1  # shorter pre-release is smaller (semver §11.4)
        if i >= len(b):
            return 1
        cmp = _cmp_keys(a[i], b[i])
        if cmp != 0:
            return cmp
    return 0


# ---------------------------------------------------------------------------
# CPE 2.3 helpers and formatting
# ---------------------------------------------------------------------------


def _cpe_version_slot(cpe23: str) -> str | None:
    """Literal version slot from a CPE 2.3 string, or ``None`` for a wildcard."""
    parts = cpe23.split(":")
    if len(parts) < 6 or parts[0] != "cpe" or parts[1] != "2.3":
        return None
    ver = parts[5]
    if ver in {"*", "-", "ANY", ""}:
        return None
    return ver


def _cpe_stem(cpe23: str | None) -> str:
    """Lowercased ``vendor:product`` from a CPE 2.3 string. Empty on parse failure."""
    if not cpe23:
        return ""
    parts = cpe23.split(":")
    if len(parts) < 6 or parts[0] != "cpe" or parts[1] != "2.3":
        return ""
    vendor, product = parts[3], parts[4]
    if not vendor or not product:
        return ""
    return f"{vendor.lower()}:{product.lower()}"


def _parse_cpe23(cpe23: str | None) -> dict[str, str] | None:
    if not cpe23:
        return None
    parts = cpe23.split(":")
    if len(parts) != 13 or parts[0] != "cpe" or parts[1] != "2.3":
        return None
    return {
        "part": parts[2],
        "vendor": parts[3],
        "product": parts[4],
        "version": parts[5],
    }


def _component_value(component: Mapping[str, Any], *keys: str) -> str | None:
    for key in keys:
        value = component.get(key)
        if isinstance(value, str) and value.strip():
            return value.strip()
    return None


def _normalize_cpe_token(value: str | None) -> str:
    return re.sub(r"[^a-z0-9]+", "_", (value or "").strip().lower()).strip("_")


def _trusted_component_stems(component: Mapping[str, Any], target_cpe: str | None = None) -> set[str]:
    stems: set[str] = set()
    if target_cpe and _parse_cpe23(target_cpe):
        stems.add(_cpe_stem(target_cpe))

    cpe = _component_value(component, "cpe", "primary_cpe")
    cpe_source = (_component_value(component, "cpe_source") or "").lower()
    if cpe and cpe_source in {"sbom_provided", "official_nvd_cpe", "manual_verified", "trusted_mapping"}:
        stem = _cpe_stem(cpe)
        if stem:
            stems.add(stem)

    purl = _component_value(component, "purl", "normalized_purl", "original_purl")
    version = _component_value(component, "version", "component_version", "normalized_version")
    if purl:
        mapped = trusted_cpe23_from_purl(purl, version_override=version)
        if mapped is not None:
            stems.add(_cpe_stem(mapped.cpe))
    return {stem for stem in stems if stem}


def _component_identity_matches(
    component: Mapping[str, Any],
    criteria: str,
    *,
    target_cpe: str | None = None,
) -> ApplicabilityResult:
    parsed = _parse_cpe23(criteria)
    if parsed is None:
        return ApplicabilityResult(ApplicabilityStatus.UNKNOWN, "cpe_criteria_invalid", criteria)

    allowed = _trusted_component_stems(component, target_cpe=target_cpe)
    if not allowed:
        return ApplicabilityResult(ApplicabilityStatus.UNKNOWN, "component_cpe_identity_unknown", criteria)

    criteria_stem = _cpe_stem(criteria)
    if criteria_stem in allowed:
        return ApplicabilityResult(ApplicabilityStatus.AFFECTED, "cpe_product_matched", criteria)
    return ApplicabilityResult(ApplicabilityStatus.NOT_AFFECTED, "cpe_product_mismatch", criteria)


def _evaluate_node(
    node: Mapping[str, Any],
    component: Mapping[str, Any],
    *,
    target_cpe: str | None,
) -> tuple[TriState, ApplicabilityResult]:
    child_results: list[tuple[TriState, ApplicabilityResult]] = []
    for match in node.get("cpeMatch") or []:
        if not isinstance(match, Mapping):
            continue
        result = evaluate_nvd_cpe_match(component, match, target_cpe=target_cpe)
        child_results.append((_state_from_result(result), result))
    for child in node.get("children") or []:
        if isinstance(child, Mapping):
            child_results.append(_evaluate_node(child, component, target_cpe=target_cpe))

    if not child_results:
        combined = (
            TriState.UNKNOWN,
            ApplicabilityResult(ApplicabilityStatus.UNKNOWN, "empty_configuration_node"),
        )
    else:
        operator = str(node.get("operator") or "OR").upper()
        combined = _combine_and(child_results) if operator == "AND" else _combine_or(child_results)

    if node.get("negate") is True:
        state, result = combined
        if state is TriState.TRUE:
            return (
                TriState.FALSE,
                ApplicabilityResult(
                    ApplicabilityStatus.NOT_AFFECTED,
                    f"negated_{result.reason}",
                    result.matched_criteria,
                    result.matched_range,
                ),
            )
        if state is TriState.FALSE:
            return (
                TriState.TRUE,
                ApplicabilityResult(
                    ApplicabilityStatus.AFFECTED,
                    f"negated_{result.reason}",
                    result.matched_criteria,
                    result.matched_range,
                ),
            )
    return combined


def _state_from_result(result: ApplicabilityResult) -> TriState:
    if result.status is ApplicabilityStatus.AFFECTED:
        return TriState.TRUE
    if result.status is ApplicabilityStatus.NOT_AFFECTED:
        return TriState.FALSE
    return TriState.UNKNOWN


def _combine_or(items: list[tuple[TriState, ApplicabilityResult]]) -> tuple[TriState, ApplicabilityResult]:
    unknown: ApplicabilityResult | None = None
    first_false: ApplicabilityResult | None = None
    for state, result in items:
        if state is TriState.TRUE:
            return state, result
        if state is TriState.UNKNOWN and unknown is None:
            unknown = result
        if state is TriState.FALSE and first_false is None:
            first_false = result
    if unknown is not None:
        return TriState.UNKNOWN, unknown
    return TriState.FALSE, first_false or ApplicabilityResult(ApplicabilityStatus.NOT_AFFECTED, "no_or_match")


def _combine_and(items: list[tuple[TriState, ApplicabilityResult]]) -> tuple[TriState, ApplicabilityResult]:
    unknown: ApplicabilityResult | None = None
    first_true: ApplicabilityResult | None = None
    for state, result in items:
        if state is TriState.FALSE:
            return state, result
        if state is TriState.UNKNOWN and unknown is None:
            unknown = result
        if state is TriState.TRUE and first_true is None:
            first_true = result
    if unknown is not None:
        return TriState.UNKNOWN, unknown
    return TriState.TRUE, first_true or ApplicabilityResult(ApplicabilityStatus.AFFECTED, "and_matched")


def _range_dict(bounds: VersionRange) -> dict[str, str | None]:
    return {
        "versionStartIncluding": bounds.start_including,
        "versionStartExcluding": bounds.start_excluding,
        "versionEndIncluding": bounds.end_including,
        "versionEndExcluding": bounds.end_excluding,
        "criteriaVersion": bounds.criteria_version,
        "label": _fmt_range(bounds),
    }


def _format_result_range(result: ApplicabilityResult) -> str | None:
    if not result.matched_range:
        return None
    label = result.matched_range.get("label")
    return str(label) if label else None


def _str_or_none(v: Any) -> str | None:
    if v is None:
        return None
    s = str(v).strip()
    return s or None


def _fmt_range(bounds: VersionRange) -> str:
    """Human-readable range label for ``MatchVerdict.matched_range``."""
    if all(
        b is None
        for b in (
            bounds.start_including,
            bounds.start_excluding,
            bounds.end_including,
            bounds.end_excluding,
        )
    ):
        if bounds.criteria_version is None:
            return "*"
        return f"= {bounds.criteria_version}"
    parts: list[str] = []
    if bounds.start_including is not None:
        parts.append(f">= {bounds.start_including}")
    if bounds.start_excluding is not None:
        parts.append(f"> {bounds.start_excluding}")
    if bounds.end_including is not None:
        parts.append(f"<= {bounds.end_including}")
    if bounds.end_excluding is not None:
        parts.append(f"< {bounds.end_excluding}")
    return ", ".join(parts)


__all__ = [
    "ApplicabilityResult",
    "ApplicabilityStatus",
    "MatchReason",
    "MatchVerdict",
    "TriState",
    "VersionRange",
    "compare_versions",
    "evaluate_nvd_configurations",
    "evaluate_nvd_cpe_match",
    "evaluate_version_bounds",
    "parse_range",
    "version_in_range",
    "cve_affects_component",
]

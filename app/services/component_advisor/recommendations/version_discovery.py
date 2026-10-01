"""Same-family safer-version discovery (FR-SCA-013, US-SCA-09).

Pure logic. Before any different component is considered (Step 6), every
other version of the *same component family* is evaluated. Candidate
versions come from evidence only:

* ``TENANT_OBSERVED`` — the version is present in the tenant's active SBOMs,
  so its current posture (risk, lifecycle, license, freshness) is known.
* ``LIFECYCLE_LATEST`` / ``LIFECYCLE_LATEST_SUPPORTED`` /
  ``LIFECYCLE_RECOMMENDED`` — versions named by lifecycle enrichment on the
  source occurrences.
* ``FINDING_FIXED_VERSION`` — fix versions declared by the source version's
  actionable findings.

Each candidate is evaluated on the FR-SCA-013 dimensions that have evidence
(current posture, lifecycle, license change, version direction / major
change, fix coverage, freshness, adoption). Dimensions without evidence yet
(history, release cadence, platform, transitive dependencies) are reported
as explicit limitations, never assumed. Nothing is upgraded — the output is
a list for human review.
"""

from __future__ import annotations

import re
from collections.abc import Iterable, Mapping, Sequence
from dataclasses import dataclass, field
from typing import Any

from ....sources.version_range import InvalidVersion, compare_versions
from ..classification import RiskClassification
from ..filters import RISK_SORT_RANK
from ..lifecycle_mapping import END_OF_LIFE_BUCKETS, LifecycleBucket
from .workflow import CandidateKind, CandidateSourceType

HINT_SOURCES = ("LIFECYCLE_RECOMMENDED", "LIFECYCLE_LATEST_SUPPORTED", "LIFECYCLE_LATEST")
#: Limitations every same-family candidate carries until Steps 6–7 add evidence.
ALWAYS_LIMITATIONS = (
    ("MIGRATION_REGRESSION_TESTING_REQUIRED", "Any version change needs regression testing before adoption"),
    ("TRANSITIVE_DEPENDENCY_DIFFERENCES", "Transitive dependencies of the candidate were not compared"),
    ("HISTORY_NOT_EVALUATED", "Vulnerability history over the observation window is evaluated in a later step"),
    ("RELEASE_CADENCE_UNKNOWN", "Release recency and cadence evidence is not available"),
    ("PLATFORM_EVIDENCE_INCOMPLETE", "Product / platform / runtime constraints were not evaluated"),
)
_SUPPORTIVE_LIFECYCLE = frozenset({LifecycleBucket.SUPPORTED, LifecycleBucket.MAINTENANCE})


@dataclass
class CandidateEvaluation:
    kind: CandidateKind
    source_type: CandidateSourceType
    canonical_key: str | None
    name: str
    version: str
    purl: str | None
    ecosystem: str | None
    evidence_sources: list[str]
    reasons: list[dict[str, Any]] = field(default_factory=list)
    limitations: list[dict[str, Any]] = field(default_factory=list)
    evaluation: dict[str, Any] = field(default_factory=dict)
    rank: int = 0

    def to_dict(self) -> dict[str, Any]:
        return {
            "candidate_kind": self.kind.value,
            "source_type": self.source_type.value,
            "canonical_key": self.canonical_key,
            "name": self.name,
            "version": self.version,
            "purl": self.purl,
            "ecosystem": self.ecosystem,
            "rank": self.rank,
            "evidence_sources": list(self.evidence_sources),
            "reasons": [dict(r) for r in self.reasons],
            "limitations": [dict(item) for item in self.limitations],
            "evaluation": dict(self.evaluation),
        }


@dataclass
class DiscoveryResult:
    candidates: list[CandidateEvaluation]
    excluded: list[dict[str, Any]]

    def summary(self) -> dict[str, Any]:
        return {
            "status": "CANDIDATES_FOUND" if self.candidates else "NO_CANDIDATES_FOUND",
            "same_family_candidates": len(self.candidates),
            "alternative_candidates": 0,
            "alternatives_status": "NOT_EVALUATED",
            "excluded": [dict(item) for item in self.excluded],
        }


def _major(version: str | None) -> int | None:
    match = re.match(r"^[vV]?(\d+)", str(version or "").strip())
    return int(match.group(1)) if match else None


def _direction(ecosystem: str | None, source: str | None, candidate: str) -> str:
    if not source:
        return "UNKNOWN"
    try:
        cmp = compare_versions(ecosystem, candidate, source)
    except (InvalidVersion, ValueError, TypeError):
        return "UNKNOWN"
    return "UPGRADE" if cmp > 0 else "DOWNGRADE" if cmp < 0 else "SAME"


def _fix_coverage(ecosystem: str | None, candidate: str, fixed_versions: Mapping[str, Sequence[str]]) -> dict[str, list[str]]:
    """Which of the source's actionable vulnerabilities the candidate is past a fix for.

    Conservative: a fix counts only when a declared fix version is on the
    candidate's major line and the candidate is not older than it. Anything
    else is ``unknown`` — never "fixed".
    """
    covered, unknown = [], []
    major = _major(candidate)
    for vuln_id, fixes in sorted(fixed_versions.items()):
        hit = False
        for fix in fixes or ():
            if _major(fix) != major:
                continue
            try:
                if compare_versions(ecosystem, candidate, fix) >= 0:
                    hit = True
                    break
            except (InvalidVersion, ValueError, TypeError):
                continue
        (covered if hit else unknown).append(vuln_id)
    return {"fixed": covered, "unknown": unknown}


def _improves(source, observed) -> bool:
    """Observed candidate is safer: lower current risk, or same risk with a better lifecycle."""
    source_rank, candidate_rank = RISK_SORT_RANK[source.classification], RISK_SORT_RANK[observed.classification]
    if observed.classification in (RiskClassification.REVIEW_REQUIRED, RiskClassification.UNKNOWN):
        return False
    if candidate_rank < source_rank:
        return True
    lifecycle_better = source.lifecycle.bucket in END_OF_LIFE_BUCKETS and observed.lifecycle.bucket in _SUPPORTIVE_LIFECYCLE
    return candidate_rank == source_rank and lifecycle_better


def discover_same_family(
    source,
    family_versions: Iterable,
    *,
    lifecycle_hints: Mapping[str, str | None] | None = None,
    fixed_versions: Mapping[str, Sequence[str]] | None = None,
) -> DiscoveryResult:
    """Evaluate safer versions of ``source``'s family (FR-SCA-013).

    ``source`` and ``family_versions`` are ComponentVersionIntelligence
    records from the tenant-wide eligible snapshot; ``lifecycle_hints`` maps
    hint source → version; ``fixed_versions`` maps each actionable
    vulnerability of the source to its declared fix versions.
    """
    fixed_versions = dict(fixed_versions or {})
    observed = {
        str(v.version): v for v in family_versions
        if v.canonical_key != source.canonical_key and v.version and str(v.version) != str(source.version or "")
    }
    sources: dict[str, list[str]] = {version: ["TENANT_OBSERVED"] for version in observed}
    for hint in HINT_SOURCES:
        value = (lifecycle_hints or {}).get(hint)
        if value and str(value) != str(source.version or ""):
            sources.setdefault(str(value), []).append(hint)
    for fixes in fixed_versions.values():
        for fix in fixes or ():
            if fix and str(fix) != str(source.version or ""):
                bucket = sources.setdefault(str(fix), [])
                if "FINDING_FIXED_VERSION" not in bucket:
                    bucket.append("FINDING_FIXED_VERSION")

    candidates: list[CandidateEvaluation] = []
    excluded: list[dict[str, Any]] = []
    for version, evidence in sorted(sources.items()):
        record = observed.get(version)
        direction = _direction(source.ecosystem, source.version, version)
        coverage = _fix_coverage(source.ecosystem, version, fixed_versions)
        if record is not None and not _improves(source, record):
            excluded.append({"version": version, "reason": "NOT_SAFER_THAN_SOURCE",
                             "classification": record.classification.value,
                             "lifecycle_bucket": record.lifecycle.bucket.value})
            continue
        if record is None and direction == "DOWNGRADE":
            excluded.append({"version": version, "reason": "DOWNGRADE_WITHOUT_OBSERVED_POSTURE"})
            continue
        candidates.append(_evaluate(source, version, record, evidence, direction, coverage))

    _rank(candidates)
    return DiscoveryResult(candidates, excluded)


def _evaluate(source, version, record, evidence, direction, coverage) -> CandidateEvaluation:
    major_change = None
    if _major(version) is not None and _major(source.version) is not None:
        major_change = _major(version) != _major(source.version)
    candidate = CandidateEvaluation(
        kind=CandidateKind.SAME_FAMILY_VERSION,
        source_type=CandidateSourceType.TENANT_OBSERVED if record is not None else CandidateSourceType.EXTERNAL,
        canonical_key=record.canonical_key if record is not None else None,
        name=record.name if record is not None else source.name,
        version=version,
        purl=record.purl if record is not None else None,
        ecosystem=source.ecosystem,
        evidence_sources=list(evidence),
    )
    reasons, limitations = candidate.reasons, candidate.limitations
    reasons.append({"code": "SAME_ECOSYSTEM", "detail": f"Same component family ({source.family_key})"})

    if record is not None:
        posture = {
            "status": "OBSERVED",
            "classification": record.classification.value,
            "highest_actionable_severity": record.highest_actionable_severity,
            "actionable_vulnerability_count": record.actionable_vulnerability_count,
            "review_reasons": list(record.review_reasons),
        }
        if RISK_SORT_RANK[record.classification] < RISK_SORT_RANK[source.classification]:
            reasons.append({"code": "LOWER_CURRENT_RISK",
                            "detail": f"{record.classification.value} vs source {source.classification.value}"})
        if record.classification is RiskClassification.NO_KNOWN_ACTIONABLE_VULNERABILITIES:
            reasons.append({"code": "NO_KNOWN_ACTIONABLE_VULNS_CURRENT_SNAPSHOT",
                            "detail": "No actionable findings in the current eligible snapshot (not proof of security)"})
        reasons.append({"code": "FOUND_IN_N_ACTIVE_TENANT_SBOMS", "count": record.occurrence_count})
        reasons.append({"code": "USED_BY_N_TENANT_PRODUCTS", "count": len(record.product_ids)})
        lifecycle = {"bucket": record.lifecycle.bucket.value, "status": record.lifecycle.status,
                     "effective_date": record.lifecycle.effective_date}
        if record.lifecycle.bucket is LifecycleBucket.SUPPORTED:
            reasons.append({"code": "SUPPORTED_LIFECYCLE"})
            if "LOWER_CURRENT_RISK" in {r["code"] for r in reasons}:
                reasons.append({"code": "SAFER_SUPPORTED_VERSION"})
        elif record.lifecycle.bucket is LifecycleBucket.UNKNOWN:
            limitations.append({"code": "LIFECYCLE_EVIDENCE_UNAVAILABLE", "detail": "No lifecycle status for this version"})
        if record.review_reasons:
            limitations.append({"code": "CANDIDATE_REVIEW_REASONS", "detail": ", ".join(record.review_reasons)})
        licenses = {"source": list(source.licenses), "candidate": list(record.licenses)}
        licenses["changed"] = sorted(map(str.lower, source.licenses)) != sorted(map(str.lower, record.licenses))
        if not record.licenses:
            limitations.append({"code": "LICENSE_EVIDENCE_UNAVAILABLE", "detail": "No license declared for the candidate"})
        elif licenses["changed"]:
            limitations.append({"code": "LICENSE_CHANGED", "detail": f"{source.licenses} → {record.licenses}"})
        freshness = {"latest_analysis_at": record.latest_analysis_at, "lifecycle_checked_at": record.lifecycle.checked_at}
        adoption = {"active_sbom_occurrences": record.occurrence_count, "product_count": len(record.product_ids)}
    else:
        posture = {"status": "NOT_OBSERVED_IN_TENANT"}
        limitations.append({"code": "VULNERABILITY_POSTURE_NOT_OBSERVED",
                            "detail": "Version is not in the tenant's active SBOMs; its current findings are unknown"})
        limitations.append({"code": "LIFECYCLE_EVIDENCE_UNAVAILABLE", "detail": "No lifecycle status for this version"})
        limitations.append({"code": "LICENSE_EVIDENCE_UNAVAILABLE", "detail": "License of this version is unknown"})
        lifecycle = {"bucket": LifecycleBucket.UNKNOWN.value, "status": "Unknown", "effective_date": None}
        licenses = {"source": list(source.licenses), "candidate": None, "changed": None}
        freshness = {"latest_analysis_at": None, "lifecycle_checked_at": None}
        adoption = {"active_sbom_occurrences": 0, "product_count": 0}

    if "LIFECYCLE_RECOMMENDED" in evidence:
        reasons.append({"code": "LIFECYCLE_PROVIDER_RECOMMENDED"})
    if "LIFECYCLE_LATEST_SUPPORTED" in evidence:
        reasons.append({"code": "LIFECYCLE_PROVIDER_LATEST_SUPPORTED"})
    if coverage["fixed"]:
        reasons.append({"code": "FIXES_SOURCE_VULNERABILITIES", "vulnerabilities": list(coverage["fixed"])})

    if direction == "DOWNGRADE":
        limitations.append({"code": "DOWNGRADE", "detail": "Candidate is older than the source version"})
    if direction == "UNKNOWN":
        limitations.append({"code": "VERSION_ORDER_UNKNOWN", "detail": "Versions cannot be ordered for this ecosystem"})
    if major_change is not False:
        limitations.append({"code": "API_COMPATIBILITY_REQUIRES_VERIFICATION",
                            "detail": "Major version change" if major_change else "Major version cannot be determined"})
    for code, detail in ALWAYS_LIMITATIONS:
        limitations.append({"code": code, "detail": detail})

    candidate.evaluation = {
        "current_posture": posture,
        "fix_coverage": coverage,
        "lifecycle": lifecycle,
        "license": licenses,
        "version_change": {"direction": direction, "major_version_change": major_change,
                           "from": source.version, "to": version},
        "freshness": freshness,
        "adoption": adoption,
        "historical_trend": {"status": "NOT_EVALUATED"},
        "release_cadence": {"status": "NOT_EVALUATED"},
        "compatibility": {"status": "NOT_EVALUATED"},
    }
    return candidate


def _rank(candidates: list[CandidateEvaluation]) -> None:
    """Order for review only (no score until Step 7): observed + safer first."""
    def key(c: CandidateEvaluation):
        posture = c.evaluation["current_posture"]
        observed = posture["status"] == "OBSERVED"
        risk = RISK_SORT_RANK[RiskClassification(posture["classification"])] if observed else 99
        fixes = len(c.evaluation["fix_coverage"]["fixed"])
        upgrade = c.evaluation["version_change"]["direction"] == "UPGRADE"
        return (0 if observed else 1, risk, -fixes, 0 if upgrade else 1, c.version)

    candidates.sort(key=key)
    for index, candidate in enumerate(candidates, start=1):
        candidate.rank = index


__all__ = ["CandidateEvaluation", "DiscoveryResult", "discover_same_family"]

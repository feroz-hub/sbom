"""Candidate compatibility checks (FR-SCA-014, FR-SCA-015, US-SCA-10).

Pure logic. Every candidate — same-family version or alternative — gets one
result per check type, each PASS | FAIL | REVIEW_REQUIRED | UNKNOWN with
evidence, reason, limitation, a blocking flag and the evaluation time.

A blocking FAIL marks the candidate ``blocked``: it can never be represented
as an approved replacement, and no score can override it (spec Step 6). The
blocking gates are exactly the spec's list: incompatible license,
unsupported platform / runtime, known breaking API/ABI issue, applicable
regulatory block, unsupported/EOL candidate where policy forbids it — plus
the structural ones (different ecosystem or language, no established
functional purpose for an alternative, outside the product's constraints).

Where evidence does not exist the result is UNKNOWN and says so; nothing is
assumed to pass.
"""

from __future__ import annotations

from collections.abc import Iterable
from dataclasses import dataclass, field
from datetime import UTC, datetime
from enum import Enum
from typing import Any

from ..lifecycle_mapping import LifecycleBucket
from ..policy import PolicyVersionRef
from ..purpose import ResolvedPurpose
from .workflow import CandidateKind


class CheckResult(str, Enum):
    PASS = "PASS"
    FAIL = "FAIL"
    REVIEW_REQUIRED = "REVIEW_REQUIRED"
    UNKNOWN = "UNKNOWN"


CHECK_TYPES = (
    "LANGUAGE", "PACKAGE_ECOSYSTEM", "FUNCTIONAL_PURPOSE", "API_COMPATIBILITY", "ABI_COMPATIBILITY",
    "OPERATING_SYSTEM", "RUNTIME", "CPU_ARCHITECTURE", "LICENSE", "PRODUCT_CONSTRAINTS", "REGULATORY",
    "LIFECYCLE", "SUPPORTED_VERSIONS", "TRANSITIVE_DEPENDENCIES",
)

#: Ecosystem → language. Unlisted ecosystems have an UNKNOWN language.
LANGUAGE_BY_ECOSYSTEM = {
    "npm": "JavaScript/TypeScript", "pypi": "Python", "maven": "JVM", "gradle": "JVM", "nuget": ".NET",
    "gem": "Ruby", "cargo": "Rust", "go": "Go", "golang": "Go", "composer": "PHP", "hex": "Erlang/Elixir",
    "pub": "Dart", "swift": "Swift", "cocoapods": "Swift/Objective-C",
}
#: Ecosystems shipping compiled artefacts where ABI matters.
ABI_ECOSYSTEMS = frozenset({"cargo", "go", "golang", "nuget", "conan", "generic", "deb", "rpm", "apk"})


@dataclass(frozen=True)
class ProductConstraints:
    """What the product(s) using the source can accept (FR-SCA-014).

    Baseline: derived from evidence the platform has — the ecosystems present
    in the products' active SBOMs. Platform / runtime / OS / architecture
    constraints have no model yet and are UNKNOWN unless supplied.
    """

    established: bool
    ecosystems: frozenset[str] = frozenset()
    runtimes: frozenset[str] = frozenset()
    operating_systems: frozenset[str] = frozenset()
    architectures: frozenset[str] = frozenset()
    source: str = "PRODUCT_SBOM_ECOSYSTEMS"

    def to_dict(self) -> dict[str, Any]:
        return {
            "established": self.established,
            "ecosystems": sorted(self.ecosystems),
            "runtimes": sorted(self.runtimes),
            "operating_systems": sorted(self.operating_systems),
            "architectures": sorted(self.architectures),
            "source": self.source,
        }


@dataclass(frozen=True)
class CompatibilityEvidence:
    """Candidate-specific evidence from an adapter or a manual reviewer."""

    known_breaking_api: bool | None = None
    known_breaking_abi: bool | None = None
    unsupported_runtimes: tuple[str, ...] = ()
    unsupported_operating_systems: tuple[str, ...] = ()
    unsupported_architectures: tuple[str, ...] = ()
    regulatory_block: str | None = None
    transitive_dependencies_reviewed: bool | None = None
    source: str | None = None

    @classmethod
    def from_dict(cls, data: dict[str, Any] | None, *, source: str | None = None) -> CompatibilityEvidence:
        data = dict(data or {})
        return cls(
            known_breaking_api=data.get("known_breaking_api"),
            known_breaking_abi=data.get("known_breaking_abi"),
            unsupported_runtimes=tuple(data.get("unsupported_runtimes") or ()),
            unsupported_operating_systems=tuple(data.get("unsupported_operating_systems") or ()),
            unsupported_architectures=tuple(data.get("unsupported_architectures") or ()),
            regulatory_block=data.get("regulatory_block") or None,
            transitive_dependencies_reviewed=data.get("transitive_dependencies_reviewed"),
            source=source or data.get("source"),
        )


@dataclass(frozen=True)
class CandidateFacts:
    kind: CandidateKind
    name: str
    version: str | None
    ecosystem: str | None
    family_key: str | None
    observed: bool
    purpose: ResolvedPurpose | None
    licenses: tuple[str, ...] | None  # None = unknown
    lifecycle: LifecycleBucket | None  # None = unknown
    major_version_change: bool | None
    evidence: CompatibilityEvidence = field(default_factory=CompatibilityEvidence)


@dataclass(frozen=True)
class CompatibilityCheck:
    check_type: str
    result: CheckResult
    blocking: bool
    reason: str
    limitation: str | None
    evidence: dict[str, Any]
    evaluated_at: str

    def to_dict(self) -> dict[str, Any]:
        return {
            "check_type": self.check_type,
            "result": self.result.value,
            "blocking": self.blocking,
            "reason": self.reason,
            "limitation": self.limitation,
            "evidence": dict(self.evidence),
            "evaluated_at": self.evaluated_at,
        }


def _eco(value: str | None) -> str:
    return str(value or "").strip().lower()


def _category(purpose: ResolvedPurpose | None) -> str | None:
    if purpose is None:
        return None
    field_ = purpose.fields.get("technology_category")
    return field_.value.strip().lower() if field_ and field_.searchable else None


def evaluate_compatibility(
    source,
    candidate: CandidateFacts,
    *,
    constraints: ProductConstraints,
    trust_policy: PolicyVersionRef | None = None,
    now: datetime | None = None,
) -> list[CompatibilityCheck]:
    """All FR-SCA-014 checks for one candidate, in :data:`CHECK_TYPES` order."""
    at = (now or datetime.now(UTC)).isoformat()
    checks: list[CompatibilityCheck] = []

    def add(check_type, result, reason, *, blocking=False, limitation=None, **evidence):
        checks.append(CompatibilityCheck(check_type, result, blocking and result is CheckResult.FAIL,
                                         reason, limitation, evidence, at))

    src_eco, cand_eco = _eco(source.ecosystem), _eco(candidate.ecosystem)
    same_family = candidate.kind is CandidateKind.SAME_FAMILY_VERSION

    # LANGUAGE
    src_lang, cand_lang = LANGUAGE_BY_ECOSYSTEM.get(src_eco), LANGUAGE_BY_ECOSYSTEM.get(cand_eco)
    if same_family or (src_lang and src_lang == cand_lang):
        add("LANGUAGE", CheckResult.PASS, "Same language", source=src_lang, candidate=cand_lang or src_lang)
    elif src_lang and cand_lang:
        add("LANGUAGE", CheckResult.FAIL, f"{cand_lang} cannot replace {src_lang}", blocking=True,
            source=src_lang, candidate=cand_lang)
    else:
        add("LANGUAGE", CheckResult.UNKNOWN, "Language cannot be determined from the ecosystem",
            limitation="LANGUAGE_EVIDENCE_UNAVAILABLE", source=src_lang, candidate=cand_lang)

    # PACKAGE_ECOSYSTEM
    if src_eco and src_eco == cand_eco:
        add("PACKAGE_ECOSYSTEM", CheckResult.PASS, "Same package ecosystem", ecosystem=src_eco)
    elif src_eco and cand_eco:
        add("PACKAGE_ECOSYSTEM", CheckResult.FAIL, f"Ecosystem {cand_eco} differs from {src_eco}", blocking=True,
            source=src_eco, candidate=cand_eco)
    else:
        add("PACKAGE_ECOSYSTEM", CheckResult.UNKNOWN, "Ecosystem not established", limitation="ECOSYSTEM_UNKNOWN")

    # FUNCTIONAL_PURPOSE
    if same_family:
        add("FUNCTIONAL_PURPOSE", CheckResult.PASS, "Same component family", family_key=candidate.family_key)
    else:
        src_cat, cand_cat = _category(source.purpose), _category(candidate.purpose)
        if not cand_cat:
            add("FUNCTIONAL_PURPOSE", CheckResult.FAIL, "Candidate has no evidenced functional purpose", blocking=True,
                limitation="INSUFFICIENT_PURPOSE_EVIDENCE", source=src_cat)
        elif src_cat and src_cat == cand_cat:
            add("FUNCTIONAL_PURPOSE", CheckResult.PASS, f"Same technology category ({src_cat})",
                source=src_cat, candidate=cand_cat,
                candidate_source=candidate.purpose.fields["technology_category"].source.value)
        else:
            add("FUNCTIONAL_PURPOSE", CheckResult.FAIL, f"Category {cand_cat} differs from {src_cat}", blocking=True,
                source=src_cat, candidate=cand_cat)

    # API / ABI
    ev = candidate.evidence
    if ev.known_breaking_api:
        add("API_COMPATIBILITY", CheckResult.FAIL, "Known breaking API change", blocking=True, evidence_source=ev.source)
    elif not same_family:
        add("API_COMPATIBILITY", CheckResult.REVIEW_REQUIRED, "A different component has a different API",
            limitation="MIGRATION_REQUIRED")
    elif candidate.major_version_change is False:
        add("API_COMPATIBILITY", CheckResult.REVIEW_REQUIRED, "Same major version; API compatibility unverified",
            limitation="API_COMPATIBILITY_REQUIRES_VERIFICATION")
    else:
        add("API_COMPATIBILITY", CheckResult.REVIEW_REQUIRED,
            "Major version change" if candidate.major_version_change else "Major version cannot be determined",
            limitation="API_COMPATIBILITY_REQUIRES_VERIFICATION")
    if ev.known_breaking_abi:
        add("ABI_COMPATIBILITY", CheckResult.FAIL, "Known breaking ABI change", blocking=True, evidence_source=ev.source)
    elif cand_eco in ABI_ECOSYSTEMS or src_eco in ABI_ECOSYSTEMS:
        add("ABI_COMPATIBILITY", CheckResult.UNKNOWN, "No ABI evidence for a compiled ecosystem",
            limitation="ABI_EVIDENCE_UNAVAILABLE")
    else:
        add("ABI_COMPATIBILITY", CheckResult.PASS, "Ecosystem distributes source or bytecode; no native ABI",
            ecosystem=cand_eco)

    # OPERATING_SYSTEM / RUNTIME / CPU_ARCHITECTURE
    for check_type, unsupported, required, label in (
        ("OPERATING_SYSTEM", ev.unsupported_operating_systems, constraints.operating_systems, "operating system"),
        ("RUNTIME", ev.unsupported_runtimes, constraints.runtimes, "runtime"),
        ("CPU_ARCHITECTURE", ev.unsupported_architectures, constraints.architectures, "CPU architecture"),
    ):
        clash = sorted({u.lower() for u in unsupported} & {r.lower() for r in required})
        if clash:
            add(check_type, CheckResult.FAIL, f"Unsupported {label}: {', '.join(clash)}", blocking=True,
                evidence_source=ev.source, unsupported=clash)
        elif unsupported and not required:
            add(check_type, CheckResult.REVIEW_REQUIRED, f"Candidate excludes some {label}s; product needs unknown",
                limitation="PLATFORM_EVIDENCE_INCOMPLETE", unsupported=sorted(unsupported))
        else:
            add(check_type, CheckResult.UNKNOWN, f"No {label} evidence", limitation="PLATFORM_EVIDENCE_INCOMPLETE")

    # LICENSE
    checks.append(_license_check(source, candidate, trust_policy, at))

    # PRODUCT_CONSTRAINTS
    if not constraints.established:
        add("PRODUCT_CONSTRAINTS", CheckResult.UNKNOWN, "Product constraints could not be established",
            limitation="PRODUCT_CONSTRAINTS_UNAVAILABLE")
    elif cand_eco and cand_eco in constraints.ecosystems:
        add("PRODUCT_CONSTRAINTS", CheckResult.PASS, "Ecosystem already used by the product(s)",
            ecosystems=sorted(constraints.ecosystems))
    else:
        add("PRODUCT_CONSTRAINTS", CheckResult.FAIL, "Ecosystem not used by the product(s)", blocking=True,
            ecosystems=sorted(constraints.ecosystems), candidate=cand_eco)

    # REGULATORY
    if ev.regulatory_block:
        add("REGULATORY", CheckResult.FAIL, f"Regulatory block: {ev.regulatory_block}", blocking=True,
            evidence_source=ev.source)
    else:
        add("REGULATORY", CheckResult.UNKNOWN, "No regulatory constraint evidence", limitation="REGULATORY_EVIDENCE_UNAVAILABLE")

    # LIFECYCLE
    checks.append(_lifecycle_check(candidate, trust_policy, at))

    # SUPPORTED_VERSIONS
    if candidate.lifecycle in (LifecycleBucket.SUPPORTED, LifecycleBucket.MAINTENANCE):
        add("SUPPORTED_VERSIONS", CheckResult.PASS, f"Version is {candidate.lifecycle.value}")
    else:
        add("SUPPORTED_VERSIONS", CheckResult.UNKNOWN, "Supported-version range unknown",
            limitation="SUPPORTED_VERSION_EVIDENCE_UNAVAILABLE")

    # TRANSITIVE_DEPENDENCIES
    if ev.transitive_dependencies_reviewed:
        add("TRANSITIVE_DEPENDENCIES", CheckResult.PASS, "Reviewer confirmed transitive dependencies",
            evidence_source=ev.source)
    else:
        add("TRANSITIVE_DEPENDENCIES", CheckResult.UNKNOWN, "Transitive dependencies were not compared",
            limitation="TRANSITIVE_DEPENDENCY_DIFFERENCES")
    return checks


def _license_check(source, candidate: CandidateFacts, trust_policy, at) -> CompatibilityCheck:
    rules = trust_policy.rules if trust_policy else {}
    allowed = {item.lower() for item in rules.get("allowed_licenses") or ()}
    denied = {item.lower() for item in rules.get("denied_licenses") or ()}
    policy_ref = {"policy_version_id": trust_policy.id} if trust_policy and (allowed or denied) else {}

    def make(result, reason, *, blocking=False, limitation=None, **evidence):
        return CompatibilityCheck("LICENSE", result, blocking and result is CheckResult.FAIL, reason, limitation,
                                  {**evidence, **policy_ref}, at)

    if candidate.licenses is None or not candidate.licenses:
        return make(CheckResult.UNKNOWN, "Candidate license unknown", limitation="LICENSE_EVIDENCE_UNAVAILABLE")
    lowered = {item.lower() for item in candidate.licenses}
    if denied & lowered:
        return make(CheckResult.FAIL, f"Denied license: {sorted(denied & lowered)}", blocking=True,
                    candidate=list(candidate.licenses))
    if allowed and not lowered <= allowed:
        return make(CheckResult.FAIL, f"License outside allow list: {sorted(lowered - allowed)}", blocking=True,
                    candidate=list(candidate.licenses))
    if allowed:
        return make(CheckResult.PASS, "All licenses allowed by policy", candidate=list(candidate.licenses))
    if {item.lower() for item in source.licenses} != lowered:
        return make(CheckResult.REVIEW_REQUIRED, "License differs from the source; no license policy configured",
                    limitation="LICENSE_CHANGED", source=list(source.licenses), candidate=list(candidate.licenses))
    return make(CheckResult.PASS, "Same license as the source", candidate=list(candidate.licenses))


def _lifecycle_check(candidate: CandidateFacts, trust_policy, at) -> CompatibilityCheck:
    """T26: an EOL candidate follows lifecycle policy.

    With a trust policy, its ``allowed_lifecycle`` list decides. Without one the
    baseline forbids recommending an EOL replacement and asks for review of EOS.
    """
    bucket = candidate.lifecycle
    allowed = (trust_policy.rules.get("allowed_lifecycle") if trust_policy else None) or None
    evidence = {"lifecycle": bucket.value if bucket else None}
    if trust_policy and allowed:
        evidence["policy_version_id"] = trust_policy.id
    if bucket is None or bucket is LifecycleBucket.UNKNOWN:
        return CompatibilityCheck("LIFECYCLE", CheckResult.UNKNOWN, False, "Candidate lifecycle unknown",
                                  "LIFECYCLE_EVIDENCE_UNAVAILABLE", evidence, at)
    if allowed is not None:
        ok = bucket.value in allowed
        return CompatibilityCheck("LIFECYCLE", CheckResult.PASS if ok else CheckResult.FAIL, not ok,
                                  f"Lifecycle {bucket.value} {'allowed' if ok else 'forbidden'} by policy",
                                  None, {**evidence, "allowed": list(allowed)}, at)
    if bucket is LifecycleBucket.EOL:
        return CompatibilityCheck("LIFECYCLE", CheckResult.FAIL, True, "Candidate is end of life", None, evidence, at)
    if bucket is LifecycleBucket.EOS:
        return CompatibilityCheck("LIFECYCLE", CheckResult.REVIEW_REQUIRED, False, "Candidate is end of support",
                                  "END_OF_SUPPORT", evidence, at)
    return CompatibilityCheck("LIFECYCLE", CheckResult.PASS, False, f"Lifecycle {bucket.value}", None, evidence, at)


def summarize(checks: Iterable[CompatibilityCheck]) -> dict[str, Any]:
    checks = list(checks)
    counts = {result.value: 0 for result in CheckResult}
    for check in checks:
        counts[check.result.value] += 1
    blocking = [check.check_type for check in checks if check.blocking]
    return {
        "status": "BLOCKED" if blocking else "REVIEW_REQUIRED" if counts["REVIEW_REQUIRED"] or counts["UNKNOWN"] else "PASS",
        "counts": counts,
        "blocking_checks": blocking,
        "blocked": bool(blocking),
        # Missing material compatibility evidence prevents any "drop-in" claim (FR-SCA-019).
        "drop_in_representable": not blocking and counts["UNKNOWN"] == 0 and counts["REVIEW_REQUIRED"] == 0,
    }


__all__ = [
    "CHECK_TYPES",
    "CandidateFacts",
    "CheckResult",
    "CompatibilityCheck",
    "CompatibilityEvidence",
    "ProductConstraints",
    "evaluate_compatibility",
    "summarize",
]

"""Risk classification for one unique component version (FR-SCA-003, spec §2).

Pure domain logic — no database access — so the rules can be unit tested
directly (NFR-SCA-009) and every caller (dashboard tiles, drill-down, search,
recommendation triggers) buckets a component the same way.

Actionability follows the VEX effective status (spec §2):

* ``AFFECTED`` / ``UNDER_INVESTIGATION`` → actionable.
* ``FIXED`` / ``NOT_AFFECTED`` → non-actionable. They stay visible as evidence
  but never make a component actionable.

Buckets are mutually exclusive. Precedence (phase0-analysis.md §4, decisions
D-3/D-4/D-5, amended 2026-10-01 so Critical/High are never hidden):

1. **Critical / High** — the highest actionable severity is CRITICAL or HIGH.
   These outrank review reasons so the Critical/High KPIs never understate
   known risk; any review reasons stay attached to the result.
2. **Review Required** — a review reason is present (VEX conflict or
   revalidation, VEX-only AFFECTED assertion, LOW identity confidence,
   stale evidence, or an actionable finding whose highest severity is
   UNKNOWN).
3. **Unknown** — no occurrence of the version has a successful analysis in
   the eligible snapshot, so there is no vulnerability evidence at all.
4. Remaining actionable findings (Medium / Low):
   a. an active accepted-risk policy is satisfied → **Accepted Risk**;
   b. otherwise **Medium** / **Low**.
5. No actionable findings → **No Known Actionable Vulnerabilities**.

An accepted-risk policy is never applied to Critical/High or to a version
with review reasons: unreliable evidence cannot be accepted.

INFORMATIONAL exists in the vocabulary because the spec lists it, but the
severity model has no such level (D-4), so nothing is ever classified as
INFORMATIONAL and :data:`INFORMATIONAL_SUPPORTED` is ``False``.
"""

from __future__ import annotations

from collections.abc import Iterable
from dataclasses import dataclass, field
from enum import Enum

#: Effective VEX statuses that make a finding actionable (spec §2).
ACTIONABLE_VEX_STATUSES = frozenset({"AFFECTED", "UNDER_INVESTIGATION"})
#: Effective VEX statuses that are explicitly non-actionable (spec §2).
NON_ACTIONABLE_VEX_STATUSES = frozenset({"FIXED", "NOT_AFFECTED"})

#: Severity rank, highest first. Mirrors ``app.services.finding_metrics``.
SEVERITY_RANK = {"CRITICAL": 4, "HIGH": 3, "MEDIUM": 2, "LOW": 1, "UNKNOWN": 0}

#: The severity model has no INFORMATIONAL level (decision D-4).
INFORMATIONAL_SUPPORTED = False


class RiskClassification(str, Enum):
    """The nine spec risk filters (FR-SCA-007). Never "Safe" or "Secure"."""

    NO_KNOWN_ACTIONABLE_VULNERABILITIES = "NO_KNOWN_ACTIONABLE_VULNERABILITIES"
    INFORMATIONAL = "INFORMATIONAL"
    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"
    CRITICAL = "CRITICAL"
    ACCEPTED_RISK = "ACCEPTED_RISK"
    REVIEW_REQUIRED = "REVIEW_REQUIRED"
    UNKNOWN = "UNKNOWN"


class ReviewReason(str, Enum):
    """Why a component version needs human review before it can be bucketed."""

    VEX_CONFLICT = "VEX_CONFLICT_REVIEW_REQUIRED"
    VEX_REVALIDATION = "VEX_REVALIDATION_REQUIRED"
    VEX_ONLY_AFFECTED = "VEX_ONLY_AFFECTED_ASSERTION"
    LOW_IDENTITY_CONFIDENCE = "LOW_IDENTITY_CONFIDENCE"
    UNKNOWN_ACTIONABLE_SEVERITY = "ACTIONABLE_SEVERITY_UNKNOWN"
    STALE_EVIDENCE = "STALE_EVIDENCE"


#: VEX reconciliation states that force review (VEX-DASH-003).
RECONCILIATION_REVIEW_REASONS = {
    "CONFLICT_REVIEW_REQUIRED": ReviewReason.VEX_CONFLICT,
    "REVALIDATION_REQUIRED": ReviewReason.VEX_REVALIDATION,
}

_SEVERITY_BUCKETS = {
    "CRITICAL": RiskClassification.CRITICAL,
    "HIGH": RiskClassification.HIGH,
    "MEDIUM": RiskClassification.MEDIUM,
    "LOW": RiskClassification.LOW,
}


#: Severities that set the bucket even when review reasons exist.
_OUTRANKS_REVIEW = frozenset({"CRITICAL", "HIGH"})


def normalize_severity(value: object) -> str:
    """Upper-case canonical severity; anything unrecognised is UNKNOWN."""
    severity = str(value or "").strip().upper()
    return severity if severity in SEVERITY_RANK else "UNKNOWN"


def is_actionable(effective_status: str | None) -> bool:
    """True for AFFECTED / UNDER_INVESTIGATION.

    ``None`` means the analyser finding has no VEX context yet (reconciliation
    has not caught up). VEX-REC-002 A makes that UNDER_INVESTIGATION, so it is
    actionable: failing safe, never silently "no known vulnerabilities".
    """
    if effective_status is None:
        return True
    return str(effective_status).strip().upper() in ACTIONABLE_VEX_STATUSES


def highest_severity(severities: Iterable[str]) -> str | None:
    """Highest of ``severities`` by rank, or ``None`` when empty."""
    best: str | None = None
    for raw in severities:
        severity = normalize_severity(raw)
        if best is None or SEVERITY_RANK[severity] > SEVERITY_RANK[best]:
            best = severity
    return best


@dataclass(frozen=True)
class AcceptedRiskOutcome:
    """Result of evaluating an accepted-risk policy version (FR-SCA-004).

    Produced by the policy seam (Step 4). Until a policy is configured,
    callers pass ``None`` and no component is ever Accepted Risk.
    """

    satisfied: bool
    policy_version_id: int | None = None
    #: Criteria that passed / failed, by name.
    reasons: tuple[str, ...] = ()
    failures: tuple[str, ...] = ()
    #: Full per-criterion trace (``{"criterion", "passed", "detail"}``) for the UI.
    criteria: tuple[dict, ...] = ()


@dataclass(frozen=True)
class ClassificationInput:
    """Everything the bucket rules need for one unique component version."""

    #: True when at least one occurrence's SBOM has a successful analysis run
    #: in the eligible snapshot.
    has_vulnerability_evidence: bool
    #: Severity of each distinct actionable vulnerability.
    actionable_severities: tuple[str, ...] = ()
    review_reasons: frozenset[ReviewReason] = field(default_factory=frozenset)
    accepted_risk: AcceptedRiskOutcome | None = None


@dataclass(frozen=True)
class ClassificationResult:
    classification: RiskClassification
    highest_actionable_severity: str | None
    review_reasons: tuple[str, ...]
    accepted_risk_policy_version_id: int | None = None
    accepted_risk_reasons: tuple[str, ...] = ()


def classify(data: ClassificationInput) -> ClassificationResult:
    """Apply the spec §2 rules with the phase-0 precedence (module docstring)."""
    highest = highest_severity(data.actionable_severities)
    reasons = set(data.review_reasons)
    if highest == "UNKNOWN":
        reasons.add(ReviewReason.UNKNOWN_ACTIONABLE_SEVERITY)
    ordered_reasons = tuple(sorted(reason.value for reason in reasons))

    if highest in _OUTRANKS_REVIEW:
        return ClassificationResult(_SEVERITY_BUCKETS[highest], highest, ordered_reasons)
    if reasons:
        return ClassificationResult(RiskClassification.REVIEW_REQUIRED, highest, ordered_reasons)
    if not data.has_vulnerability_evidence:
        return ClassificationResult(RiskClassification.UNKNOWN, None, ())
    if highest is None:
        return ClassificationResult(
            RiskClassification.NO_KNOWN_ACTIONABLE_VULNERABILITIES, None, ()
        )
    accepted = data.accepted_risk
    if accepted is not None and accepted.satisfied:
        return ClassificationResult(
            RiskClassification.ACCEPTED_RISK,
            highest,
            (),
            accepted_risk_policy_version_id=accepted.policy_version_id,
            accepted_risk_reasons=accepted.reasons,
        )
    return ClassificationResult(_SEVERITY_BUCKETS[highest], highest, ())


#: Display order of the buckets; every bucket always appears in counts so
#: the totals visibly reconcile (spec §2 "Buckets must reconcile").
CLASSIFICATION_ORDER: tuple[RiskClassification, ...] = (
    RiskClassification.CRITICAL,
    RiskClassification.HIGH,
    RiskClassification.MEDIUM,
    RiskClassification.LOW,
    RiskClassification.INFORMATIONAL,
    RiskClassification.ACCEPTED_RISK,
    RiskClassification.REVIEW_REQUIRED,
    RiskClassification.UNKNOWN,
    RiskClassification.NO_KNOWN_ACTIONABLE_VULNERABILITIES,
)


def bucket_counts(classifications: Iterable[RiskClassification]) -> dict[str, int]:
    """Count per bucket, including zero buckets. Sum == number of inputs."""
    counts = {bucket.value: 0 for bucket in CLASSIFICATION_ORDER}
    for classification in classifications:
        counts[RiskClassification(classification).value] += 1
    return counts


__all__ = [
    "ACTIONABLE_VEX_STATUSES",
    "CLASSIFICATION_ORDER",
    "INFORMATIONAL_SUPPORTED",
    "NON_ACTIONABLE_VEX_STATUSES",
    "RECONCILIATION_REVIEW_REASONS",
    "SEVERITY_RANK",
    "AcceptedRiskOutcome",
    "ClassificationInput",
    "ClassificationResult",
    "ReviewReason",
    "RiskClassification",
    "bucket_counts",
    "classify",
    "highest_severity",
    "is_actionable",
    "normalize_severity",
]

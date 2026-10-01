"""Recommendation work item states, transitions and triggers (FR-SCA-011).

Pure logic (NFR-SCA-009).

States (spec Step 5)::

    OPEN → EVALUATING → REVIEW_REQUIRED → RECOMMENDED → ACCEPTED | REJECTED | DEFERRED → CLOSED

Evaluation always ends in REVIEW_REQUIRED: human review is mandatory before
anything is RECOMMENDED, and only a reviewer can move an item past it
(Step 8). "Open" items — the ones a re-run must not duplicate (T20) — are
OPEN, EVALUATING, REVIEW_REQUIRED and RECOMMENDED; DEFERRED is a decision,
so a new trigger may raise a fresh item (decision D-10).

Triggers are checked against the *current* evidence: a CRITICAL_FINDING
trigger is only accepted for a version whose highest actionable severity is
CRITICAL right now, and so on. MANUAL is always allowed (T17–T19).
"""

from __future__ import annotations

from enum import Enum
from typing import Any

from ..classification import RiskClassification
from ..lifecycle_mapping import LifecycleBucket


class RecommendationStatus(str, Enum):
    OPEN = "OPEN"
    EVALUATING = "EVALUATING"
    REVIEW_REQUIRED = "REVIEW_REQUIRED"
    RECOMMENDED = "RECOMMENDED"
    ACCEPTED = "ACCEPTED"
    REJECTED = "REJECTED"
    DEFERRED = "DEFERRED"
    CLOSED = "CLOSED"


class TriggerType(str, Enum):
    CRITICAL_FINDING = "CRITICAL_FINDING"
    HIGH_FINDING = "HIGH_FINDING"
    EOL = "EOL"
    EOS = "EOS"
    POLICY_VIOLATION = "POLICY_VIOLATION"
    MANUAL = "MANUAL"


class CandidateKind(str, Enum):
    SAME_FAMILY_VERSION = "SAME_FAMILY_VERSION"
    ALTERNATIVE = "ALTERNATIVE"


class CandidateSourceType(str, Enum):
    TENANT_OBSERVED = "TENANT_OBSERVED"
    EXTERNAL = "EXTERNAL"
    MANUAL = "MANUAL"


OPEN_STATUSES = frozenset({
    RecommendationStatus.OPEN,
    RecommendationStatus.EVALUATING,
    RecommendationStatus.REVIEW_REQUIRED,
    RecommendationStatus.RECOMMENDED,
})

_S = RecommendationStatus
ALLOWED_TRANSITIONS: dict[RecommendationStatus, frozenset[RecommendationStatus]] = {
    _S.OPEN: frozenset({_S.EVALUATING}),
    # Evaluation finishes in review, or returns to OPEN when it could not start.
    _S.EVALUATING: frozenset({_S.REVIEW_REQUIRED, _S.OPEN}),
    # Re-evaluate, recommend a candidate, or decide.
    _S.REVIEW_REQUIRED: frozenset({_S.EVALUATING, _S.RECOMMENDED, _S.REJECTED, _S.DEFERRED}),
    # Accept / reject / defer, or request more evidence (back to review).
    _S.RECOMMENDED: frozenset({_S.ACCEPTED, _S.REJECTED, _S.DEFERRED, _S.REVIEW_REQUIRED}),
    _S.DEFERRED: frozenset({_S.REVIEW_REQUIRED, _S.CLOSED}),
    _S.ACCEPTED: frozenset({_S.CLOSED}),
    _S.REJECTED: frozenset({_S.CLOSED}),
    _S.CLOSED: frozenset(),
}


class InvalidTransition(ValueError):
    def __init__(self, current: RecommendationStatus, target: RecommendationStatus):
        super().__init__(f"Cannot move a recommendation from {current.value} to {target.value}")
        self.current, self.target = current, target


def require_transition(current: RecommendationStatus | str, target: RecommendationStatus | str) -> RecommendationStatus:
    current, target = RecommendationStatus(current), RecommendationStatus(target)
    if target not in ALLOWED_TRANSITIONS[current]:
        raise InvalidTransition(current, target)
    return target


def can_evaluate(status: RecommendationStatus | str) -> bool:
    return RecommendationStatus.EVALUATING in ALLOWED_TRANSITIONS[RecommendationStatus(status)]


class TriggerNotSupported(ValueError):
    """The trigger does not match the version's current evidence (HTTP 422)."""


def trigger_evidence(version, trigger: TriggerType | str) -> dict[str, Any]:
    """Evidence justifying ``trigger`` for ``version``, or :class:`TriggerNotSupported`.

    ``version`` is a :class:`~app.metrics.component_advisor.ComponentVersionIntelligence`.
    The returned dict is stored on the work item so the trigger stays
    explainable after the evidence changes (NFR-SCA-002).
    """
    trigger = TriggerType(trigger)
    base = {
        "classification": version.classification.value,
        "highest_actionable_severity": version.highest_actionable_severity,
        "actionable_vulnerability_count": version.actionable_vulnerability_count,
        "lifecycle_bucket": version.lifecycle.bucket.value,
        "lifecycle_status": version.lifecycle.status,
        "lifecycle_effective_date": version.lifecycle.effective_date,
        "evidence": [dict(item) for item in version.evidence],
    }
    if trigger is TriggerType.MANUAL:
        return base
    if trigger is TriggerType.CRITICAL_FINDING and version.highest_actionable_severity == "CRITICAL":
        return base
    if trigger is TriggerType.HIGH_FINDING and version.highest_actionable_severity == "HIGH":
        return base
    if trigger is TriggerType.EOL and version.lifecycle.bucket is LifecycleBucket.EOL:
        return base
    if trigger is TriggerType.EOS and version.lifecycle.bucket is LifecycleBucket.EOS:
        return base
    if trigger is TriggerType.POLICY_VIOLATION:
        failures = _policy_failures(version)
        if failures:
            return {**base, "policy_failures": failures}
    raise TriggerNotSupported(
        f"{trigger.value} is not supported by the current evidence for this component version"
    )


def _policy_failures(version) -> list[dict[str, Any]]:
    """Failed criteria of configured policies (baseline definition; see plan log).

    A version violates policy when a configured trust policy evaluates it as
    not trusted. Accepted-risk "not satisfied" is not a violation — it only
    means the risk was not accepted.
    """
    trust = getattr(version, "trust", None)
    if trust is None or trust.trusted:
        return []
    return [
        {"policy": "TRUST", "policy_version_id": trust.policy_version_id, "criterion": c.name, "detail": c.detail}
        for c in trust.criteria
        if not c.passed
    ]


def eligible_triggers(version) -> list[str]:
    """Every trigger the current evidence supports (UI hint; server re-checks)."""
    out = []
    for trigger in TriggerType:
        try:
            trigger_evidence(version, trigger)
        except TriggerNotSupported:
            continue
        out.append(trigger.value)
    return out


#: Classifications that make a version a remediation source by themselves.
REMEDIATION_CLASSIFICATIONS = frozenset({RiskClassification.CRITICAL, RiskClassification.HIGH})


__all__ = [
    "ALLOWED_TRANSITIONS",
    "OPEN_STATUSES",
    "CandidateKind",
    "CandidateSourceType",
    "InvalidTransition",
    "RecommendationStatus",
    "TriggerNotSupported",
    "TriggerType",
    "can_evaluate",
    "eligible_triggers",
    "require_transition",
    "trigger_evidence",
]

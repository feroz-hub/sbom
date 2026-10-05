"""Human review decisions (FR-SCA-021, US-SCA-14). Pure rules.

Spec decisions are ACCEPT | REJECT | DEFER | REQUEST_MORE_EVIDENCE; RECOMMEND
("Recommend candidate", spec §9) and CLOSE complete the state machine. Each
decision maps to one permission (spec §9, decision D-7):

============================ ===================================== ===========================
Decision                     From → to                              Permission
============================ ===================================== ===========================
RECOMMEND (candidate)        REVIEW_REQUIRED → RECOMMENDED          recommendation:review
ACCEPT                       RECOMMENDED → ACCEPTED                 recommendation:accept
REJECT                       REVIEW_REQUIRED/RECOMMENDED → REJECTED recommendation:review
DEFER                        REVIEW_REQUIRED/RECOMMENDED → DEFERRED recommendation:review
REQUEST_MORE_EVIDENCE        RECOMMENDED/DEFERRED → REVIEW_REQUIRED recommendation:review
                             (REVIEW_REQUIRED stays REVIEW_REQUIRED)
CLOSE                        ACCEPTED/REJECTED/DEFERRED → CLOSED    recommendation:review
============================ ===================================== ===========================

A blocked candidate, or one with INSUFFICIENT_EVIDENCE confidence, can never
be recommended or accepted (FR-SCA-015/019). ACCEPT applies to the candidate
that was recommended. Every decision needs a reason. Nothing here touches a
dependency, manifest, source file or SBOM (spec §1.1).
"""

from __future__ import annotations

from enum import Enum

from .workflow import ALLOWED_TRANSITIONS, RecommendationStatus


class Decision(str, Enum):
    RECOMMEND = "RECOMMEND"
    ACCEPT = "ACCEPT"
    REJECT = "REJECT"
    DEFER = "DEFER"
    REQUEST_MORE_EVIDENCE = "REQUEST_MORE_EVIDENCE"
    CLOSE = "CLOSE"


_S = RecommendationStatus
TARGET = {
    Decision.RECOMMEND: _S.RECOMMENDED,
    Decision.ACCEPT: _S.ACCEPTED,
    Decision.REJECT: _S.REJECTED,
    Decision.DEFER: _S.DEFERRED,
    Decision.REQUEST_MORE_EVIDENCE: _S.REVIEW_REQUIRED,
    Decision.CLOSE: _S.CLOSED,
}
PERMISSION = {
    Decision.RECOMMEND: "component_advisor:recommendation:review",
    Decision.ACCEPT: "component_advisor:recommendation:accept",
    Decision.REJECT: "component_advisor:recommendation:review",
    Decision.DEFER: "component_advisor:recommendation:review",
    Decision.REQUEST_MORE_EVIDENCE: "component_advisor:recommendation:review",
    Decision.CLOSE: "component_advisor:recommendation:review",
}


class InvalidDecision(ValueError):
    """The decision is not allowed for this item / candidate (HTTP 409 or 422)."""

    def __init__(self, message: str, *, code: str = "INVALID_DECISION"):
        super().__init__(message)
        self.code = code


def next_status(current: RecommendationStatus | str, decision: Decision | str) -> RecommendationStatus:
    current, decision = RecommendationStatus(current), Decision(decision)
    target = TARGET[decision]
    if decision is Decision.REQUEST_MORE_EVIDENCE and current is _S.REVIEW_REQUIRED:
        return current  # already in review; the request itself is recorded
    if target not in ALLOWED_TRANSITIONS[current]:
        raise InvalidDecision(f"{decision.value} is not allowed while the recommendation is {current.value}",
                              code="INVALID_STATE")
    return target


def allowed(current: RecommendationStatus | str, decision: Decision | str) -> bool:
    try:
        next_status(current, decision)
    except InvalidDecision:
        return False
    return True


def check_candidate(decision: Decision, candidate) -> None:
    """RECOMMEND / ACCEPT gates on the candidate itself."""
    if decision not in (Decision.RECOMMEND, Decision.ACCEPT):
        return
    if candidate is None:
        raise InvalidDecision("A candidate is required", code="CANDIDATE_REQUIRED")
    if candidate.blocked:
        raise InvalidDecision("A blocked candidate cannot be recommended or accepted", code="CANDIDATE_BLOCKED")
    if candidate.confidence in (None, "INSUFFICIENT_EVIDENCE"):
        raise InvalidDecision("A candidate with insufficient evidence cannot be recommended or accepted",
                              code="INSUFFICIENT_EVIDENCE")


__all__ = ["PERMISSION", "TARGET", "Decision", "InvalidDecision", "allowed", "check_candidate", "next_status"]

"""Accepted-risk and trusted-component policy rules (FR-SCA-004, FR-SCA-005).

Pure domain logic (NFR-SCA-009): validate a rules document, then evaluate it
against one component version's facts. Persistence, scoping and versioning
live in :mod:`.policy_service`; this module never touches the database.

Every evaluation returns the policy version id and the per-criterion trace,
so the UI can explain *why* a component qualifies (US-SCA-03/04) and a
classification is always traceable to the exact version that produced it.

Hard rules encoded here:

* Accepted risk can never cover CRITICAL or HIGH findings
  (``max_actionable_severity`` ≤ MEDIUM) — they outrank everything except
  themselves (decision 2026-10-01) — nor a version with review reasons.
* Trust always requires an acceptable-risk and a lifecycle criterion. Tenant
  adoption (``min_tenant_products``) is an optional *additional* criterion and
  can never grant trust on its own (T9).
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta
from enum import Enum
from typing import Any

from .classification import SEVERITY_RANK, AcceptedRiskOutcome, RiskClassification
from .lifecycle_mapping import LifecycleBucket


class PolicyKind(str, Enum):
    ACCEPTED_RISK = "ACCEPTED_RISK"
    TRUST = "TRUST"


class PolicyStatus(str, Enum):
    """Status carried by each immutable version.

    * ACTIVE — the version's rules apply.
    * DISABLED — no policy for this scope; a tenant DISABLED also stops the
      platform default from applying to that tenant.
    * INHERIT — tenant only: the override is withdrawn and the platform
      default applies again. This is the append-only form of "reset".
    """

    ACTIVE = "ACTIVE"
    DISABLED = "DISABLED"
    INHERIT = "INHERIT"


class PolicyValidationError(ValueError):
    """The rules document is invalid. Routers map it to HTTP 422."""


ACCEPTABLE_MAX_SEVERITIES = ("MEDIUM", "LOW")
ACTIONABLE_VEX = ("AFFECTED", "UNDER_INVESTIGATION")
#: Classifications a trust policy may allow. Critical/High, Review Required and
#: Unknown can never be trusted: they are not an "acceptable current risk".
TRUSTABLE_CLASSIFICATIONS = (
    RiskClassification.NO_KNOWN_ACTIONABLE_VULNERABILITIES,
    RiskClassification.ACCEPTED_RISK,
    RiskClassification.LOW,
    RiskClassification.MEDIUM,
)


@dataclass(frozen=True)
class PolicyVersionRef:
    """A resolved, effective policy version."""

    id: int
    policy_id: int
    kind: PolicyKind
    version: int
    status: PolicyStatus
    scope: str  # "TENANT" or "PLATFORM"
    rules: dict[str, Any]
    created_at: str | None = None

    @property
    def active(self) -> bool:
        return self.status is PolicyStatus.ACTIVE

    def to_dict(self) -> dict[str, Any]:
        return {
            "id": self.id,
            "policy_id": self.policy_id,
            "kind": self.kind.value,
            "version": self.version,
            "status": self.status.value,
            "scope": self.scope,
            "rules": dict(self.rules),
            "created_at": self.created_at,
        }


@dataclass(frozen=True)
class ComponentFacts:
    """What a policy may look at for one unique component version."""

    classification: RiskClassification
    highest_actionable_severity: str | None
    max_actionable_cvss: float | None
    actionable_vulnerability_count: int
    actionable_vex_statuses: frozenset[str]
    lifecycle: LifecycleBucket
    latest_analysis_at: str | None
    has_review_reasons: bool
    licenses: tuple[str, ...] = ()
    product_count: int = 0


@dataclass(frozen=True)
class Criterion:
    name: str
    passed: bool
    detail: str

    def to_dict(self) -> dict[str, Any]:
        return {"criterion": self.name, "passed": self.passed, "detail": self.detail}


@dataclass(frozen=True)
class TrustOutcome:
    trusted: bool
    policy_version_id: int | None
    criteria: tuple[Criterion, ...] = field(default_factory=tuple)


# ---------------------------------------------------------------------------
# Validation
# ---------------------------------------------------------------------------


def _optional_number(rules, key, *, minimum, maximum=None, integer=False):
    value = rules.get(key)
    if value is None:
        return None
    if isinstance(value, bool) or not isinstance(value, (int, float)) or (integer and not isinstance(value, int)):
        raise PolicyValidationError(f"{key} must be a{'n integer' if integer else ' number'}")
    if value < minimum or (maximum is not None and value > maximum):
        raise PolicyValidationError(f"{key} must be between {minimum} and {maximum if maximum is not None else '∞'}")
    return value


def _enum_list(rules, key, enum_cls, *, required=False, allowed=None):
    value = rules.get(key)
    if value is None:
        if required:
            raise PolicyValidationError(f"{key} is required")
        return None
    if not isinstance(value, list) or (required and not value):
        raise PolicyValidationError(f"{key} must be a {'non-empty ' if required else ''}list")
    out = []
    for item in value:
        try:
            member = enum_cls(str(item).strip().upper())
        except ValueError as exc:
            raise PolicyValidationError(f"{key} contains unknown value {item!r}") from exc
        if allowed is not None and member not in allowed:
            raise PolicyValidationError(f"{key} may not contain {member.value}")
        out.append(member.value)
    return sorted(set(out))


def _string_list(rules, key):
    value = rules.get(key)
    if value is None:
        return None
    if not isinstance(value, list) or not all(isinstance(item, str) and item.strip() for item in value):
        raise PolicyValidationError(f"{key} must be a list of non-empty strings")
    return sorted({item.strip() for item in value}, key=str.lower)


def validate_accepted_risk_rules(rules: dict[str, Any]) -> dict[str, Any]:
    """Normalized accepted-risk rules or :class:`PolicyValidationError`."""
    if not isinstance(rules, dict):
        raise PolicyValidationError("rules must be an object")
    known = {"max_actionable_severity", "max_cvss_score", "allowed_actionable_vex_statuses",
             "max_actionable_vulnerabilities", "allowed_lifecycle", "max_analysis_age_days"}
    unknown = sorted(set(rules) - known)
    if unknown:
        raise PolicyValidationError(f"Unknown accepted-risk rule(s): {', '.join(unknown)}")
    severity = str(rules.get("max_actionable_severity") or "").strip().upper()
    if severity not in ACCEPTABLE_MAX_SEVERITIES:
        raise PolicyValidationError("max_actionable_severity is required and must be MEDIUM or LOW")
    statuses = rules.get("allowed_actionable_vex_statuses", list(ACTIONABLE_VEX))
    if not isinstance(statuses, list) or not statuses or any(str(s).upper() not in ACTIONABLE_VEX for s in statuses):
        raise PolicyValidationError("allowed_actionable_vex_statuses must be a non-empty subset of AFFECTED, UNDER_INVESTIGATION")
    return {
        "max_actionable_severity": severity,
        "max_cvss_score": _optional_number(rules, "max_cvss_score", minimum=0, maximum=10),
        "allowed_actionable_vex_statuses": sorted({str(s).upper() for s in statuses}),
        "max_actionable_vulnerabilities": _optional_number(rules, "max_actionable_vulnerabilities", minimum=0, integer=True),
        "allowed_lifecycle": _enum_list(rules, "allowed_lifecycle", LifecycleBucket),
        "max_analysis_age_days": _optional_number(rules, "max_analysis_age_days", minimum=1, integer=True),
    }


def validate_trust_rules(rules: dict[str, Any]) -> dict[str, Any]:
    """Normalized trust rules. Adoption-only trust is impossible by construction."""
    if not isinstance(rules, dict):
        raise PolicyValidationError("rules must be an object")
    known = {"allowed_classifications", "allowed_lifecycle", "allowed_licenses", "denied_licenses",
             "max_evidence_age_days", "min_tenant_products", "require_no_review_reasons"}
    unknown = sorted(set(rules) - known)
    if unknown:
        raise PolicyValidationError(f"Unknown trust rule(s): {', '.join(unknown)}")
    review = rules.get("require_no_review_reasons", True)
    if not isinstance(review, bool):
        raise PolicyValidationError("require_no_review_reasons must be true or false")
    return {
        "allowed_classifications": _enum_list(
            rules, "allowed_classifications", RiskClassification, required=True, allowed=TRUSTABLE_CLASSIFICATIONS
        ),
        "allowed_lifecycle": _enum_list(rules, "allowed_lifecycle", LifecycleBucket, required=True),
        "allowed_licenses": _string_list(rules, "allowed_licenses"),
        "denied_licenses": _string_list(rules, "denied_licenses"),
        "max_evidence_age_days": _optional_number(rules, "max_evidence_age_days", minimum=1, integer=True),
        "min_tenant_products": _optional_number(rules, "min_tenant_products", minimum=1, integer=True),
        "require_no_review_reasons": review,
    }


def validate_rules(kind: PolicyKind, rules: dict[str, Any]) -> dict[str, Any]:
    if kind is PolicyKind.ACCEPTED_RISK:
        return validate_accepted_risk_rules(rules)
    return validate_trust_rules(rules)


# ---------------------------------------------------------------------------
# Evaluation
# ---------------------------------------------------------------------------


def _age_days(timestamp: str | None, now: datetime) -> float | None:
    if not timestamp:
        return None
    try:
        parsed = datetime.fromisoformat(str(timestamp).replace("Z", "+00:00"))
    except ValueError:
        return None
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=UTC)
    return (now - parsed) / timedelta(days=1)


def _freshness(name: str, limit: int | None, facts: ComponentFacts, now: datetime) -> Criterion | None:
    if limit is None:
        return None
    age = _age_days(facts.latest_analysis_at, now)
    if age is None:
        return Criterion(name, False, "No analysis timestamp; freshness cannot be shown")
    return Criterion(name, age <= limit, f"Latest analysis {age:.0f} day(s) old; limit {limit}")


def evaluate_accepted_risk(
    version: PolicyVersionRef, facts: ComponentFacts, *, now: datetime | None = None
) -> AcceptedRiskOutcome:
    """Does the version satisfy the accepted-risk policy? Never for Critical/High."""
    now = now or datetime.now(UTC)
    rules = version.rules
    criteria: list[Criterion] = []
    highest = facts.highest_actionable_severity
    if highest is None:
        criteria.append(Criterion("ACTIONABLE_FINDINGS_PRESENT", False, "No actionable findings; nothing to accept"))
    else:
        limit = rules["max_actionable_severity"]
        criteria.append(Criterion(
            "MAX_ACTIONABLE_SEVERITY",
            highest != "UNKNOWN" and SEVERITY_RANK[highest] <= SEVERITY_RANK[limit],
            f"Highest actionable severity {highest}; limit {limit}",
        ))
    criteria.append(Criterion(
        "NO_REVIEW_REASONS", not facts.has_review_reasons,
        "Evidence needs review; it cannot be accepted" if facts.has_review_reasons else "No review reasons",
    ))
    if rules.get("max_cvss_score") is not None:
        score = facts.max_actionable_cvss
        criteria.append(Criterion(
            "MAX_CVSS_SCORE",
            score is not None and score <= rules["max_cvss_score"],
            f"Highest actionable CVSS {score if score is not None else 'unavailable'}; limit {rules['max_cvss_score']}",
        ))
    allowed_vex = set(rules["allowed_actionable_vex_statuses"])
    outside = sorted(facts.actionable_vex_statuses - allowed_vex)
    criteria.append(Criterion(
        "ALLOWED_VEX_STATUSES", not outside,
        f"Actionable VEX statuses {sorted(facts.actionable_vex_statuses)}; allowed {sorted(allowed_vex)}",
    ))
    if rules.get("max_actionable_vulnerabilities") is not None:
        criteria.append(Criterion(
            "MAX_ACTIONABLE_VULNERABILITIES",
            facts.actionable_vulnerability_count <= rules["max_actionable_vulnerabilities"],
            f"{facts.actionable_vulnerability_count} actionable; limit {rules['max_actionable_vulnerabilities']}",
        ))
    if rules.get("allowed_lifecycle"):
        criteria.append(Criterion(
            "ALLOWED_LIFECYCLE", facts.lifecycle.value in rules["allowed_lifecycle"],
            f"Lifecycle {facts.lifecycle.value}; allowed {rules['allowed_lifecycle']}",
        ))
    freshness = _freshness("ANALYSIS_FRESHNESS", rules.get("max_analysis_age_days"), facts, now)
    if freshness:
        criteria.append(freshness)

    satisfied = all(c.passed for c in criteria)
    return AcceptedRiskOutcome(
        satisfied=satisfied,
        policy_version_id=version.id,
        reasons=tuple(c.name for c in criteria if c.passed),
        failures=tuple(c.name for c in criteria if not c.passed),
        criteria=tuple(c.to_dict() for c in criteria),
    )


def _license_criteria(rules, licenses: tuple[str, ...]) -> list[Criterion]:
    out = []
    lowered = {item.lower() for item in licenses}
    if rules.get("denied_licenses"):
        hit = sorted(item for item in rules["denied_licenses"] if item.lower() in lowered)
        out.append(Criterion("NO_DENIED_LICENSE", not hit, f"Denied licenses present: {hit}" if hit else "No denied license"))
    if rules.get("allowed_licenses"):
        allowed = {item.lower() for item in rules["allowed_licenses"]}
        if not licenses:
            out.append(Criterion("ALLOWED_LICENSE", False, "No license declared; cannot confirm it is allowed"))
        else:
            outside = sorted(item for item in licenses if item.lower() not in allowed)
            out.append(Criterion("ALLOWED_LICENSE", not outside, f"Licenses outside the allow list: {outside}" if outside else "All licenses allowed"))
    return out


def evaluate_trust(version: PolicyVersionRef, facts: ComponentFacts, *, now: datetime | None = None) -> TrustOutcome:
    """Is the version trusted by policy? Adoption alone never suffices (T9)."""
    now = now or datetime.now(UTC)
    rules = version.rules
    criteria = [
        Criterion(
            "ACCEPTABLE_CURRENT_RISK", facts.classification.value in rules["allowed_classifications"],
            f"Classification {facts.classification.value}; allowed {rules['allowed_classifications']}",
        ),
        Criterion(
            "SUPPORTED_LIFECYCLE", facts.lifecycle.value in rules["allowed_lifecycle"],
            f"Lifecycle {facts.lifecycle.value}; allowed {rules['allowed_lifecycle']}",
        ),
    ]
    if rules.get("require_no_review_reasons", True):
        criteria.append(Criterion("NO_REVIEW_REASONS", not facts.has_review_reasons, "Review reasons present" if facts.has_review_reasons else "No review reasons"))
    criteria.extend(_license_criteria(rules, facts.licenses))
    freshness = _freshness("EVIDENCE_FRESHNESS", rules.get("max_evidence_age_days"), facts, now)
    if freshness:
        criteria.append(freshness)
    if rules.get("min_tenant_products") is not None:
        criteria.append(Criterion(
            "MIN_TENANT_ADOPTION", facts.product_count >= rules["min_tenant_products"],
            f"Used by {facts.product_count} product(s); minimum {rules['min_tenant_products']} (contextual evidence only)",
        ))
    return TrustOutcome(trusted=all(c.passed for c in criteria), policy_version_id=version.id, criteria=tuple(criteria))


__all__ = [
    "ACCEPTABLE_MAX_SEVERITIES",
    "TRUSTABLE_CLASSIFICATIONS",
    "ComponentFacts",
    "Criterion",
    "PolicyKind",
    "PolicyStatus",
    "PolicyValidationError",
    "PolicyVersionRef",
    "TrustOutcome",
    "evaluate_accepted_risk",
    "evaluate_trust",
    "validate_accepted_risk_rules",
    "validate_rules",
    "validate_trust_rules",
]

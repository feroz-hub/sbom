"""Transparent, versioned candidate scoring (FR-SCA-017, US-SCA-12).

Pure logic. The score **orders candidates only**: it is never a "safety
score", it never makes a candidate acceptable, and it never overrides a
blocking compatibility check — blocked candidates always rank after every
unblocked one of the same kind, whatever their score (FR-SCA-015, T24/T25).

Weights come from the effective SCORING policy version (tenant override →
platform default); with none configured, the documented built-in default
:data:`DEFAULT_SCORING_RULES` applies and is labelled as such. Every factor
records its policy version, raw value, normalized value, weight, weighted
contribution, missing-data treatment, evidence source and evidence time.

Default weights (phase0-analysis.md §10, proposed for review):

==================== ======
current_risk          0.30
lifecycle             0.20
vulnerability_trend   0.15
compatibility         0.15
maintenance           0.08
license               0.05
tenant_adoption       0.05
evidence_freshness    0.02
==================== ======
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import UTC, datetime
from typing import Any

from ..policy import PolicyValidationError, PolicyVersionRef

FACTORS = (
    "current_risk", "lifecycle", "vulnerability_trend", "compatibility",
    "maintenance", "license", "tenant_adoption", "evidence_freshness",
)
BUILTIN_LABEL = "builtin-default-2026-10-01"
DEFAULT_SCORING_RULES: dict[str, Any] = {
    "weights": {
        "current_risk": 0.30, "lifecycle": 0.20, "vulnerability_trend": 0.15, "compatibility": 0.15,
        "maintenance": 0.08, "license": 0.05, "tenant_adoption": 0.05, "evidence_freshness": 0.02,
    },
    # PENALIZE: a missing factor scores 0 (absence of evidence never helps).
    # EXCLUDE: a missing factor's weight is dropped and the rest renormalized.
    "missing_data": "PENALIZE",
    "history_window_months": 24,
    "stale_after_days": 90,
}

_RISK_VALUE = {
    "NO_KNOWN_ACTIONABLE_VULNERABILITIES": 1.0, "ACCEPTED_RISK": 0.8, "LOW": 0.7, "MEDIUM": 0.5,
    "REVIEW_REQUIRED": 0.3, "HIGH": 0.2, "CRITICAL": 0.0,
}
_LIFECYCLE_VALUE = {"SUPPORTED": 1.0, "MAINTENANCE": 0.6, "EOS": 0.2, "EOL": 0.0}
_LICENSE_VALUE = {"PASS": 1.0, "REVIEW_REQUIRED": 0.5, "FAIL": 0.0}


def validate_scoring_rules(rules: dict[str, Any]) -> dict[str, Any]:
    if not isinstance(rules, dict):
        raise PolicyValidationError("rules must be an object")
    unknown = sorted(set(rules) - set(DEFAULT_SCORING_RULES))
    if unknown:
        raise PolicyValidationError(f"Unknown scoring rule(s): {', '.join(unknown)}")
    weights = rules.get("weights", DEFAULT_SCORING_RULES["weights"])
    if not isinstance(weights, dict) or set(weights) - set(FACTORS):
        raise PolicyValidationError(f"weights may only contain: {', '.join(FACTORS)}")
    if any(isinstance(w, bool) or not isinstance(w, (int, float)) or w < 0 for w in weights.values()):
        raise PolicyValidationError("weights must be non-negative numbers")
    if sum(weights.values()) <= 0:
        raise PolicyValidationError("at least one weight must be positive")
    missing = str(rules.get("missing_data", "PENALIZE")).upper()
    if missing not in ("PENALIZE", "EXCLUDE"):
        raise PolicyValidationError("missing_data must be PENALIZE or EXCLUDE")
    window = rules.get("history_window_months", 24)
    stale = rules.get("stale_after_days", 90)
    if not isinstance(window, int) or not 6 <= window <= 120:
        raise PolicyValidationError("history_window_months must be an integer from 6 to 120")
    if not isinstance(stale, int) or not 1 <= stale <= 3650:
        raise PolicyValidationError("stale_after_days must be an integer from 1 to 3650")
    return {"weights": {f: float(weights.get(f, 0.0)) for f in FACTORS}, "missing_data": missing,
            "history_window_months": window, "stale_after_days": stale}


@dataclass(frozen=True)
class ScoringPolicy:
    rules: dict[str, Any]
    policy_version_id: int | None
    label: str

    @classmethod
    def resolve(cls, ref: PolicyVersionRef | None) -> ScoringPolicy:
        if ref is None:
            return cls(validate_scoring_rules(DEFAULT_SCORING_RULES), None, BUILTIN_LABEL)
        return cls(validate_scoring_rules(ref.rules), ref.id, f"{ref.scope.lower()}-v{ref.version}")

    def to_dict(self) -> dict[str, Any]:
        return {"policy_version_id": self.policy_version_id, "label": self.label, "rules": dict(self.rules)}


@dataclass(frozen=True)
class Factor:
    factor: str
    raw_value: Any
    normalized_value: float | None
    weight: float
    contribution: float
    missing_data_treatment: str | None
    evidence_source: str
    evidence_at: str | None

    def to_dict(self, policy: ScoringPolicy) -> dict[str, Any]:
        return {
            "factor": self.factor, "raw_value": self.raw_value, "normalized_value": self.normalized_value,
            "weight": self.weight, "contribution": round(self.contribution, 6),
            "missing_data_treatment": self.missing_data_treatment, "evidence_source": self.evidence_source,
            "evidence_at": self.evidence_at, "policy_version_id": policy.policy_version_id,
            "policy_version_label": policy.label,
        }


def _age_days(timestamp: str | None, now: datetime) -> float | None:
    if not timestamp:
        return None
    try:
        parsed = datetime.fromisoformat(str(timestamp).replace("Z", "+00:00"))
    except ValueError:
        return None
    return (now - (parsed if parsed.tzinfo else parsed.replace(tzinfo=UTC))).total_seconds() / 86400


def raw_factors(evaluation: dict[str, Any], *, now: datetime | None = None) -> dict[str, tuple[Any, float | None, str, str | None]]:
    """``{factor: (raw, normalized or None, evidence_source, evidence_at)}`` from a candidate evaluation."""
    now = now or datetime.now(UTC)
    posture = evaluation.get("current_posture", {})
    lifecycle = evaluation.get("lifecycle", {})
    history = evaluation.get("history", {})
    compat = evaluation.get("compatibility", {})
    freshness = evaluation.get("freshness", {})
    adoption = evaluation.get("adoption", {})
    checks = {c["check_type"]: c for c in evaluation.get("compatibility_checks", [])}
    out: dict[str, tuple[Any, float | None, str, str | None]] = {}

    classification = posture.get("classification") if posture.get("status") == "OBSERVED" else None
    out["current_risk"] = (classification, _RISK_VALUE.get(classification), "TENANT_ANALYSIS",
                           freshness.get("latest_analysis_at"))
    bucket = lifecycle.get("bucket")
    out["lifecycle"] = (bucket, _LIFECYCLE_VALUE.get(bucket), "LIFECYCLE_ENRICHMENT", freshness.get("lifecycle_checked_at"))
    if history.get("status") in ("AVAILABLE", "NO_VULNERABILITIES_IN_COVERED_WINDOW"):
        crit_high, total = history.get("critical_high_count", 0), history.get("disclosed_vulnerability_count", 0)
        trend = 1.0 / (1.0 + crit_high + 0.25 * (total - crit_high))
        out["vulnerability_trend"] = ({"critical_high": crit_high, "disclosed": total,
                                       "covered_months": history["coverage"]["covered_months"]},
                                      round(trend, 4), "HISTORY:" + "+".join(
                                          s["source"] for s in history["coverage"]["sources"] if s["status"] == "AVAILABLE"),
                                      history.get("window_end"))
    else:
        out["vulnerability_trend"] = (None, None, "HISTORY", None)
    counts = compat.get("counts") or {}
    known = counts.get("PASS", 0) + counts.get("REVIEW_REQUIRED", 0) + counts.get("FAIL", 0)
    if compat.get("blocked"):
        out["compatibility"] = (counts, 0.0, "COMPATIBILITY_CHECKS", None)
    elif known:
        out["compatibility"] = (counts, round((counts.get("PASS", 0) + 0.5 * counts.get("REVIEW_REQUIRED", 0)) / known, 4),
                                "COMPATIBILITY_CHECKS", None)
    else:
        out["compatibility"] = (counts, None, "COMPATIBILITY_CHECKS", None)
    # No release-cadence / maintainer-health source exists yet (Step 6 limitation).
    out["maintenance"] = (None, None, "RELEASE_METADATA", None)
    license_result = (checks.get("LICENSE") or {}).get("result")
    out["license"] = (license_result, _LICENSE_VALUE.get(license_result), "COMPATIBILITY_CHECKS:LICENSE", None)
    products = adoption.get("product_count", 0) or 0
    out["tenant_adoption"] = (products, round(min(products / 5.0, 1.0), 4), "TENANT_ANALYSIS", freshness.get("latest_analysis_at"))
    age = _age_days(freshness.get("latest_analysis_at"), now)
    fresh = None if age is None else 1.0 if age <= 30 else 0.6 if age <= 90 else 0.3 if age <= 180 else 0.0
    out["evidence_freshness"] = (None if age is None else round(age, 1), fresh, "TENANT_ANALYSIS", freshness.get("latest_analysis_at"))
    return out


def score_candidate(evaluation: dict[str, Any], policy: ScoringPolicy, *, now: datetime | None = None) -> tuple[float, list[Factor]]:
    """Score 0–100 plus the factor breakdown. Orders candidates only."""
    weights = policy.rules["weights"]
    raws = raw_factors(evaluation, now=now)
    total_weight = sum(weights.values())
    if policy.rules["missing_data"] == "EXCLUDE":
        total_weight = sum(weights[f] for f in FACTORS if raws[f][1] is not None) or total_weight
    factors, score = [], 0.0
    for name in FACTORS:
        raw, normalized, source, at = raws[name]
        weight = weights[name] / total_weight if total_weight else 0.0
        treatment = None
        if normalized is None:
            treatment = policy.rules["missing_data"]
            contribution = 0.0
            weight = 0.0 if treatment == "EXCLUDE" else weight
        else:
            contribution = normalized * weight
        score += contribution
        factors.append(Factor(name, raw, normalized, round(weight, 6), contribution, treatment, source, at))
    return round(score * 100, 2), factors


__all__ = ["BUILTIN_LABEL", "DEFAULT_SCORING_RULES", "FACTORS", "Factor", "ScoringPolicy", "raw_factors",
           "score_candidate", "validate_scoring_rules"]

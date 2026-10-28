"""Recommendation confidence and freshness (FR-SCA-019, FR-SCA-020, US-SCA-13).

Pure logic. Confidence is HIGH | MEDIUM | LOW | INSUFFICIENT_EVIDENCE and is
derived from evidence *completeness and freshness*, never from rank or score.

* ``completeness`` — share of scoring weight backed by real evidence.
* Material compatibility evidence — LICENSE, LIFECYCLE, FUNCTIONAL_PURPOSE,
  PRODUCT_CONSTRAINTS, API_COMPATIBILITY. Each UNKNOWN lowers confidence;
  any missing material evidence also rules out a drop-in representation.
* Freshness — stale analysis or lifecycle evidence lowers confidence by one
  level and is flagged; unavailable evidence never silently passes.

Rules (documented for review):

* INSUFFICIENT_EVIDENCE — posture not observed *and* no history coverage, or
  completeness < 0.40.
* HIGH — completeness ≥ 0.85, posture observed, no UNKNOWN material check,
  fresh evidence.
* MEDIUM — completeness ≥ 0.60 with observed posture or history, at most one
  UNKNOWN material check.
* LOW — otherwise.
* Stale → one level down (HIGH → MEDIUM → LOW; LOW stays LOW).
"""

from __future__ import annotations

from datetime import UTC, datetime
from typing import Any

MATERIAL_CHECKS = ("LICENSE", "LIFECYCLE", "FUNCTIONAL_PURPOSE", "PRODUCT_CONSTRAINTS", "API_COMPATIBILITY")
LEVELS = ("INSUFFICIENT_EVIDENCE", "LOW", "MEDIUM", "HIGH")


def _age_days(value: str | None, now: datetime) -> float | None:
    if not value:
        return None
    try:
        parsed = datetime.fromisoformat(str(value).replace("Z", "+00:00"))
    except ValueError:
        return None
    return (now - (parsed if parsed.tzinfo else parsed.replace(tzinfo=UTC))).total_seconds() / 86400


def freshness_view(evaluation: dict[str, Any], *, source_freshness: dict[str, Any], stale_after_days: int,
                   now: datetime | None = None) -> dict[str, Any]:
    """Timestamps and stale flags for every evidence stream (FR-SCA-020)."""
    now = now or datetime.now(UTC)
    fresh = dict(evaluation.get("freshness") or {})
    history = evaluation.get("history") or {}
    stale = []
    analysis_age = _age_days(fresh.get("latest_analysis_at"), now)
    if analysis_age is None:
        stale.append("ANALYSIS_EVIDENCE_UNAVAILABLE")
    elif analysis_age > stale_after_days:
        stale.append("ANALYSIS_EVIDENCE_STALE")
    lifecycle_age = _age_days(fresh.get("lifecycle_checked_at"), now)
    if lifecycle_age is not None and lifecycle_age > stale_after_days:
        stale.append("LIFECYCLE_EVIDENCE_STALE")
    return {
        "latest_sbom_analysis_at": fresh.get("latest_analysis_at"),
        "tenant_observation_at": fresh.get("latest_analysis_at"),
        "vulnerability_source_refreshed_at": source_freshness.get("nvd_mirror_last_success_at"),
        "package_metadata_refreshed_at": fresh.get("external_retrieved_at"),
        "lifecycle_refreshed_at": fresh.get("lifecycle_checked_at"),
        "observation_window": {"months": history.get("window_months"), "start": history.get("window_start"),
                               "end": history.get("window_end"),
                               "covered_months": (history.get("coverage") or {}).get("covered_months")},
        "stale_after_days": stale_after_days,
        "stale_flags": stale,
    }


def confidence(evaluation: dict[str, Any], factors: list, freshness: dict[str, Any], *, weights: dict[str, float]) -> dict[str, Any]:
    # Policy weights, not the renormalized ones: under EXCLUDE a missing factor
    # gets weight 0, which would otherwise make completeness always 1.0.
    total = sum(weights.values()) or 1.0
    completeness = round(sum(weights.get(f.factor, 0.0) for f in factors if f.normalized_value is not None) / total, 4)
    observed = (evaluation.get("current_posture") or {}).get("status") == "OBSERVED"
    history_ok = (evaluation.get("history") or {}).get("status") in ("AVAILABLE", "NO_VULNERABILITIES_IN_COVERED_WINDOW")
    checks = {c["check_type"]: c for c in evaluation.get("compatibility_checks", [])}
    unknown_material = sorted(t for t in MATERIAL_CHECKS if (checks.get(t) or {}).get("result") == "UNKNOWN")
    stale = [flag for flag in freshness.get("stale_flags", []) if flag.endswith("_STALE")]

    reasons = []
    if (not observed and not history_ok) or completeness < 0.40:
        level = "INSUFFICIENT_EVIDENCE"
        reasons.append("POSTURE_AND_HISTORY_UNAVAILABLE" if not observed and not history_ok else "LOW_EVIDENCE_COMPLETENESS")
    elif completeness >= 0.85 and observed and not unknown_material and not stale:
        level = "HIGH"
    elif completeness >= 0.60 and (observed or history_ok) and len(unknown_material) <= 1:
        level = "MEDIUM"
    else:
        level = "LOW"
    if unknown_material:
        reasons.append("MATERIAL_COMPATIBILITY_EVIDENCE_MISSING")
    if stale and level in ("HIGH", "MEDIUM"):
        level = LEVELS[LEVELS.index(level) - 1]
        reasons.append("STALE_EVIDENCE")
    return {
        "level": level,
        "completeness": completeness,
        "posture_observed": observed,
        "history_available": history_ok,
        "unknown_material_checks": unknown_material,
        "stale_flags": stale,
        "reasons": reasons,
        # A drop-in claim needs every material check evidenced (FR-SCA-019).
        "drop_in_representable": not unknown_material and not (evaluation.get("compatibility") or {}).get("blocked")
        and (evaluation.get("compatibility") or {}).get("drop_in_representable", False),
    }


__all__ = ["LEVELS", "MATERIAL_CHECKS", "confidence", "freshness_view"]

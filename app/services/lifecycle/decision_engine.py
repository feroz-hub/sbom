"""Deterministic lifecycle and VEX decision rules."""

from __future__ import annotations

from .types import (
    DEPRECATED,
    EOF,
    EOL,
    EOL_SOON,
    EOS,
    POSSIBLY_UNMAINTAINED,
    SUPPORTED,
    UNKNOWN,
    UNSUPPORTED,
    LifecycleResult,
    VexResult,
)

LIFECYCLE_PRIORITY = {
    EOL: 90,
    EOS: 85,
    EOF: 80,
    DEPRECATED: 70,
    UNSUPPORTED: 65,
    EOL_SOON: 60,
    POSSIBLY_UNMAINTAINED: 30,
    SUPPORTED: 10,
    UNKNOWN: 0,
}

CONFIDENCE_PRIORITY = {"High": 3, "Medium": 2, "Low": 1, "Unknown": 0}

VEX_PRIORITY = {
    "affected": 90,
    "fixed": 80,
    "under_investigation": 60,
    "not_affected": 50,
    "unknown": 0,
}


def choose_lifecycle_result(results: list[LifecycleResult]) -> LifecycleResult | None:
    """Choose the highest-priority lifecycle result without inventing evidence."""
    if not results:
        return None
    manual = next((result for result in results if result.manual_override), None)
    if manual:
        return manual

    actionable = [result.canonicalized() for result in results if result.is_actionable]
    if not actionable:
        return None

    vendor = next(
        (
            result
            for result in actionable
            if isinstance(result.evidence, dict) and result.evidence.get("authority") == "vendor"
        ),
        None,
    )
    if vendor:
        return _merge_recommendations(vendor, actionable)

    chosen = max(
        actionable,
        key=lambda result: (
            LIFECYCLE_PRIORITY.get(result.lifecycle_status, 0),
            CONFIDENCE_PRIORITY.get(result.confidence, 0),
        ),
    )
    return _merge_recommendations(chosen, actionable)


def _merge_recommendations(chosen: LifecycleResult, results: list[LifecycleResult]) -> LifecycleResult:
    for result in results:
        if result is chosen:
            continue
        if result.recommended_version and not chosen.recommended_version:
            chosen.recommended_version = result.recommended_version
        if result.latest_version and not chosen.latest_version:
            chosen.latest_version = result.latest_version
        if result.recommendation and not chosen.recommendation:
            chosen.recommendation = result.recommendation
        if result.vulnerability_count is not None and chosen.vulnerability_count is None:
            chosen.vulnerability_count = result.vulnerability_count
        if result.evidence and result.source_name:
            chosen.evidence = {**chosen.evidence, result.source_name: result.evidence}
    return chosen.canonicalized()


def choose_vex_result(results: list[VexResult]) -> VexResult | None:
    """Choose VEX result by explicit exploitability priority."""
    if not results:
        return None
    return max(results, key=lambda result: VEX_PRIORITY.get(result.vex_status, 0))


__all__ = ["choose_lifecycle_result", "choose_vex_result"]

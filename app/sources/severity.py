"""
CVSS / severity helpers.

Canonical extraction from ``app/analysis.py``. ``sev_bucket`` accepts a
loosely-typed ``settings`` object — anything with the four CVSS threshold
attributes used here. This deliberately avoids importing
``app.analysis.AnalysisSettings`` to keep the new package free of cycles
back into the legacy module. Phase 2 source adapters will pass their own
config object that satisfies this duck-typed contract.
"""

from __future__ import annotations

from typing import Any


def safe_score(value: Any) -> float | None:
    """Coerce a CVSS score-like value to ``float``, returning ``None`` on failure."""
    if value is None:
        return None
    try:
        return float(value)
    except (TypeError, ValueError):
        return None


def parse_cvss_attack_vector(vector: str | None) -> str | None:
    """Extract the AV: component from a CVSS vector string."""
    if not vector:
        return None
    for part in (vector or "").split("/"):
        if part.startswith("AV:"):
            return {
                "N": "Network",
                "A": "Adjacent",
                "L": "Local",
                "P": "Physical",
            }.get(part[3:], part[3:])
    return None


def cvss_version_from_metrics(metrics: dict[str, Any]) -> str | None:
    """Return ``'V40'``, ``'V31'``, or ``'V2'`` based on which metric key has data."""
    for key, label in (
        ("cvssMetricV40", "V40"),
        ("cvssMetricV31", "V31"),
        ("cvssMetricV30", "V31"),
        ("cvssMetricV2", "V2"),
    ):
        if metrics.get(key):
            return label
    return None


def extract_best_cvss(
    metrics: dict[str, Any],
) -> tuple[float | None, str | None, str | None]:
    """
    Pick the best available CVSS triple ``(score, vector, baseSeverity)``
    from an NVD-style metrics dict, preferring v4.0 → v3.1 → v3.0 → v2.
    """
    if not isinstance(metrics, dict):
        return None, None, None
    metric_keys = ("cvssMetricV40", "cvssMetricV31", "cvssMetricV30", "cvssMetricV2")
    for key in metric_keys:
        entries = metrics.get(key) or []
        if not entries:
            continue
        primary = next(
            (m for m in entries if str((m or {}).get("type", "")).lower() == "primary"),
            entries[0],
        )
        cvss_data = (primary or {}).get("cvssData") or {}
        score = safe_score(cvss_data.get("baseScore"))
        vector = cvss_data.get("vectorString")
        severity = (primary or {}).get("baseSeverity") or cvss_data.get("baseSeverity")
        return score, vector, severity
    return None, None, None


# GitHub Advisory severity normalisation: GraphQL returns "MODERATE" for medium.
GH_SEV_NORM: dict[str, str] = {
    "CRITICAL": "CRITICAL",
    "HIGH": "HIGH",
    "MODERATE": "MEDIUM",
    "MEDIUM": "MEDIUM",
    "LOW": "LOW",
    # Lowercase variants for defence-in-depth (callers may skip .upper())
    "critical": "CRITICAL",
    "high": "HIGH",
    "moderate": "MEDIUM",
    "medium": "MEDIUM",
    "low": "LOW",
}


def sev_bucket(
    score: float | None,
    settings: Any,
    severity_text: str | None = None,
) -> str:
    """
    Bucket a CVSS score into ``CRITICAL`` / ``HIGH`` / ``MEDIUM`` / ``LOW``
    using the thresholds on ``settings``. Falls back to a textual severity
    if no numeric score is available.

    ``settings`` is duck-typed: any object exposing
    ``cvss_critical_threshold``, ``cvss_high_threshold`` and
    ``cvss_medium_threshold`` works. This avoids importing the legacy
    ``AnalysisSettings`` dataclass.
    """
    if score is not None:
        if score >= settings.cvss_critical_threshold:
            return "CRITICAL"
        if score >= settings.cvss_high_threshold:
            return "HIGH"
        if score >= settings.cvss_medium_threshold:
            return "MEDIUM"
        return "LOW"
    if severity_text:
        text = severity_text.strip().upper()
        normalized = GH_SEV_NORM.get(text)
        if normalized:
            return normalized
    return "UNKNOWN"

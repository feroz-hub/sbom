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
    from .cvss_assessment import numeric_score
    return numeric_score(value)


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
    selected = nvd_assessment(metrics)
    return selected["version"] if selected else None


def nvd_assessment(metrics: dict[str, Any]) -> dict | None:
    from .cvss_assessment import VERSION_ORDER, assessment
    candidates = []
    for key, version in (("cvssMetricV31", "3.1"), ("cvssMetricV30", "3.0"),
                         ("cvssMetricV40", "4.0"), ("cvssMetricV2", "2.0")):
        for entry in metrics.get(key) or []:
            data = entry.get("cvssData") or {}
            selected = assessment(data.get("baseScore"), data.get("vectorString"), version, provider="NVD")
            if selected:
                candidates.append((entry, selected))
    return min(candidates, key=lambda item: (
        0 if item[0].get("source") == "nvd@nist.gov" else 1,
        0 if str(item[0].get("type", "")).lower() == "primary" else 1,
        VERSION_ORDER[item[1]["version"]], str(item[1]["vector"] or ""), item[1]["score"]))[1] if candidates else None


def extract_best_cvss(metrics: dict[str, Any]) -> tuple[float | None, str | None, str | None]:
    from .cvss_assessment import severity_for_score
    selected = nvd_assessment(metrics)
    return ((selected["score"], selected["vector"], severity_for_score(selected["score"]))
            if selected else (None, None, None))


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

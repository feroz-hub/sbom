# utils.py — Shared utilities for SBOM Analyzer API
from __future__ import annotations

from datetime import UTC, datetime
from typing import Any


def now_iso() -> str:
    """Return current UTC time as ISO 8601 string."""
    return datetime.now(UTC).replace(microsecond=0).isoformat()


def legacy_analysis_level() -> int:
    from .settings import get_analysis_legacy_level

    return get_analysis_legacy_level()


def safe_int(value: Any, default: int = 0) -> int:
    try:
        return int(value)
    except (TypeError, ValueError):
        return default


def safe_float(value: Any) -> float | None:
    try:
        if value is None:
            return None
        return float(value)
    except (TypeError, ValueError):
        return None


def normalized_key(value: str | None) -> str:
    return (value or "").strip().lower()


def compute_report_status(total_findings: int, query_errors: list[dict]) -> str:
    if total_findings > 0:
        return "FAIL"
    if query_errors:
        return "PARTIAL"
    return "PASS"


def normalize_details(details: dict | None, components: list[dict]) -> dict:
    """
    Preserve analyzer-provided totals if present; only compute from raw components
    as a fallback. Always recompute severity buckets from the 'findings' list.
    """
    data = dict(details or {})

    findings = data.get("findings")
    if not isinstance(findings, list):
        findings = []
    data["findings"] = findings

    query_errors = data.get("query_errors")
    if not isinstance(query_errors, list):
        query_errors = []
    data["query_errors"] = query_errors

    if "total_components" not in data or not isinstance(data["total_components"], int):
        data["total_components"] = len(components)

    if "components_with_cpe" not in data or not isinstance(data["components_with_cpe"], int):
        data["components_with_cpe"] = len({c.get("cpe") for c in components if c.get("cpe")})

    if "total_findings" not in data or not isinstance(data["total_findings"], int):
        data["total_findings"] = len(findings)

    buckets = {"critical": 0, "high": 0, "medium": 0, "low": 0, "unknown": 0}
    for f in findings:
        sev = str((f or {}).get("severity", "UNKNOWN")).upper()
        if sev == "CRITICAL":
            buckets["critical"] += 1
        elif sev == "HIGH":
            buckets["high"] += 1
        elif sev == "MEDIUM":
            buckets["medium"] += 1
        elif sev == "LOW":
            buckets["low"] += 1
        else:
            buckets["unknown"] += 1

    data["critical"] = buckets["critical"]
    data["high"] = buckets["high"]
    data["medium"] = buckets["medium"]
    data["low"] = buckets["low"]
    data["unknown"] = buckets["unknown"]
    return data

"""Canonical finding identity and run-level finding metrics.

User-facing finding totals are component-vulnerability findings:
one affected component plus one canonical vulnerability identity. Provider
observations remain available as a separate raw count when the run report
recorded them, but they are never the primary "Findings" total.
"""

from __future__ import annotations

import json
import re
from collections.abc import Iterable
from dataclasses import dataclass
from types import SimpleNamespace
from typing import Any

from ..models import AnalysisFinding, AnalysisRun

SEVERITY_ORDER = {"UNKNOWN": 0, "LOW": 1, "MEDIUM": 2, "HIGH": 3, "CRITICAL": 4}
SEVERITIES = ("CRITICAL", "HIGH", "MEDIUM", "LOW", "UNKNOWN")
_CVE_RE = re.compile(r"^CVE-\d{4}-\d{4,}$", re.IGNORECASE)
_GHSA_RE = re.compile(r"^GHSA-[0-9a-z]{4}-[0-9a-z]{4}-[0-9a-z]{4}$", re.IGNORECASE)


@dataclass(frozen=True)
class RunFindingMetrics:
    raw_observation_count: int
    total_findings: int
    unique_vulnerabilities: int
    ai_fix_eligible_findings: int
    severity_counts: dict[str, int]


def parse_json_list(value: Any) -> list[str]:
    if value is None:
        return []
    if isinstance(value, (list, tuple, set)):
        return [str(v).strip() for v in value if str(v).strip()]
    if not isinstance(value, str):
        return []
    raw = value.strip()
    if not raw:
        return []
    try:
        parsed = json.loads(raw)
    except (TypeError, ValueError):
        return [part.strip() for part in raw.split(",") if part.strip()]
    if isinstance(parsed, list):
        return [str(v).strip() for v in parsed if str(v).strip()]
    return []


def normalize_severity(value: Any) -> str:
    sev = str(value or "UNKNOWN").strip().upper()
    return sev if sev in SEVERITY_ORDER else "UNKNOWN"


def merge_severity(left: Any, right: Any) -> str:
    lval = normalize_severity(left)
    rval = normalize_severity(right)
    return rval if SEVERITY_ORDER[rval] > SEVERITY_ORDER[lval] else lval


def canonical_vulnerability_id(vuln_id: Any, aliases: Iterable[Any] | None = None) -> str:
    """Pick one canonical vulnerability identity from a provider id + aliases."""
    values: list[str] = []
    if vuln_id:
        values.append(str(vuln_id).strip())
    values.extend(str(alias).strip() for alias in (aliases or []) if str(alias).strip())

    upper_values = [v.upper() for v in values if v]
    for value in upper_values:
        if _CVE_RE.match(value):
            return value
    for value in upper_values:
        if _GHSA_RE.match(value):
            return value
    for value in upper_values:
        if value.startswith("OSV-"):
            return value
    return upper_values[0] if upper_values else "UNKNOWN-VULNERABILITY"


def component_identity_from_dict(finding: dict[str, Any]) -> str:
    component_id = finding.get("component_id")
    if component_id is not None:
        return f"id:{component_id}"
    purl = str(finding.get("purl") or "").strip().lower()
    if purl:
        return f"purl:{purl}"
    cpe = str(finding.get("cpe") or "").strip().lower()
    if cpe:
        return f"cpe:{cpe}"
    name = str(finding.get("normalized_name") or finding.get("component_name") or finding.get("name") or "").strip().lower()
    version = str(finding.get("component_version") or finding.get("version") or "").strip().lower()
    ecosystem = str(finding.get("ecosystem") or "").strip().lower()
    return f"component:{ecosystem}:{name}:{version}"


def component_identity_from_row(finding: Any) -> str:
    if finding.component_id is not None:
        return f"id:{finding.component_id}"
    if finding.cpe:
        return f"cpe:{finding.cpe.strip().lower()}"
    name = (finding.component_name or "").strip().lower()
    version = (finding.component_version or "").strip().lower()
    return f"component::{name}:{version}"


def canonical_finding_key_from_dict(finding: dict[str, Any]) -> tuple[str, str]:
    aliases = parse_json_list(finding.get("aliases"))
    return (
        component_identity_from_dict(finding),
        canonical_vulnerability_id(finding.get("vuln_id") or finding.get("id"), aliases),
    )


def canonical_finding_key_from_row(finding: Any) -> tuple[str, str]:
    aliases = parse_json_list(finding.aliases)
    return (
        component_identity_from_row(finding),
        canonical_vulnerability_id(finding.vuln_id, aliases),
    )


def _merge_string_lists(*values: Any) -> list[str]:
    merged: dict[str, str] = {}
    for value in values:
        for item in parse_json_list(value):
            key = item.upper() if item.upper().startswith(("CVE-", "GHSA-", "OSV-")) else item
            merged.setdefault(key, item)
    return sorted(merged.values(), key=lambda s: s.upper())


def _merge_sources(left: Any, right: Any) -> list[str]:
    values: list[str] = []
    for raw in (left, right):
        if isinstance(raw, (list, tuple, set)):
            values.extend(str(v).strip() for v in raw if str(v).strip())
        elif isinstance(raw, str):
            values.extend(part.strip() for part in raw.split(",") if part.strip())
    return sorted(set(values), key=lambda s: s.upper())


def deduplicate_finding_dicts(findings: Iterable[dict[str, Any]]) -> list[dict[str, Any]]:
    """Merge duplicate provider observations before persistence."""
    merged: dict[tuple[str, str], dict[str, Any]] = {}
    for finding in findings:
        if not isinstance(finding, dict):
            continue
        key = canonical_finding_key_from_dict(finding)
        canonical_id = key[1]
        if key not in merged:
            row = dict(finding)
            row["vuln_id"] = canonical_id
            row["aliases"] = _merge_string_lists(row.get("aliases"), finding.get("vuln_id"), finding.get("id"))
            row["sources"] = _merge_sources(row.get("sources"), row.get("source"))
            merged[key] = row
            continue

        existing = merged[key]
        existing["vuln_id"] = canonical_id
        existing["sources"] = _merge_sources(existing.get("sources"), finding.get("sources") or finding.get("source"))
        existing["aliases"] = _merge_string_lists(
            existing.get("aliases"),
            finding.get("aliases"),
            finding.get("vuln_id"),
            finding.get("id"),
        )
        existing["references"] = _merge_string_lists(existing.get("references"), finding.get("references"))
        existing["fixed_versions"] = _merge_string_lists(existing.get("fixed_versions"), finding.get("fixed_versions"))
        existing["cwe"] = _merge_string_lists(existing.get("cwe"), finding.get("cwe"))
        existing["severity"] = merge_severity(existing.get("severity"), finding.get("severity"))
        if finding.get("score") is not None and (
            existing.get("score") is None or float(finding.get("score") or 0) > float(existing.get("score") or 0)
        ):
            existing["score"] = finding.get("score")
        for field in (
            "title",
            "description",
            "url",
            "purl",
            "ecosystem",
            "normalized_name",
            "bom_ref",
            "package_type",
            "match_reason",
            "matched_range",
            "match_strategy",
            "match_confidence",
            "applicability_status",
            "attack_vector",
            "vector",
            "cvss_version",
        ):
            if not existing.get(field) and finding.get(field):
                existing[field] = finding[field]
    return list(merged.values())


def _finding_view(finding: AnalysisFinding) -> Any:
    return SimpleNamespace(
        id=finding.id,
        analysis_run_id=finding.analysis_run_id,
        component_id=finding.component_id,
        vuln_id=finding.vuln_id,
        source=finding.source,
        title=finding.title,
        description=finding.description,
        severity=finding.severity,
        score=finding.score,
        vector=finding.vector,
        published_on=finding.published_on,
        reference_url=finding.reference_url,
        cwe=finding.cwe,
        cpe=finding.cpe,
        component_name=finding.component_name,
        component_version=finding.component_version,
        fixed_versions=finding.fixed_versions,
        attack_vector=finding.attack_vector,
        cvss_version=finding.cvss_version,
        aliases=finding.aliases,
        match_reason=finding.match_reason,
        matched_range=finding.matched_range,
        match_strategy=finding.match_strategy,
        match_confidence=finding.match_confidence,
    )


def canonicalize_finding_rows(findings: Iterable[AnalysisFinding]) -> list[Any]:
    """Return representative rows merged by canonical component-vulnerability key."""
    grouped: dict[tuple[str, str], AnalysisFinding] = {}
    for finding in findings:
        key = canonical_finding_key_from_row(finding)
        existing = grouped.get(key)
        if existing is None:
            grouped[key] = _finding_view(finding)
            continue

        existing.source = ",".join(_merge_sources(existing.source, finding.source)) or existing.source
        existing.aliases = json.dumps(
            _merge_string_lists(existing.aliases, finding.aliases, existing.vuln_id, finding.vuln_id)
        )
        existing.fixed_versions = json.dumps(_merge_string_lists(existing.fixed_versions, finding.fixed_versions)) or None
        existing.cwe = ",".join(_merge_string_lists(existing.cwe, finding.cwe)) or existing.cwe
        existing.severity = merge_severity(existing.severity, finding.severity)
        if finding.score is not None and (existing.score is None or finding.score > existing.score):
            existing.score = finding.score
            existing.vector = finding.vector or existing.vector
            existing.cvss_version = finding.cvss_version or existing.cvss_version
        for field in ("title", "description", "reference_url", "published_on", "attack_vector", "match_reason", "matched_range", "match_strategy", "match_confidence"):
            if not getattr(existing, field, None) and getattr(finding, field, None):
                setattr(existing, field, getattr(finding, field))
    return list(grouped.values())


def _ai_fix_eligible(finding: Any) -> bool:
    return bool((finding.vuln_id or "").strip() and ((finding.component_name or "").strip() or finding.component_id is not None))


def _raw_observation_count(run: AnalysisRun | None, persisted_rows: int) -> int:
    candidates = [persisted_rows]
    if run is not None:
        candidates.append(int(run.total_findings or 0))
        try:
            report = json.loads(run.raw_report or "{}")
        except (TypeError, ValueError):
            report = {}
        if isinstance(report, dict):
            metadata = report.get("analysis_metadata") if isinstance(report.get("analysis_metadata"), dict) else {}
            for key in ("raw_observation_count", "raw_observations", "provider_observation_count"):
                value = metadata.get(key) if key in metadata else report.get(key)
                if isinstance(value, int):
                    candidates.append(value)
            findings = report.get("raw_findings")
            if isinstance(findings, list):
                candidates.append(len(findings))
            if isinstance(report.get("total_findings"), int):
                candidates.append(report["total_findings"])
    return max(candidates) if candidates else 0


def calculate_run_finding_metrics(
    findings: Iterable[AnalysisFinding],
    *,
    run: AnalysisRun | None = None,
) -> RunFindingMetrics:
    rows = list(findings)
    canonical_rows = canonicalize_finding_rows(rows)
    severity_counts = {sev.lower(): 0 for sev in SEVERITIES}
    unique_vulns: set[str] = set()
    ai_eligible = 0

    for finding in canonical_rows:
        severity_counts[normalize_severity(finding.severity).lower()] += 1
        unique_vulns.add(canonical_finding_key_from_row(finding)[1])
        if _ai_fix_eligible(finding):
            ai_eligible += 1

    return RunFindingMetrics(
        raw_observation_count=_raw_observation_count(run, len(rows)),
        total_findings=len(canonical_rows),
        unique_vulnerabilities=len(unique_vulns),
        ai_fix_eligible_findings=ai_eligible,
        severity_counts=severity_counts,
    )


def apply_metrics_to_run(run: AnalysisRun, metrics: RunFindingMetrics) -> None:
    run.total_findings = metrics.total_findings
    run.critical_count = metrics.severity_counts.get("critical", 0)
    run.high_count = metrics.severity_counts.get("high", 0)
    run.medium_count = metrics.severity_counts.get("medium", 0)
    run.low_count = metrics.severity_counts.get("low", 0)
    run.unknown_count = metrics.severity_counts.get("unknown", 0)


def metrics_to_dict(metrics: RunFindingMetrics) -> dict[str, Any]:
    return {
        "raw_observation_count": metrics.raw_observation_count,
        "total_findings": metrics.total_findings,
        "unique_vulnerabilities": metrics.unique_vulnerabilities,
        "ai_fix_eligible_findings": metrics.ai_fix_eligible_findings,
        "severity_counts": metrics.severity_counts,
    }

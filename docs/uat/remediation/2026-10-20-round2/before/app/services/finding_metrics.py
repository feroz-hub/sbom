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
from ..sources.reconciliation import canonical_vulnerability, occurrence_identity, reconcile

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
    cvss_scored_findings: int = 0
    cvss_unknown_findings: int = 0
    total_component_entries: int | None = None
    unique_package_releases: int | None = None
    unresolved_component_entries: int | None = None


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
    return canonical_vulnerability(vuln_id, list(aliases or []))


def component_identity_from_dict(finding: dict[str, Any]) -> str:
    return occurrence_identity(finding)


def component_identity_from_row(finding: Any) -> str:
    return occurrence_identity({"component_id": finding.component_id,
                                "analysis_run_id": getattr(finding, "analysis_run_id", None),
                                "id": getattr(finding, "id", None)})


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
    return reconcile([f for f in findings if isinstance(f, dict)])


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
    dictionaries = []
    for finding in findings:
        row = vars(_finding_view(finding)).copy()
        evidence = getattr(finding, "evidence_json", None) or {}
        row.update(evidence)
        row["sources"] = _merge_sources(finding.source, None)
        for field in ("aliases", "fixed_versions", "cwe"):
            row[field] = parse_json_list(row.get(field))
        dictionaries.append(row)
    result = []
    for row in reconcile(dictionaries):
        row["source"] = ",".join(row.pop("sources", []))
        for field in ("aliases", "fixed_versions", "cwe"):
            row[field] = json.dumps(row.get(field) or [])
        result.append(SimpleNamespace(**row))
    return result


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

    try:
        metadata = json.loads(run.raw_report or "{}").get("analysis_metadata", {}) if run else {}
    except (ValueError, TypeError, AttributeError):
        metadata = {}
    return RunFindingMetrics(
        raw_observation_count=_raw_observation_count(run, max(len(rows), sum(len(f.source_observations) or 1 for f in canonical_rows))),
        total_findings=len(canonical_rows),
        unique_vulnerabilities=len(unique_vulns),
        ai_fix_eligible_findings=ai_eligible,
        severity_counts=severity_counts,
        cvss_scored_findings=sum(f.score is not None for f in canonical_rows),
        cvss_unknown_findings=sum(f.score is None for f in canonical_rows),
        total_component_entries=metadata.get("total_component_entries"),
        unique_package_releases=metadata.get("unique_package_releases"),
        unresolved_component_entries=metadata.get("unresolved_component_entries"),
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
        "total_component_entries": metrics.total_component_entries,
        "unique_package_releases": metrics.unique_package_releases,
        "unresolved_component_entries": metrics.unresolved_component_entries,
        "cvss_scored_findings": metrics.cvss_scored_findings,
        "cvss_unknown_findings": metrics.cvss_unknown_findings,
        "cvss_coverage": metrics.cvss_scored_findings / metrics.total_findings if metrics.total_findings else None,
    }


def equivalent_vulnerability_ids(finding: Any) -> set[str]:
    """Only use non-ambiguous aliases for existing workflow records."""
    primary = str(finding.vuln_id or "").upper()
    aliases = {value.upper() for value in parse_json_list(finding.aliases)}
    cves = {value for value in {primary, *aliases} if _CVE_RE.fullmatch(value)}
    return {primary} if len(cves) > 1 else {primary, *aliases}


def vex_for_finding(vex: dict, finding: Any) -> Any:
    candidates = [vex[(finding.component_id, vid)] for vid in equivalent_vulnerability_ids(finding)
                  if (finding.component_id, vid) in vex]
    if not candidates or len({item.status for item in candidates}) > 1:
        return None
    return vex.get((finding.component_id, str(finding.vuln_id).upper())) or candidates[0]


def remediation_for_finding(remediations: dict, finding: Any) -> Any:
    direct = remediations.get((finding.vuln_id, finding.component_name, finding.component_version))
    if direct is not None:
        return direct
    names = {finding.component_name, getattr(finding, "normalized_name", None)}
    # Alternate names are accepted only from this resolved occurrence's evidence.
    if finding.component_id is not None:
        names.update(obs.get("component_name") for obs in getattr(finding, "source_observations", []))
    identities = equivalent_vulnerability_ids(finding)
    candidates = [item for (vid, name, version), item in remediations.items()
                  if vid.upper() in identities and name in names and version == finding.component_version]
    return candidates[0] if len(candidates) == 1 else None

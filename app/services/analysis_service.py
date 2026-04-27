"""
Analysis Service Layer - Business logic for vulnerability analysis and reporting.
"""

from __future__ import annotations

import json
import logging
from typing import Any

from sqlalchemy import func, select
from sqlalchemy.orm import Session

from ..analysis import extract_components
from ..models import AnalysisRun, SBOMAnalysisReport, SBOMComponent, SBOMSource
from ..settings import get_analysis_legacy_level
from .sbom_service import _upsert_components, now_iso, resolve_component_id, safe_int

log = logging.getLogger(__name__)


# ============================================================
# Configuration
# ============================================================


def legacy_analysis_level() -> int:
    """Get the legacy analysis level from Settings (env ANALYSIS_LEGACY_LEVEL)."""
    return get_analysis_legacy_level()


# ============================================================
# Details Normalization
# ============================================================


def normalize_details(details: dict | None, components: list[dict]) -> dict:
    """
    Normalize and validate analysis details.

    Preserves analyzer-provided totals if present; only computes from raw components
    as a fallback. Always recomputes severity buckets from the 'findings' list.

    Args:
        details: Raw analysis details dictionary
        components: List of component dictionaries

    Returns:
        Normalized details dictionary with validated structure
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

    # Only set totals if the analyzer didn't already supply them
    if "total_components" not in data or not isinstance(data["total_components"], int):
        data["total_components"] = len(components)

    if "components_with_cpe" not in data or not isinstance(data["components_with_cpe"], int):
        data["components_with_cpe"] = len({c.get("cpe") for c in components if c.get("cpe")})

    if "total_findings" not in data or not isinstance(data["total_findings"], int):
        data["total_findings"] = len(findings)

    # Always recompute buckets from 'findings'
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


def compute_report_status(total_findings: int, query_errors: list[dict]) -> str:
    """
    Compute the overall report status based on findings and errors.

    Args:
        total_findings: Number of vulnerabilities found
        query_errors: List of query error dictionaries

    Returns:
        Status string: "FAIL" (findings), "PARTIAL" (errors), or "PASS"
    """
    if total_findings > 0:
        return "FAIL"
    if query_errors:
        return "PARTIAL"
    return "PASS"


# ============================================================
# Analysis Run Persistence
# ============================================================


def persist_analysis_run(
    db: Session,
    sbom_obj: SBOMSource,
    details: dict,
    components: list[dict],
    run_status: str,
    source: str,
    started_on: str,
    completed_on: str,
    duration_ms: int,
) -> AnalysisRun:
    """
    Persist an analysis run and its findings to the database.

    Args:
        db: Database session
        sbom_obj: SBOM source object
        details: Analysis details dict containing findings, totals, etc.
        components: List of component dictionaries
        run_status: Overall status (PASS, FAIL, ERROR, etc.)
        source: Source identifier (NVD, OSV, GITHUB, VULNDB, MULTI, etc.)
        started_on: ISO timestamp when analysis started
        completed_on: ISO timestamp when analysis completed
        duration_ms: Duration in milliseconds

    Returns:
        Newly created AnalysisRun object
    """
    from ..models import AnalysisFinding

    component_maps = _upsert_components(db, sbom_obj, components)

    run = AnalysisRun(
        sbom_id=sbom_obj.id,
        project_id=sbom_obj.projectid,
        run_status=run_status,
        source=source,
        started_on=started_on,
        completed_on=completed_on,
        duration_ms=duration_ms,
        total_components=safe_int(details.get("total_components")),
        components_with_cpe=safe_int(details.get("components_with_cpe")),
        total_findings=safe_int(details.get("total_findings")),
        critical_count=safe_int(details.get("critical")),
        high_count=safe_int(details.get("high")),
        medium_count=safe_int(details.get("medium")),
        low_count=safe_int(details.get("low")),
        unknown_count=safe_int(details.get("unknown")),
        query_error_count=len(details.get("query_errors") or []),
        raw_report=json.dumps(details),
    )
    db.add(run)
    db.flush()

    # Persist findings
    for finding in details.get("findings") or []:
        if not isinstance(finding, dict):
            continue

        fv = finding.get("fixed_versions") or []
        db.add(
            AnalysisFinding(
                analysis_run_id=run.id,
                component_id=resolve_component_id(finding, component_maps),
                vuln_id=str(finding.get("vuln_id") or "UNKNOWN-CVE"),
                source=",".join(finding.get("sources", ["NVD"])),
                title=(finding.get("title") or finding.get("vuln_id")),
                description=finding.get("description"),
                severity=finding.get("severity"),
                score=_safe_float(finding.get("score")),
                vector=finding.get("vector"),
                published_on=finding.get("published"),
                reference_url=(finding.get("url") or (finding.get("references") or [None])[0]),
                cwe=",".join(finding.get("cwe", [])) if finding.get("cwe") else None,
                cpe=finding.get("cpe"),
                component_name=finding.get("component_name"),
                component_version=finding.get("component_version"),
                fixed_versions=json.dumps(fv) if fv else None,
                attack_vector=finding.get("attack_vector"),
                cvss_version=finding.get("cvss_version"),
                aliases=json.dumps(finding.get("aliases") or []) if finding.get("aliases") else None,
            )
        )

    return run


def _safe_float(value: Any) -> float | None:
    """Safely convert value to float, return None on failure."""
    try:
        if value is None:
            return None
        return float(value)
    except (TypeError, ValueError):
        return None


# ============================================================
# Backfill Analytics
# ============================================================
#
# Phase 5 cleanup note: this module previously also exported
# `create_auto_report`, `create_legacy_report_from_run`, and the sync
# wrapper `analyze_sbom_multi_source`. None of them had any callers
# outside the dead code path itself — the production
# `POST /api/sboms/{id}/analyze` flow lives in
# `app/routers/sboms_crud.py:create_auto_report` and uses its own
# `persist_analysis_run`. The legacy helpers were removed.
# `persist_analysis_run` here is kept because `backfill_analytics_tables`
# (called from `app/main.py:on_startup`) still consumes it to migrate
# legacy SBOMAnalysisReport rows into the AnalysisRun table on first run.


def backfill_analytics_tables(db: Session) -> None:
    """
    Backfill the AnalysisRun table from existing SBOMSource and SBOMAnalysisReport records.

    This migrates legacy reports into the new AnalysisRun/AnalysisFinding structure,
    ensuring all historical analysis data is available for dashboard and reporting.

    Args:
        db: Database session
    """
    sboms = db.execute(select(SBOMSource).order_by(SBOMSource.id.asc())).scalars().all()

    for sbom in sboms:
        components = []
        has_components = db.execute(
            select(func.count(SBOMComponent.id)).where(SBOMComponent.sbom_id == sbom.id)
        ).scalar_one()

        # Extract components if not already stored
        if sbom.sbom_data:
            try:
                components = extract_components(sbom.sbom_data)
                if not has_components and components:
                    _upsert_components(db, sbom, components)
            except Exception as e:
                log.warning("Component extraction failed for SBOM id=%d: %s", sbom.id, e)
                components = []

        # Check if analysis run already exists
        has_run = db.execute(select(AnalysisRun.id).where(AnalysisRun.sbom_id == sbom.id).limit(1)).scalar_one_or_none()
        if has_run is not None:
            continue

        # Look for legacy report to backfill from
        latest_legacy = (
            db.execute(
                select(SBOMAnalysisReport)
                .where(SBOMAnalysisReport.sbom_ref_id == sbom.id)
                .order_by(SBOMAnalysisReport.id.desc())
            )
            .scalars()
            .first()
        )

        if latest_legacy:
            try:
                details = json.loads(latest_legacy.analysis_details or "{}")
            except json.JSONDecodeError:
                details = {"message": "Legacy report was non-JSON", "findings": []}

            details = normalize_details(details, components)
            run_status = latest_legacy.sbom_result or compute_report_status(
                safe_int(details.get("total_findings")), details.get("query_errors") or []
            )
            used = (details.get("analysis_metadata") or {}).get("sources") or []
            source = ",".join(used) if used else "BACKFILL"
            started_on = latest_legacy.created_on or now_iso()
            completed_on = latest_legacy.created_on or started_on
        else:
            details = normalize_details({"message": "Backfilled from SBOM without legacy report."}, components)
            run_status = "NO_DATA" if not sbom.sbom_data else "PASS"
            source = "BACKFILL"
            started_on = now_iso()
            completed_on = started_on

        persist_analysis_run(
            db=db,
            sbom_obj=sbom,
            details=details,
            components=components,
            run_status=run_status,
            source=source,
            started_on=started_on,
            completed_on=completed_on,
            duration_ms=0,
        )

    db.commit()

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


# Run-status enum (ADR-0001). One word, one meaning.
RUN_STATUS_OK = "OK"            # completed cleanly, zero findings
RUN_STATUS_FINDINGS = "FINDINGS"  # completed cleanly, >=1 finding (NOT a pipeline failure)
RUN_STATUS_PARTIAL = "PARTIAL"  # completed but some upstream feeds errored
RUN_STATUS_ERROR = "ERROR"      # technical failure
RUN_STATUS_RUNNING = "RUNNING"
RUN_STATUS_PENDING = "PENDING"
RUN_STATUS_NO_DATA = "NO_DATA"

# Anything in this set counts as a successful run for dashboard scoping.
SUCCESSFUL_RUN_STATUSES = (RUN_STATUS_OK, RUN_STATUS_FINDINGS, RUN_STATUS_PARTIAL)

# Legacy aliases accepted as inbound-only (one-release deprecation window).
# Outbound payloads always emit the canonical names above.
_LEGACY_STATUS_ALIASES = {"FAIL": RUN_STATUS_FINDINGS, "PASS": RUN_STATUS_OK}


def normalize_run_status(value: str | None) -> str | None:
    """Map a legacy run-status string to its canonical form. Idempotent."""
    if value is None:
        return None
    upper = value.strip().upper()
    return _LEGACY_STATUS_ALIASES.get(upper, upper)


def compute_report_status(total_findings: int, query_errors: list[dict]) -> str:
    """Compute the overall run status from findings + upstream errors.

    Returns one of: ``OK`` (clean), ``FINDINGS`` (vulns detected — *successful*
    scan), ``PARTIAL`` (some upstream feed errored). See ADR-0001 for the
    rename history (``FAIL`` → ``FINDINGS``, ``PASS`` → ``OK``).
    """
    if total_findings > 0:
        return RUN_STATUS_FINDINGS
    if query_errors:
        return RUN_STATUS_PARTIAL
    return RUN_STATUS_OK


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

        # Multi-source orchestrator emits the canonical id under "vuln_id";
        # legacy callers may still use "id". Accept both, prefer the new
        # key. Hard-fallback to "UNKNOWN-CVE" because the column is NOT NULL.
        vuln_id = (finding.get("vuln_id") or finding.get("id") or "").strip() or "UNKNOWN-CVE"

        sources = finding.get("sources", [])
        if isinstance(sources, list):
            sources_str = ",".join(str(s) for s in sources)
        else:
            sources_str = str(sources) if sources else ""

        # `cwe` may arrive as a list (NVD/GHSA/OSV multi-source path) or
        # as a legacy scalar string. Persist as a JSON-encoded sorted list
        # when it's a collection, otherwise fall back to the trimmed
        # string. Mirrors the storage convention used for `aliases` and
        # `fixed_versions` in adjacent Text columns.
        cwe_raw = finding.get("cwe")
        if isinstance(cwe_raw, (list, tuple, set)):
            cwe_value = json.dumps(sorted({str(x) for x in cwe_raw if x})) if cwe_raw else None
        elif isinstance(cwe_raw, str):
            cwe_value = cwe_raw.strip() or None
        else:
            cwe_value = None

        aliases_json = None
        if finding.get("aliases"):
            try:
                aliases_json = json.dumps(finding["aliases"])
            except (TypeError, ValueError):
                aliases_json = None

        fv = finding.get("fixed_versions") or []

        # Reference URL: prefer explicit `url`, fall back to first entry
        # of `references[]` (VulDB/OSV adapters populate references but
        # may leave url empty).
        reference_url = (finding.get("url") or "").strip()
        if not reference_url:
            refs = finding.get("references") or []
            if refs:
                reference_url = refs[0]
        reference_url = reference_url or None

        db.add(
            AnalysisFinding(
                analysis_run_id=run.id,
                component_id=resolve_component_id(finding, component_maps),
                vuln_id=vuln_id,
                source=sources_str,
                title=(finding.get("title") or finding.get("vuln_id")),
                description=(finding.get("description") or "").strip() or None,
                severity=(finding.get("severity") or "UNKNOWN").upper(),
                score=_safe_float(finding.get("score")),
                vector=(finding.get("vector") or "").strip() or None,
                published_on=(finding.get("published") or "").strip() or None,
                reference_url=reference_url,
                cwe=cwe_value,
                cpe=(finding.get("cpe") or "").strip() or None,
                component_name=(finding.get("component_name") or "").strip() or None,
                component_version=(finding.get("component_version") or "").strip() or None,
                fixed_versions=json.dumps(fv) if fv else None,
                attack_vector=(finding.get("attack_vector") or "").strip() or None,
                cvss_version=finding.get("cvss_version"),
                aliases=aliases_json,
            )
        )

    # CACHE INVALIDATION CONTRACT (ADR-0008)
    #
    # ``compare_cache`` is keyed by (run_a_id, run_b_id). Because this
    # function only CREATES new runs (immutable, append-only — every
    # analysis produces a new ``analysis_run`` row), no existing cache
    # entries reference the new ``run.id`` and there is nothing to
    # invalidate here.
    #
    # If a future code path MUTATES an existing run (re-running findings
    # against the same run_id) or DELETES a run, that path MUST call
    # ``CompareService(db).invalidate_for_run(run_id)`` in the same
    # transaction. Skipping it leaves stale rows in compare_cache that
    # the 24h TTL will eventually clean up — but until then, users would
    # see a CompareResult containing references to the mutated/deleted
    # run, which is a correctness bug.
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

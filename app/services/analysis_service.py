"""
Analysis Service Layer - Business logic for vulnerability analysis and reporting.
"""

from __future__ import annotations

import json
import logging
from datetime import UTC, datetime, timedelta
from typing import Any

from sqlalchemy import delete, inspect, select
from sqlalchemy.orm import Session
from sqlalchemy.sql.sqltypes import String

from ..models import AnalysisRun, SBOMAnalysisReport, SBOMSource
from ..settings import get_analysis_legacy_level
from ..sources.routing import count_authoritative_cpes, normalize_query_errors
from .finding_metrics import (
    apply_metrics_to_run,
    calculate_run_finding_metrics,
    deduplicate_finding_dicts,
)
from .kev_enrichment import enrich_findings_with_kev
from .sbom_service import (
    COMPONENT_EXTRACTION_COMPLETED,
    COMPONENT_EXTRACTION_FAILED,
    COMPONENT_EXTRACTION_SKIPPED,
    ComponentExtractionSkipped,
    _upsert_components,
    detect_supported_component_extraction_format,
    now_iso,
    resolve_component_id,
    safe_int,
    sync_sbom_components,
)

log = logging.getLogger(__name__)

_APPLICABILITY_GATED_SOURCES = {"GITHUB", "NVD", "OSV"}
_FINDING_PREVIEW_LIMIT = 96
_ALLOWED_SEVERITIES = {"CRITICAL", "HIGH", "MEDIUM", "LOW", "UNKNOWN"}
_ALLOWED_ATTACK_VECTORS = {"NETWORK", "ADJACENT", "ADJACENT_NETWORK", "LOCAL", "PHYSICAL", "N", "A", "L", "P"}


class AnalysisFindingPersistenceValidationError(ValueError):
    """Raised when a finding cannot be safely persisted as modeled."""

    def __init__(self, violations: list[dict[str, Any]]):
        self.violations = violations
        first = violations[0] if violations else {}
        field = first.get("field", "unknown")
        actual = first.get("actual_length")
        allowed = first.get("allowed_length")
        detail = f"{field} length {actual} exceeds allowed length {allowed}" if actual else str(first)
        super().__init__(f"analysis finding persistence validation failed: {detail}")


def _preview(value: Any) -> str:
    text = str(value).replace("\r", " ").replace("\n", " ")
    if len(text) <= _FINDING_PREVIEW_LIMIT:
        return text
    return f"{text[:_FINDING_PREVIEW_LIMIT]}..."


def _finding_identity(row: Any) -> dict[str, Any]:
    return {
        "vuln_id": getattr(row, "vuln_id", None),
        "component": getattr(row, "component_name", None),
    }


def _validate_analysis_finding_rows(
    db: Session,
    rows: list[Any],
    *,
    run_id: int | None,
    sbom_id: int | None,
    correlation_id: str | None = None,
) -> None:
    """Validate pending AnalysisFinding rows before SQLAlchemy bulk flushes."""

    from ..models import AnalysisFinding

    violations: list[dict[str, Any]] = []
    string_limits: dict[str, int] = {}
    for column in inspect(AnalysisFinding).columns:
        if isinstance(column.type, String) and getattr(column.type, "length", None):
            string_limits[column.name] = int(column.type.length)

    try:
        for column in inspect(db.get_bind()).get_columns(AnalysisFinding.__tablename__):
            length = getattr(column["type"], "length", None)
            if not length:
                continue
            existing = string_limits.get(column["name"])
            string_limits[column["name"]] = min(existing, int(length)) if existing else int(length)
    except Exception:
        log.debug(
            "Unable to inspect live analysis_finding column lengths",
            extra={"run_id": run_id, "sbom_id": sbom_id, "correlation_id": correlation_id},
            exc_info=True,
        )

    for row in rows:
        identity = _finding_identity(row)
        for field_name, allowed in string_limits.items():
            value = getattr(row, field_name, None)
            if value is None:
                continue
            text = str(value)
            actual = len(text)
            if actual <= allowed:
                continue
            violation = {
                "field": field_name,
                "actual_length": actual,
                "allowed_length": allowed,
                "vuln_id": identity["vuln_id"],
                "component": identity["component"],
                "preview": _preview(text),
                "run_id": run_id,
                "sbom_id": sbom_id,
                "correlation_id": correlation_id,
            }
            violations.append(violation)
            log.warning("analysis.finding_column_overflow", extra=violation)

        severity = getattr(row, "severity", None)
        if severity and str(severity).upper() not in _ALLOWED_SEVERITIES:
            violations.append(
                {
                    "field": "severity",
                    "value": _preview(severity),
                    "vuln_id": identity["vuln_id"],
                    "component": identity["component"],
                    "run_id": run_id,
                    "sbom_id": sbom_id,
                    "correlation_id": correlation_id,
                }
            )

        attack_vector = getattr(row, "attack_vector", None)
        if attack_vector:
            normalized_attack_vector = str(attack_vector).strip().upper().replace(" ", "_")
            if normalized_attack_vector not in _ALLOWED_ATTACK_VECTORS:
                violations.append(
                    {
                        "field": "attack_vector",
                        "value": _preview(attack_vector),
                        "vuln_id": identity["vuln_id"],
                        "component": identity["component"],
                        "run_id": run_id,
                        "sbom_id": sbom_id,
                        "correlation_id": correlation_id,
                    }
                )

    if violations:
        first = violations[0]
        log.warning(
            "analysis.finding_validation_failed",
            extra={
                "run_id": run_id,
                "sbom_id": sbom_id,
                "finding_count": len(rows),
                "field": first.get("field"),
                "actual_length": first.get("actual_length"),
                "permitted_length": first.get("allowed_length"),
                "vuln_id": first.get("vuln_id"),
                "component": first.get("component"),
                "correlation_id": correlation_id,
            },
        )
        raise AnalysisFindingPersistenceValidationError(violations)


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
    query_errors = normalize_query_errors(query_errors)
    data["query_errors"] = query_errors

    # Only set totals if the analyzer didn't already supply them
    if "total_components" not in data or not isinstance(data["total_components"], int):
        data["total_components"] = len(components)

    data["components_with_cpe"] = count_authoritative_cpes(components)

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
RUN_STATUS_OK = "OK"  # completed cleanly, zero findings
RUN_STATUS_FINDINGS = "FINDINGS"  # completed cleanly, >=1 finding (NOT a pipeline failure)
RUN_STATUS_PARTIAL = "PARTIAL"  # completed but some upstream feeds errored
RUN_STATUS_ERROR = "ERROR"  # technical failure
RUN_STATUS_RUNNING = "RUNNING"
RUN_STATUS_PENDING = "PENDING"
RUN_STATUS_INTERRUPTED = "INTERRUPTED"
RUN_STATUS_NO_DATA = "NO_DATA"
ACTIVE_ANALYSIS_RUN_STATUSES = ("PENDING", "QUEUED", "RUNNING", "ANALYSING", "ANALYZING")

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


def _parse_iso_timestamp(value: str | None) -> datetime | None:
    if not value:
        return None
    text = value.strip()
    if not text:
        return None
    if text.endswith("Z"):
        text = f"{text[:-1]}+00:00"
    try:
        parsed = datetime.fromisoformat(text)
    except ValueError:
        return None
    if parsed.tzinfo is None:
        return parsed.replace(tzinfo=UTC)
    return parsed.astimezone(UTC)


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


def mark_analysis_run_failed(
    db: Session,
    *,
    run_id: int,
    error_message: str,
    completed_on: str,
    duration_ms: int,
    code: int = 500,
    sources: list[str] | None = None,
    correlation_id: str | None = None,
    error_category: str | None = None,
) -> AnalysisRun | None:
    """Mark an analysis run failed using the caller-provided clean session."""

    log.info(
        "analysis.run_mark_failed.started",
        extra={"run_id": run_id, "correlation_id": correlation_id},
    )
    run = db.get(AnalysisRun, run_id)
    if run is None:
        log.warning(
            "analysis.run_mark_failed.failed",
            extra={"run_id": run_id, "correlation_id": correlation_id, "reason": "run_not_found"},
        )
        return None

    run.run_status = RUN_STATUS_ERROR
    run.completed_on = completed_on
    run.duration_ms = duration_ms
    run.raw_report = json.dumps(
        {
            "error_message": error_message,
            "status": "failed",
            "code": code,
            "sources": sources or [],
            "correlation_id": correlation_id,
            "error_category": error_category,
        }
    )
    db.add(run)
    log.info(
        "analysis.run_mark_failed.completed",
        extra={"run_id": run_id, "sbom_id": run.sbom_id, "correlation_id": correlation_id},
    )
    return run


def mark_analysis_run_interrupted(
    db: Session,
    *,
    run_id: int,
    reason: str,
    completed_on: str,
    duration_ms: int = 0,
    correlation_id: str | None = None,
) -> AnalysisRun | None:
    """Mark an orphaned active run as interrupted using a clean session."""

    run = db.get(AnalysisRun, run_id)
    if run is None:
        log.warning(
            "analysis.run_mark_interrupted.failed",
            extra={"run_id": run_id, "correlation_id": correlation_id, "reason": "run_not_found"},
        )
        return None

    old_status = run.run_status
    run.run_status = RUN_STATUS_INTERRUPTED
    run.completed_on = completed_on
    run.duration_ms = duration_ms
    run.raw_report = json.dumps(
        {
            "status": "interrupted",
            "error_message": reason,
            "message": reason,
            "previous_status": old_status,
            "correlation_id": correlation_id,
        }
    )
    db.add(run)
    log.info(
        "analysis_status_transition",
        extra={
            "event": "analysis_status_transition",
            "analysis_run_id": run.id,
            "sbom_id": run.sbom_id,
            "old_status": old_status,
            "new_status": RUN_STATUS_INTERRUPTED,
            "completed_at": completed_on,
            "duration_ms": duration_ms,
            "error_message": reason,
            "correlation_id": correlation_id,
        },
    )
    return run


def reconcile_stale_analysis_runs(
    db: Session,
    *,
    stale_after_seconds: int = 60,
    now: datetime | None = None,
) -> list[AnalysisRun]:
    """Transition old active inline analysis runs to INTERRUPTED on startup.

    The current production analysis flow runs inside the API/SSE process and
    stores no task id, worker id, or heartbeat. A run older than the grace
    period cannot be verified as active after process startup, so it is marked
    terminal instead of blocking future analyses forever.
    """

    now_dt = now or datetime.now(UTC)
    if now_dt.tzinfo is None:
        now_dt = now_dt.replace(tzinfo=UTC)
    cutoff = now_dt - timedelta(seconds=max(0, stale_after_seconds))
    reason = "Analysis was interrupted because the application or worker stopped unexpectedly."
    interrupted: list[AnalysisRun] = []
    active_runs = (
        db.execute(
            select(AnalysisRun)
            .where(AnalysisRun.run_status.in_(ACTIVE_ANALYSIS_RUN_STATUSES))
            .order_by(AnalysisRun.id.asc())
        )
        .scalars()
        .all()
    )

    log.info(
        "analysis.startup_reconciliation.executed",
        extra={
            "event": "analysis_startup_reconciliation",
            "active_run_count": len(active_runs),
            "stale_after_seconds": stale_after_seconds,
        },
    )

    for run in active_runs:
        last_seen = _parse_iso_timestamp(run.completed_on) or _parse_iso_timestamp(run.started_on)
        if last_seen is not None and last_seen > cutoff:
            continue
        started = _parse_iso_timestamp(run.started_on)
        duration_ms = 0
        if started is not None:
            duration_ms = max(0, int((now_dt - started).total_seconds() * 1000))
        marked = mark_analysis_run_interrupted(
            db,
            run_id=int(run.id),
            reason=reason,
            completed_on=now_iso(),
            duration_ms=duration_ms,
        )
        if marked is not None:
            interrupted.append(marked)

    if interrupted:
        log.warning(
            "analysis.startup_reconciliation.interrupted_stale_runs",
            extra={
                "event": "analysis_stale_runs_interrupted",
                "run_ids": [run.id for run in interrupted],
                "count": len(interrupted),
            },
        )
    return interrupted


def get_active_analysis_run(db: Session, sbom_id: int) -> AnalysisRun | None:
    """Return the newest active analysis run for an SBOM, if one exists."""
    return db.execute(
        select(AnalysisRun)
        .where(
            AnalysisRun.sbom_id == sbom_id,
            AnalysisRun.run_status.in_(ACTIVE_ANALYSIS_RUN_STATUSES),
        )
        .order_by(AnalysisRun.id.desc())
        .limit(1)
    ).scalar_one_or_none()


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
    existing_run: AnalysisRun | None = None,
    trigger_source: str = "unknown",
    correlation_id: str | None = None,
) -> AnalysisRun:
    """
    Persist an analysis run and its findings to the database.

    Args:
        db: Database session
        sbom_obj: SBOM source object
        details: Analysis details dict containing findings, totals, etc.
        components: List of component dictionaries
        run_status: Overall status (OK, FINDINGS, ERROR, etc.; legacy PASS/FAIL accepted)
        source: Source identifier (NVD, OSV, GITHUB, VULNDB, MULTI, etc.)
        started_on: ISO timestamp when analysis started
        completed_on: ISO timestamp when analysis completed
        duration_ms: Duration in milliseconds

    Returns:
        Newly created AnalysisRun object
    """
    from ..models import AnalysisFinding

    component_maps = _upsert_components(db, sbom_obj, components)
    details = filter_unconfirmed_provider_findings(details, components)
    details["findings"] = deduplicate_finding_dicts(details.get("findings") or [])
    raw_observation_count = safe_int(
        (details.get("analysis_metadata") or {}).get("raw_observation_count")
        or details.get("raw_observation_count")
        or details.get("total_findings")
    )
    details = normalize_details(details, components)
    details.setdefault("analysis_metadata", {})
    if isinstance(details["analysis_metadata"], dict):
        details["analysis_metadata"]["raw_observation_count"] = raw_observation_count

    run = existing_run or AnalysisRun(sbom_id=sbom_obj.id, project_id=sbom_obj.projectid, product_id=sbom_obj.product_id)
    run.sbom_id = sbom_obj.id
    run.project_id = sbom_obj.projectid
    run.product_id = sbom_obj.product_id
    normalized_status = normalize_run_status(run_status) or RUN_STATUS_ERROR
    if normalized_status == RUN_STATUS_FINDINGS and safe_int(details.get("total_findings")) == 0:
        normalized_status = compute_report_status(0, details.get("query_errors") or [])
    run.run_status = normalized_status
    run.source = source
    run.trigger_source = trigger_source
    run.started_on = started_on
    run.completed_on = completed_on
    run.duration_ms = duration_ms
    run.total_components = safe_int(details.get("total_components"))
    run.components_with_cpe = safe_int(details.get("components_with_cpe"))
    run.total_findings = 0
    run.critical_count = 0
    run.high_count = 0
    run.medium_count = 0
    run.low_count = 0
    run.unknown_count = 0
    run.query_error_count = len(details.get("query_errors") or [])
    run.raw_report = json.dumps(details)
    db.add(run)
    db.flush()

    if existing_run is not None:
        db.execute(delete(AnalysisFinding).where(AnalysisFinding.analysis_run_id == run.id))
        db.flush()

    # Persist canonical findings. Metrics are written after the actual rows
    # exist so duplicate guards and component resolution cannot leave stale
    # run-level counts behind.
    persisted_rows: list[AnalysisFinding] = []
    finding_count = len([finding for finding in (details.get("findings") or []) if isinstance(finding, dict)])
    log.info(
        "analysis.finding_persistence.started",
        extra={
            "run_id": run.id,
            "sbom_id": sbom_obj.id,
            "finding_count": finding_count,
            "correlation_id": correlation_id,
        },
    )
    for finding in details.get("findings") or []:
        if not isinstance(finding, dict):
            continue
        applicability_status = finding.get("applicability_status") or (finding.get("applicability") or {}).get("status")
        if applicability_status and applicability_status != "affected":
            raise AssertionError("Refusing to persist a non-affected vulnerability finding")

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

        component_id = resolve_component_id(finding, component_maps)
        cpe_value = (finding.get("cpe") or "").strip() or None
        row = AnalysisFinding(
            analysis_run_id=run.id,
            component_id=component_id,
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
            cpe=cpe_value,
            component_name=(finding.get("component_name") or "").strip() or None,
            component_version=(finding.get("component_version") or "").strip() or None,
            fixed_versions=json.dumps(fv) if fv else None,
            attack_vector=(finding.get("attack_vector") or "").strip() or None,
            cvss_version=finding.get("cvss_version"),
            aliases=aliases_json,
            # Roadmap #1 — populated by the NVD version-range filter
            # when ``nvd_version_range_filter_enabled`` is on. Absent
            # (and therefore NULL in the row) when the flag is off or
            # the source is not NVD. ``.get`` rather than ``[]`` so
            # the flag-off path never KeyErrors.
            match_reason=finding.get("match_reason"),
            matched_range=finding.get("matched_range"),
            # Roadmap #6 — search-strategy provenance tag attached
            # at the per-source emit step. NVD=cpe_name (only live
            # path), OSV=purl_direct (querybatch + /v1/query
            # fallback), GHSA=ghsa_alias. NULL on any source not
            # yet wired or any pre-PR-C row.
            match_strategy=finding.get("match_strategy"),
            # Roadmap #3 — token-overlap confidence in [0.0, 1.0],
            # post strategy-floor. Computed by the per-source emit
            # step via app.sources.match_confidence.score_match +
            # apply_strategy_floor. NULL on pre-PR-D rows and any
            # source not yet wired into the scorer.
            match_confidence=finding.get("match_confidence"),
        )
        db.add(row)
        persisted_rows.append(row)

    _validate_analysis_finding_rows(
        db,
        persisted_rows,
        run_id=run.id,
        sbom_id=sbom_obj.id,
        correlation_id=correlation_id,
    )
    db.flush()
    log.info(
        "analysis.finding_persistence.completed",
        extra={
            "run_id": run.id,
            "sbom_id": sbom_obj.id,
            "finding_count": len(persisted_rows),
            "correlation_id": correlation_id,
        },
    )
    metrics = calculate_run_finding_metrics(persisted_rows, run=run)
    kev_enrichments = enrich_findings_with_kev(db, persisted_rows)
    kev_cves = sorted(
        {
            enrichment.matched_cve
            for enrichment in kev_enrichments.values()
            if enrichment.is_kev and enrichment.matched_cve
        }
    )
    apply_metrics_to_run(run, metrics)
    if normalized_status in {RUN_STATUS_OK, RUN_STATUS_FINDINGS, RUN_STATUS_PARTIAL, "PASS", "FAIL"}:
        run.run_status = compute_report_status(metrics.total_findings, details.get("query_errors") or [])
    details["total_findings"] = metrics.total_findings
    details["critical"] = metrics.severity_counts["critical"]
    details["high"] = metrics.severity_counts["high"]
    details["medium"] = metrics.severity_counts["medium"]
    details["low"] = metrics.severity_counts["low"]
    details["unknown"] = metrics.severity_counts["unknown"]
    details["metrics"] = {
        "raw_observation_count": metrics.raw_observation_count,
        "total_findings": metrics.total_findings,
        "unique_vulnerabilities": metrics.unique_vulnerabilities,
        "ai_fix_eligible_findings": metrics.ai_fix_eligible_findings,
        "kev_findings": sum(1 for enrichment in kev_enrichments.values() if enrichment.is_kev),
        "kev_cves": kev_cves,
        "severity_counts": metrics.severity_counts,
    }
    if isinstance(details.get("analysis_metadata"), dict):
        details["analysis_metadata"]["kev_findings"] = details["metrics"]["kev_findings"]
        details["analysis_metadata"]["kev_cves"] = kev_cves
    run.raw_report = json.dumps(details)
    db.add(run)

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


def filter_unconfirmed_provider_findings(details: dict, components: list[dict]) -> dict:
    data = dict(details or {})
    findings = data.get("findings") or []
    if not isinstance(findings, list):
        return normalize_details(data, components)

    kept: list[dict] = []
    dropped = 0
    for finding in findings:
        if not isinstance(finding, dict):
            continue
        applicability_status = finding.get("applicability_status") or (finding.get("applicability") or {}).get("status")
        if applicability_status and applicability_status != "affected":
            raise AssertionError("Refusing to persist a non-affected vulnerability finding")

        sources = _finding_sources(finding)
        if sources & _APPLICABILITY_GATED_SOURCES and applicability_status != "affected":
            dropped += 1
            continue
        kept.append(finding)

    if dropped:
        log.warning("Dropped %d provider findings without affected applicability before persistence", dropped)
    data["findings"] = kept
    data.pop("total_findings", None)
    data.pop("critical", None)
    data.pop("high", None)
    data.pop("medium", None)
    data.pop("low", None)
    data.pop("unknown", None)
    return normalize_details(data, components)


def _finding_sources(finding: dict) -> set[str]:
    raw = finding.get("sources")
    if isinstance(raw, list):
        return {str(source).strip().upper() for source in raw if str(source).strip()}
    if isinstance(raw, str):
        return {source.strip().upper() for source in raw.split(",") if source.strip()}
    return set()


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


_TRUSTED_SBOM_STATUSES = {"validated", "accepted", "imported", "trusted"}
_FINAL_EXTRACTION_STATUSES = {COMPONENT_EXTRACTION_COMPLETED, COMPONENT_EXTRACTION_SKIPPED}


def _mark_startup_extraction_skipped(db: Session, sbom: SBOMSource, reason: str) -> None:
    sbom.component_extraction_status = COMPONENT_EXTRACTION_SKIPPED
    sbom.component_extraction_error = reason
    sbom.component_extraction_attempted_at = now_iso()
    sbom.component_extraction_completed_at = None
    db.add(sbom)
    db.flush()


def _mark_startup_extraction_failed(db: Session, sbom: SBOMSource, reason: str) -> None:
    sbom.component_extraction_status = COMPONENT_EXTRACTION_FAILED
    sbom.component_extraction_error = reason[:1000]
    sbom.component_extraction_attempted_at = now_iso()
    sbom.component_extraction_completed_at = None
    db.add(sbom)
    db.flush()


def _startup_component_extraction_needed(sbom: SBOMSource) -> bool:
    return (sbom.component_extraction_status or "").strip().lower() not in _FINAL_EXTRACTION_STATUSES


def _startup_skip_reason(sbom: SBOMSource) -> str | None:
    status = (sbom.status or "").strip().lower()
    if status not in _TRUSTED_SBOM_STATUSES:
        return f"SBOM validation status is '{status or 'unknown'}'; repair or revalidate before extracting components."
    _fmt, _spec_version, reason = detect_supported_component_extraction_format(sbom.sbom_data)
    return reason


def backfill_analytics_tables(
    db: Session,
    *,
    tenant_id: int,
) -> None:
    """
    Backfill the AnalysisRun table from existing SBOMSource and SBOMAnalysisReport records.

    This migrates legacy reports into the new AnalysisRun/AnalysisFinding structure,
    ensuring all historical analysis data is available for dashboard and reporting.

    Args:
        db: Database session
        tenant_id: The tenant whose SBOMs should be backfilled.  Must be a
            positive integer.  Each tenant is processed in its own session
            under an explicit tenant context established by the caller.
    """
    if not isinstance(tenant_id, int) or tenant_id <= 0:
        raise ValueError("A valid tenant_id is required for analytics backfill")

    sboms = (
        db.execute(
            select(SBOMSource)
            .where(SBOMSource.tenant_id == tenant_id)
            .order_by(SBOMSource.id.asc())
        )
        .scalars()
        .all()
    )

    for sbom in sboms:
        if int(sbom.tenant_id) != tenant_id:
            raise RuntimeError(
                "Analytics startup backfill selected an SBOM outside the active tenant"
            )
        components = []

        if _startup_component_extraction_needed(sbom):
            skip_reason = _startup_skip_reason(sbom)
            if skip_reason is not None:
                _mark_startup_extraction_skipped(db, sbom, skip_reason)
                log.info(
                    "Skipping component extraction for SBOM id=%d because %s; status marked skipped.",
                    sbom.id,
                    skip_reason,
                )
            else:
                try:
                    components = sync_sbom_components(db, sbom)
                except ComponentExtractionSkipped as exc:
                    log.info(
                        "Skipping component extraction for SBOM id=%d because %s; status marked skipped.",
                        sbom.id,
                        exc.reason,
                    )
                    components = []
                except Exception as e:
                    _mark_startup_extraction_failed(db, sbom, str(e))
                    log.warning("Component extraction failed for SBOM id=%d: %s", sbom.id, e)
                    components = []
        elif sbom.component_extraction_status == COMPONENT_EXTRACTION_SKIPPED:
            log.debug("Component extraction already skipped for SBOM id=%d: %s", sbom.id, sbom.component_extraction_error)

        # Check if analysis run already exists (tenant-scoped)
        has_run = db.execute(
            select(AnalysisRun.id).where(
                AnalysisRun.tenant_id == tenant_id,
                AnalysisRun.sbom_id == sbom.id,
            ).limit(1)
        ).scalar_one_or_none()
        if has_run is not None:
            continue

        # Look for legacy report to backfill from (tenant-scoped)
        latest_legacy = (
            db.execute(
                select(SBOMAnalysisReport)
                .where(
                    SBOMAnalysisReport.tenant_id == tenant_id,
                    SBOMAnalysisReport.sbom_ref_id == sbom.id,
                )
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
            run_status = normalize_run_status(latest_legacy.sbom_result) or compute_report_status(
                safe_int(details.get("total_findings")), details.get("query_errors") or []
            )
            used = (details.get("analysis_metadata") or {}).get("sources") or []
            source = ",".join(used) if used else "BACKFILL"
            started_on = latest_legacy.created_on or now_iso()
            completed_on = latest_legacy.created_on or started_on
        else:
            details = normalize_details({"message": "Backfilled from SBOM without legacy report."}, components)
            run_status = "NO_DATA" if not sbom.sbom_data else RUN_STATUS_OK
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

    db.flush()

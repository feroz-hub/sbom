"""Analysis orchestration service.

Owns the multi-source analysis orchestration that previously lived inside
``app/routers/sboms_crud.py``: component extraction, source fan-out, finding
deduplication, severity bucketing, run-status computation, and persistence.

Nothing here touches FastAPI request/response objects, so the same orchestration
backs the batch ``POST /analyze`` endpoint, the SSE ``POST /analyze/stream``
endpoint, and the Celery scheduled scans. Routers keep the HTTP concerns
(request parsing, auth/context, HTTPException/StreamingResponse, SSE framing);
this module keeps the business logic.
"""

from __future__ import annotations

import json
import logging
import time
from dataclasses import dataclass
from dataclasses import replace as _dc_replace

from sqlalchemy.orm import Session

from ..analysis import (
    _augment_components_with_cpe,
    deduplicate_findings,
    enrich_component_for_osv,
    extract_components,
    get_analysis_settings_multi,
)
from ..models import AnalysisRun, SBOMSource
from ..sources import (
    build_source_adapters,
    configured_default_sources,
    run_sources_concurrently,
)
from .analysis_service import compute_report_status, persist_analysis_run
from .sbom_service import now_iso

log = logging.getLogger("sbom.analysis.orchestrator")

_SEVERITY_BUCKETS = ("CRITICAL", "HIGH", "MEDIUM", "LOW", "UNKNOWN")


@dataclass
class FinalizedRun:
    """Result of finalizing an analysis run — everything a caller (batch or
    stream) needs to build its response without re-deriving anything."""

    run: AnalysisRun
    final_findings: list[dict]
    buckets: dict[str, int]
    run_status: str
    details: dict


def bucket_severities(findings: list[dict]) -> dict[str, int]:
    """Count findings per severity bucket (unknown severities fall to UNKNOWN)."""
    buckets = {name: 0 for name in _SEVERITY_BUCKETS}
    for finding in findings:
        sev = str((finding or {}).get("severity", "UNKNOWN")).upper()
        buckets[sev if sev in buckets else "UNKNOWN"] += 1
    return buckets


def finalize_analysis_run(
    db: Session,
    sbom_obj: SBOMSource,
    *,
    components: list[dict],
    raw_findings: list[dict],
    all_errors: list[dict],
    all_warnings: list[dict],
    sources_used: list[str],
    started_on: str,
    duration_ms: int,
    existing_run: AnalysisRun | None = None,
    include_query_warnings: bool = True,
) -> FinalizedRun:
    """Dedup findings, bucket severities, build the details report, compute the
    run status, and persist the run.

    Shared by ``create_analysis_report`` (batch) and the SSE stream endpoint.
    ``include_query_warnings`` preserves the pre-existing difference between the
    two report shapes (the batch report carries ``query_warnings``; the stream
    report does not). Does NOT commit — the caller owns the transaction.
    """
    final_findings = deduplicate_findings(raw_findings)
    buckets = bucket_severities(final_findings)

    details: dict = {
        "total_components": len(components),
        "components_with_cpe": sum(1 for c in components if c.get("cpe")),
        "total_findings": len(final_findings),
        "critical": buckets["CRITICAL"],
        "high": buckets["HIGH"],
        "medium": buckets["MEDIUM"],
        "low": buckets["LOW"],
        "unknown": buckets["UNKNOWN"],
        "query_errors": all_errors,
    }
    if include_query_warnings:
        details["query_warnings"] = all_warnings
    details["findings"] = final_findings
    details["analysis_metadata"] = {
        "sources": sources_used,
        "provider_status": [
            warning["provider_status"]
            for warning in all_warnings
            if isinstance(warning, dict) and isinstance(warning.get("provider_status"), dict)
        ],
    }

    run_status = compute_report_status(len(final_findings), all_errors)
    source_label = ",".join(sources_used)
    if all_errors:
        source_label += " (partial)"

    run = persist_analysis_run(
        db=db,
        sbom_obj=sbom_obj,
        details=details,
        components=components,
        run_status=run_status,
        source=source_label,
        started_on=started_on,
        completed_on=now_iso(),
        duration_ms=duration_ms,
        existing_run=existing_run,
    )
    return FinalizedRun(
        run=run,
        final_findings=final_findings,
        buckets=buckets,
        run_status=run_status,
        details=details,
    )


async def create_analysis_report(
    db: Session,
    sbom_obj: SBOMSource,
    *,
    force_refresh: bool = False,
) -> AnalysisRun | None:
    """
    Trigger default multi-source analysis for an SBOM and persist the run.

    Uses the shared ``app.sources`` adapter runner so configured sources
    (NVD, OSV, GitHub, VulDB, etc.) are fanned out consistently with the
    streaming and ad-hoc analysis endpoints.

    ``force_refresh`` (roadmap #2 PR-E): when True AND the source-response
    cache is enabled, every external-source fetch IGNORES cached hits and
    re-queries upstream — then writes the fresh result, overwriting the
    stale entry. Scheduled scans pass ``False`` (default) so they reuse
    cached responses; only an operator-triggered "scan fresh" should
    pass ``True``. No-op when ``source_cache_enabled`` is False.
    """
    if not sbom_obj.sbom_data:
        return None

    # Extract components up front so we can short-circuit empty SBOMs without
    # paying for any outbound HTTP, and so we can pass the same component list
    # into ``persist_analysis_run`` for component-row upserting.
    try:
        components_raw = extract_components(sbom_obj.sbom_data)

        # Deduplicate components before scanning
        try:
            sbom_dict = json.loads(sbom_obj.sbom_data) if isinstance(sbom_obj.sbom_data, str) else sbom_obj.sbom_data
        except Exception:
            sbom_dict = {}
        dependencies = []
        if isinstance(sbom_dict, dict):
            if sbom_dict.get("bomFormat") == "CycloneDX":
                dependencies = sbom_dict.get("dependencies") or []
            elif sbom_dict.get("spdxVersion") or sbom_dict.get("SPDXID"):
                dependencies = sbom_dict.get("relationships") or []

        from .component_deduplication_service import ComponentDeduplicationService

        canonical_raw, _, _, _, _ = ComponentDeduplicationService.deduplicate_components(components_raw, dependencies)

        components_raw = [enrich_component_for_osv(c) for c in canonical_raw]
        components, _ = _augment_components_with_cpe(components_raw)
    except Exception as exc:
        log.warning("Component extraction failed for SBOM id=%d: %s", sbom_obj.id, exc)
        return None

    if not components:
        return None

    started_on = now_iso()
    started_at = time.perf_counter()

    cfg = get_analysis_settings_multi()
    if force_refresh:
        # Per-run override via ``dataclasses.replace`` — never mutate
        # the cached singleton, which is shared across requests.
        cfg = _dc_replace(cfg, source_cache_force_refresh=True)
    sources_used = configured_default_sources()
    try:
        raw_findings, all_errors, all_warnings = await run_sources_concurrently(
            sources=build_source_adapters(sources_used),
            components=components,
            settings=cfg,
        )
    except Exception as exc:
        log.error("Auto-analysis failed for SBOM id=%d: %s", sbom_obj.id, exc, exc_info=True)
        return None

    duration_ms = int((time.perf_counter() - started_at) * 1000)
    result = finalize_analysis_run(
        db,
        sbom_obj,
        components=components,
        raw_findings=raw_findings,
        all_errors=all_errors,
        all_warnings=all_warnings,
        sources_used=sources_used,
        started_on=started_on,
        duration_ms=duration_ms,
        include_query_warnings=True,
    )
    db.commit()
    return result.run

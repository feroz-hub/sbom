"""Application service for every SBOM vulnerability-analysis entry point."""

from __future__ import annotations

import asyncio
import json
import logging
import time
from dataclasses import dataclass, replace
from typing import Any

from sqlalchemy import select
from sqlalchemy.orm import Session

from ..analysis import _augment_components_with_cpe, enrich_component_for_osv, get_analysis_settings_multi
from ..models import AnalysisRun, SBOMComponent, SBOMSource
from ..sources import (
    build_source_adapters,
    configured_default_sources,
    deduplicate_findings,
    normalize_source_names,
    run_sources_concurrently,
)
from ..sources.routing import count_authoritative_cpes
from .analysis_service import (
    compute_report_status,
    filter_unconfirmed_provider_findings,
    get_active_analysis_run,
    mark_analysis_run_failed,
    persist_analysis_run,
)
from .sbom_service import (
    MISSING_SBOM_CONTENT_REASON,
    UNPARSEABLE_SBOM_CONTENT_REASON,
    UNSUPPORTED_SBOM_FORMAT_REASON,
    ComponentExtractionSkipped,
    load_sbom_from_ref,
    now_iso,
    sync_sbom_components,
)

log = logging.getLogger(__name__)


class AnalysisOrchestrationError(RuntimeError):
    """A run failed after its durable state record was created."""

    def __init__(self, message: str, *, run_id: int | None = None, category: str = "analysis_failure") -> None:
        super().__init__(message)
        self.run_id = run_id
        self.category = category


@dataclass(slots=True)
class AnalysisExecution:
    sources: list[str]
    components: list[dict[str, Any]]
    findings: list[dict[str, Any]]
    errors: list[dict[str, Any]]
    warnings: list[dict[str, Any]]
    details: dict[str, Any]
    buckets: dict[str, int]
    run_status: str
    source_label: str


class AnalysisOrchestrator:
    """Own the durable, best-effort multi-provider analysis lifecycle."""

    def __init__(self, db: Session) -> None:
        self.db = db

    def resolve_sbom(
        self,
        *,
        sbom_id: int | None,
        sbom_name: str | None,
    ) -> tuple[SBOMSource, str, str]:
        sbom, _parsed, sbom_format, spec_version, _components = load_sbom_from_ref(
            self.db,
            sbom_id=sbom_id,
            sbom_name=sbom_name,
        )
        return sbom, sbom_format, spec_version

    def active_run(self, sbom_id: int) -> AnalysisRun | None:
        return get_active_analysis_run(self.db, sbom_id)

    @staticmethod
    def _component_input(row: SBOMComponent) -> dict[str, Any]:
        return {
            "bom_ref": row.bom_ref,
            "type": row.component_type,
            "group": row.component_group,
            "name": row.name,
            "version": row.version,
            "purl": row.normalized_purl or row.purl,
            "cpe": row.primary_cpe or row.cpe,
            "cpe_source": row.cpe_source,
            "supplier": row.supplier,
            "scope": row.scope,
            "license": row.license,
            "hashes": row.hashes,
            "ecosystem": row.normalized_ecosystem or row.ecosystem,
            "normalized_name": row.normalized_name,
            "normalized_version": row.normalized_version,
            "normalized_ecosystem": row.normalized_ecosystem,
            "normalized_purl": row.normalized_purl,
            "normalized_component_key": row.normalized_component_key,
            "primary_cpe": row.primary_cpe,
            "normalized_cpes": row.normalized_cpes,
        }

    def load_components(
        self,
        sbom: SBOMSource,
        *,
        run_id: int | None,
        correlation_id: str | None = None,
    ) -> list[dict[str, Any]]:
        def _rows() -> list[SBOMComponent]:
            return list(
                self.db.execute(
                    select(SBOMComponent)
                    .where(
                        SBOMComponent.sbom_id == sbom.id,
                        (SBOMComponent.is_duplicate.is_(False)) | (SBOMComponent.is_duplicate.is_(None)),
                    )
                    .order_by(SBOMComponent.id.asc())
                ).scalars()
            )

        rows = _rows()
        components = [self._component_input(row) for row in rows]
        if not components:
            try:
                extracted = sync_sbom_components(self.db, sbom)
                self.db.commit()
                rows = _rows()
                components = [self._component_input(row) for row in rows] or extracted
            except ComponentExtractionSkipped as exc:
                self.db.rollback()
                if exc.reason in {
                    MISSING_SBOM_CONTENT_REASON,
                    UNPARSEABLE_SBOM_CONTENT_REASON,
                    UNSUPPORTED_SBOM_FORMAT_REASON,
                }:
                    raise
                components = []
            except Exception:
                self.db.rollback()
                log.exception(
                    "analysis.component_query.sync_failed",
                    extra={"analysis_run_id": run_id, "sbom_id": sbom.id, "correlation_id": correlation_id},
                )
                raise

        components = [enrich_component_for_osv(component) for component in components]
        components, _generated_cpe = _augment_components_with_cpe(components)
        log.info(
            "analysis.component_query.completed",
            extra={
                "event": "analysis_component_query_completed",
                "analysis_run_id": run_id,
                "sbom_id": sbom.id,
                "raw_component_count": len(rows),
                "deduplicated_component_count": len(components),
                "components_loaded": len(components),
                "components_with_purl": sum(
                    1 for component in components if component.get("purl") or component.get("normalized_purl")
                ),
                "components_with_cpe": count_authoritative_cpes(components),
                "components_selected_for_analysis": len(components),
                "correlation_id": correlation_id,
            },
        )
        return components

    def create_pending_run(
        self,
        sbom: SBOMSource,
        *,
        sources: list[str],
        trigger_source: str,
        started_on: str,
        sbom_name: str | None = None,
    ) -> AnalysisRun:
        run = AnalysisRun(
            sbom_id=sbom.id,
            project_id=sbom.projectid,
            product_id=sbom.product_id,
            run_status="PENDING",
            sbom_name=sbom_name,
            source=",".join(sources),
            trigger_source=trigger_source,
            started_on=started_on,
            completed_on=started_on,
            duration_ms=0,
            total_components=0,
            components_with_cpe=0,
            total_findings=0,
            raw_report=json.dumps({"status": "queued", "message": "Analysis queued.", "sources": sources}),
        )
        self.db.add(run)
        self.db.commit()
        self.db.refresh(run)
        return run

    def mark_running(self, run: AnalysisRun, *, sources: list[str], components: list[dict] | None = None) -> None:
        run.run_status = "RUNNING"
        run.source = ",".join(sources)
        payload: dict[str, Any] = {"status": "running", "sources": sources}
        if components is not None:
            run.total_components = len(components)
            run.components_with_cpe = count_authoritative_cpes(components)
            payload.update(
                total_components=len(components),
                components_with_cpe=run.components_with_cpe,
                components_with_purl=sum(
                    1 for component in components if component.get("purl") or component.get("normalized_purl")
                ),
            )
        run.raw_report = json.dumps(payload)
        self.db.add(run)
        self.db.commit()

    async def execute_providers(
        self,
        *,
        components: list[dict[str, Any]],
        sources: list[str] | None,
        force_refresh: bool = False,
        progress_queue: asyncio.Queue | None = None,
    ) -> AnalysisExecution:
        source_names = normalize_source_names(sources, default=configured_default_sources())
        adapters = build_source_adapters(source_names)
        if not adapters:
            raise AnalysisOrchestrationError(f"No supported sources requested. Got {sources!r}.")
        settings = get_analysis_settings_multi()
        if force_refresh:
            settings = replace(settings, source_cache_force_refresh=True)
        raw_findings, errors, warnings = await run_sources_concurrently(
            sources=adapters,
            components=components,
            settings=settings,
            progress_queue=progress_queue,
        )
        findings = deduplicate_findings(raw_findings)
        findings = filter_unconfirmed_provider_findings({"findings": findings}, components)["findings"]
        buckets = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0, "UNKNOWN": 0}
        for finding in findings:
            severity = str((finding or {}).get("severity", "UNKNOWN")).upper()
            buckets[severity if severity in buckets else "UNKNOWN"] += 1
        source_summary = [
            warning["source_summary"]
            for warning in warnings
            if isinstance(warning, dict) and isinstance(warning.get("source_summary"), dict)
        ]
        provider_status = [
            warning["provider_status"]
            for warning in warnings
            if isinstance(warning, dict) and isinstance(warning.get("provider_status"), dict)
        ]
        details = {
            "total_components": len(components),
            "components_with_cpe": count_authoritative_cpes(components),
            "total_findings": len(findings),
            "critical": buckets["CRITICAL"],
            "high": buckets["HIGH"],
            "medium": buckets["MEDIUM"],
            "low": buckets["LOW"],
            "unknown": buckets["UNKNOWN"],
            "query_errors": errors,
            "query_warnings": warnings,
            "source_summary": source_summary,
            "findings": findings,
            "analysis_metadata": {
                "sources": source_names,
                "raw_observation_count": len(raw_findings),
                "source_summary": source_summary,
                "provider_status": provider_status,
            },
        }
        source_label = ",".join(source_names) + (" (partial)" if errors else "")
        return AnalysisExecution(
            sources=source_names,
            components=components,
            findings=findings,
            errors=errors,
            warnings=warnings,
            details=details,
            buckets=buckets,
            run_status=compute_report_status(len(findings), errors),
            source_label=source_label,
        )

    def persist(
        self,
        *,
        sbom: SBOMSource,
        execution: AnalysisExecution,
        started_on: str,
        duration_ms: int,
        trigger_source: str,
        existing_run: AnalysisRun | None = None,
        correlation_id: str | None = None,
    ) -> AnalysisRun:
        run = persist_analysis_run(
            db=self.db,
            sbom_obj=sbom,
            details=execution.details,
            components=execution.components,
            run_status=execution.run_status,
            source=execution.source_label,
            started_on=started_on,
            completed_on=now_iso(),
            duration_ms=duration_ms,
            existing_run=existing_run,
            trigger_source=trigger_source,
            correlation_id=correlation_id,
        )
        self.db.commit()
        return run

    def fail_run(
        self,
        run: AnalysisRun,
        *,
        message: str,
        started_at: float,
        category: str,
        correlation_id: str | None = None,
    ) -> None:
        try:
            self.db.rollback()
        except Exception:
            log.exception("analysis.rollback_failed", extra={"run_id": run.id})
        mark_analysis_run_failed(
            self.db,
            run_id=int(run.id),
            error_message=message,
            completed_on=now_iso(),
            duration_ms=int((time.perf_counter() - started_at) * 1000),
            code=500,
            sources=normalize_source_names(run.source.split(",") if run.source else None),
            correlation_id=correlation_id,
            error_category=category,
        )
        self.db.commit()

    async def run(
        self,
        sbom: SBOMSource,
        *,
        sources: list[str] | None = None,
        trigger_source: str = "manual",
        force_refresh: bool = False,
        correlation_id: str | None = None,
        progress_queue: asyncio.Queue | None = None,
    ) -> tuple[AnalysisRun, AnalysisExecution | None] | None:
        existing = self.active_run(int(sbom.id))
        if existing is not None:
            return existing, None
        source_names = normalize_source_names(sources, default=configured_default_sources())
        started_on = now_iso()
        started_at = time.perf_counter()
        components = self.load_components(sbom, run_id=None, correlation_id=correlation_id)
        if not components:
            return None
        run = self.create_pending_run(
            sbom,
            sources=source_names,
            trigger_source=trigger_source,
            started_on=started_on,
            sbom_name=sbom.sbom_name if trigger_source == "api" else None,
        )
        try:
            self.mark_running(run, sources=source_names, components=components)
            execution = await self.execute_providers(
                components=components,
                sources=source_names,
                force_refresh=force_refresh,
                progress_queue=progress_queue,
            )
            persisted = self.persist(
                sbom=sbom,
                execution=execution,
                started_on=started_on,
                duration_ms=int((time.perf_counter() - started_at) * 1000),
                trigger_source=trigger_source,
                existing_run=run,
                correlation_id=correlation_id,
            )
            return persisted, execution
        except Exception as exc:
            self.fail_run(
                run,
                message="Analysis failed while processing the SBOM.",
                started_at=started_at,
                category="analysis_execution_failure",
                correlation_id=correlation_id,
            )
            raise AnalysisOrchestrationError(
                "Analysis failed while processing the SBOM.",
                run_id=int(run.id),
                category="analysis_execution_failure",
            ) from exc

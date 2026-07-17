"""
NVD (NIST National Vulnerability Database) source adapter.

Phase 2 implementation: thin delegation wrapper around the existing
``app.analysis.nvd_query_by_components_async`` coroutine. Phase 5 will
physically move that function body (and its helpers ``_finding_from_raw``,
``nvd_query_by_cpe``, ``resolve_nvd_api_key``) into this module.

Construction takes ``api_key`` so the adapter never has to read
``os.environ`` from inside a request handler — the credential is bound at
construction time and threaded explicitly through to the underlying call.
"""

from __future__ import annotations

import asyncio
from typing import Any

from .base import SourceResult, empty_result


class NvdSource:
    """``VulnSource`` adapter for the NVD REST 2.0 API."""

    name: str = "NVD"

    def __init__(
        self,
        api_key: str | None = None,
        *,
        lookup_service: Any = None,
    ) -> None:
        self.api_key = (api_key or "").strip() or None
        # Optional per-CPE callable with shape `(cpe, api_key, settings)
        # -> list[dict]`. When provided (production wiring through
        # `build_source_adapters`), NVD lookups consult the local mirror
        # first and fall back to live NVD per the facade's 5-branch
        # decision logic. When None, the underlying coroutine hits live
        # NVD directly — the path tests use.
        self._lookup_service = lookup_service

    async def query(
        self,
        components: list[dict],
        settings: Any,
    ) -> SourceResult:
        if not components:
            return empty_result()

        # Compatibility entry point for callers outside the orchestrator.
        # Production's runner calls query_with_vulnerabilities below.
        from app.analysis import nvd_query_by_components_async

        findings, errors, warnings = await nvd_query_by_components_async(
            components,
            settings,
            nvd_api_key=self.api_key,
            lookup_service=self._lookup_service,
        )
        return SourceResult(findings=findings, errors=errors, warnings=warnings)

    async def query_with_vulnerabilities(
        self,
        components: list[dict],
        vulnerabilities: list[dict],
        settings: Any,
    ) -> SourceResult:
        """Enrich known CVEs in batches, then use only trusted CPEs."""

        import app.analysis as analysis_module

        legacy_override = analysis_module.nvd_query_by_components_async
        if not getattr(legacy_override, "_production_safe", False):
            findings, errors, warnings = await legacy_override(
                components,
                settings,
                nvd_api_key=self.api_key,
                lookup_service=self._lookup_service,
            )
            return SourceResult(findings=findings, errors=errors, warnings=warnings)

        from app.analysis import (
            NvdRejectionReason,
            NvdRejectionTracker,
            _finding_from_applicable_nvd_raw,
            _nvd_finding_key,
            _nvd_rejection_from_component,
        )
        from app.db import SessionLocal
        from app.services.nvd_enrichment_service import NvdEnrichmentService, collect_nvd_identifiers
        from app.settings import get_settings

        rejection_tracker = NvdRejectionTracker(settings=settings, components_checked=len(components))
        seen_findings: set[tuple[str, str, str | None, str | None, str | None]] = set()

        mirror_findings: list[dict] = []
        remaining_components = list(components)
        if self._lookup_service is not None and getattr(self._lookup_service, "cache_only", False):
            mirror_hit_cpes: set[str] = set()
            trusted = collect_nvd_identifiers(components, []).trusted_cpes
            for cpe, component in trusted[: get_settings().nvd_max_cpe_lookups_per_scan]:
                records = await asyncio.to_thread(self._lookup_service, cpe)
                if not records:
                    continue
                mirror_hit_cpes.add(cpe)
                for raw in records:
                    rejection_tracker.record_candidate()
                    if not isinstance(raw, dict):
                        rejection_tracker.record_rejection(
                            _nvd_rejection_from_component(
                                reason=NvdRejectionReason.INVALID_NVD_RECORD,
                                raw=None,
                                component=component,
                                identifier=cpe,
                                detail="NVD mirror record was not an object",
                            )
                        )
                        continue
                    finding = _finding_from_applicable_nvd_raw(raw, cpe, component, settings, rejection_tracker)
                    if finding is None:
                        continue
                    finding["match_strategy"] = "cpe_name"
                    finding_key = _nvd_finding_key(finding)
                    if finding_key in seen_findings:
                        rejection_tracker.record_rejection(
                            _nvd_rejection_from_component(
                                reason=NvdRejectionReason.DUPLICATE_FINDING,
                                raw=raw,
                                component=component,
                                identifier=cpe,
                                matched_cpe=finding.get("cpe"),
                                detail="Duplicate NVD finding for component and CVE",
                            )
                        )
                        continue
                    seen_findings.add(finding_key)
                    mirror_findings.append(finding)
                    rejection_tracker.record_acceptance()
            remaining_components = [
                component for component in components if component.get("cpe") not in mirror_hit_cpes
            ]

        nvd_vulnerabilities = vulnerabilities
        if not collect_nvd_identifiers(remaining_components, []).trusted_cpes:
            nvd_vulnerabilities = []

        def _run() -> dict[str, Any]:
            db = SessionLocal()
            try:
                cfg = get_settings()
                if self.api_key is not None and self.api_key != cfg.nvd_api_key:
                    cfg = cfg.model_copy(update={"nvd_api_key": self.api_key})
                return NvdEnrichmentService(db, cfg).enrich(remaining_components, nvd_vulnerabilities)
            finally:
                db.close()

        result = await asyncio.to_thread(_run)
        provider_status = result["provider_status"]
        rejection_tracker.components_queried = int(provider_status.get("total_identifiers") or 0)
        findings: list[dict] = list(mirror_findings)
        for record in result["records"]:
            rejection_tracker.record_candidate()
            raw = record["raw"]
            identifier = record["identifier"]
            component = record.get("component") or {}
            if not isinstance(raw, dict):
                rejection_tracker.record_rejection(
                    _nvd_rejection_from_component(
                        reason=NvdRejectionReason.INVALID_NVD_RECORD,
                        raw=None,
                        component=component,
                        identifier=identifier,
                        detail="NVD provider record was missing a CVE object",
                    )
                )
                continue
            finding = _finding_from_applicable_nvd_raw(raw, identifier, component, settings, rejection_tracker)
            if finding is None:
                continue
            finding["match_strategy"] = "cve_ids" if identifier.upper().startswith("CVE-") else "cpe_name"
            finding_key = _nvd_finding_key(finding)
            if finding_key in seen_findings:
                rejection_tracker.record_rejection(
                    _nvd_rejection_from_component(
                        reason=NvdRejectionReason.DUPLICATE_FINDING,
                        raw=raw,
                        component=component,
                        identifier=identifier,
                        matched_cpe=finding.get("cpe"),
                        detail="Duplicate NVD finding for component and CVE",
                    )
                )
                continue
            seen_findings.add(finding_key)
            findings.append(finding)
            rejection_tracker.record_acceptance()
        if mirror_findings:
            provider_status["cache_hits"] += len(mirror_findings)
            provider_status["status"] = (
                "success" if provider_status["status"] == "skipped" else provider_status["status"]
            )
        errors = []
        if provider_status["status"] == "degraded":
            errors.append(
                {
                    "source": "NVD",
                    "reason": "rate_limited_or_unavailable",
                    "error": provider_status.get("error_message") or "NVD degraded",
                    "provider_status": provider_status,
                }
            )
        rejection_summary = rejection_tracker.emit_summary()
        provider_status["candidate_findings"] = rejection_summary["candidate_findings"]
        provider_status["accepted_findings"] = rejection_summary["accepted_findings"]
        provider_status["rejected_findings"] = rejection_summary["total_rejected"]
        provider_status["rejections_by_reason"] = rejection_summary["by_reason"]
        return SourceResult(
            findings=findings,
            errors=errors,
            warnings=[{"source": "NVD", "provider_status": provider_status, "rejection_summary": rejection_summary}],
        )

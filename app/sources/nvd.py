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

        from app.analysis import _finding_from_raw
        from app.db import SessionLocal
        from app.services.nvd_enrichment_service import NvdEnrichmentService, collect_nvd_identifiers
        from app.settings import get_settings

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
                    finding = _finding_from_raw(
                        raw,
                        cpe,
                        component.get("name") or "",
                        component.get("version"),
                        settings,
                    )
                    finding["match_strategy"] = "cpe_name"
                    mirror_findings.append(finding)
            remaining_components = [
                component for component in components if component.get("cpe") not in mirror_hit_cpes
            ]

        def _run() -> dict[str, Any]:
            db = SessionLocal()
            try:
                cfg = get_settings()
                if self.api_key is not None and self.api_key != cfg.nvd_api_key:
                    cfg = cfg.model_copy(update={"nvd_api_key": self.api_key})
                return NvdEnrichmentService(db, cfg).enrich(remaining_components, vulnerabilities)
            finally:
                db.close()

        result = await asyncio.to_thread(_run)
        provider_status = result["provider_status"]
        findings: list[dict] = list(mirror_findings)
        for record in result["records"]:
            raw = record["raw"]
            identifier = record["identifier"]
            component = record.get("component") or {}
            finding = _finding_from_raw(
                raw,
                identifier,
                component.get("component_name") or component.get("name") or "",
                component.get("component_version") or component.get("version"),
                settings,
            )
            finding["match_strategy"] = "cve_ids" if identifier.upper().startswith("CVE-") else "cpe_name"
            findings.append(finding)
        if mirror_findings:
            provider_status["cache_hits"] += len(mirror_findings)
            provider_status["status"] = "success" if provider_status["status"] == "skipped" else provider_status["status"]
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
        return SourceResult(
            findings=findings,
            errors=errors,
            warnings=[{"source": "NVD", "provider_status": provider_status}],
        )

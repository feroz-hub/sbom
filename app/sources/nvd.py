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

        # Lazy import: ``app.analysis`` re-exports symbols from ``app.sources``
        # at module load time, so a top-level import here would create a
        # circular import. The lazy import is paid once per process.
        from app.analysis import nvd_query_by_components_async

        findings, errors, warnings = await nvd_query_by_components_async(
            components,
            settings,
            nvd_api_key=self.api_key,
            lookup_service=self._lookup_service,
        )
        return SourceResult(findings=findings, errors=errors, warnings=warnings)

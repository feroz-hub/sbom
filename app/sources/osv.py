"""
OSV (Open Source Vulnerabilities) source adapter.

Phase 2 implementation: thin delegation wrapper around the existing
``app.analysis.osv_query_by_components`` coroutine. Phase 5 will physically
move that function body and its helpers (``_best_score_and_vector_from_osv``,
``extract_cwe_from_osv``, ``extract_fixed_versions_osv``, ``enrich_component_for_osv``)
into this module.

OSV needs no credentials, so the constructor takes no arguments.
"""

from __future__ import annotations

from typing import Any

from .base import SourceResult, empty_result


class OsvSource:
    """``VulnSource`` adapter for the OSV v1 batch API."""

    name: str = "OSV"

    def __init__(self) -> None:
        # OSV is unauthenticated; constructor exists for parity with the
        # other adapters and so the registry can ``cls()`` uniformly.
        pass

    async def query(
        self,
        components: list[dict],
        settings: Any,
    ) -> SourceResult:
        if not components:
            return empty_result()

        # Lazy import to avoid the circular load that would otherwise occur
        # because ``app.analysis`` already re-exports symbols from
        # ``app.sources``. Paid once per process.
        from app.analysis import osv_query_by_components

        findings, errors, warnings = await osv_query_by_components(components, settings)
        return SourceResult(findings=findings, errors=errors, warnings=warnings)

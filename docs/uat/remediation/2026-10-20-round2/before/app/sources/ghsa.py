"""
GitHub Security Advisories (GHSA) source adapter.

Phase 2 implementation: thin delegation wrapper around the existing
``app.analysis.github_query_by_components`` coroutine. Phase 5 will
physically move that function body and its helpers
(``_github_ecosystem_from_purl_type``, ``extract_cwe_from_ghsa``) into
this module.

The GitHub token is bound at construction time. Internally we use
``dataclasses.replace`` to push it onto the existing ``_MultiSettings`` via
``gh_token_override`` so the underlying coroutine continues to receive it
through the same field — but call sites no longer have to know about that
plumbing. After Phase 5, the underlying coroutine will read the token
straight off ``self`` instead of via the settings object.
"""

from __future__ import annotations

from dataclasses import replace as dataclass_replace
from typing import Any

from .base import SourceResult, empty_result


class GhsaSource:
    """``VulnSource`` adapter for the GitHub Security Advisories GraphQL API."""

    name: str = "GITHUB"

    def __init__(self, token: str | None = None) -> None:
        self.token = (token or "").strip() or None

    async def query(
        self,
        components: list[dict],
        settings: Any,
    ) -> SourceResult:
        if not components:
            return empty_result()

        # Lazy import to break the circular load with ``app.analysis``.
        from app.analysis import github_query_by_components

        # Push the constructor-bound token onto the settings object via
        # ``dataclasses.replace`` if the settings object supports it. This
        # keeps backwards compatibility with the existing
        # ``github_query_by_components`` signature while letting Phase 3
        # call sites construct adapters with explicit credentials.
        effective_settings = settings
        if self.token is not None:
            try:
                effective_settings = dataclass_replace(settings, gh_token_override=self.token)
            except (TypeError, ValueError):
                # Settings object isn't a dataclass with that field — fall
                # through and let the coroutine read GITHUB_TOKEN from env.
                effective_settings = settings

        findings, errors, warnings = await github_query_by_components(components, effective_settings)
        return SourceResult(findings=findings, errors=errors, warnings=warnings)

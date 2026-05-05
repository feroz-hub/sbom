"""Custom OpenAI-compatible provider — the escape hatch.

Phase 1 §1.3. For LM Studio, LocalAI, LiteLLM proxies, or any
self-hosted server speaking the OpenAI Chat Completions protocol.

The user supplies a base URL (mandatory), an optional API key (many
local setups use a placeholder like ``EMPTY``), a free-text model
name, and optional rate-limit / cost overrides. Cost defaults to $0
because most callers running this on their own infrastructure don't
have a per-token cost from their own perspective.

Validation (Phase 1 §3.2 hard rule via Phase 4 anti-pattern §7):
``base_url`` must start with ``https://`` or ``http://localhost``.
This blocks the most common foot-gun (a misconfigured ``http://``
URL pointing somewhere on the public internet, leaking traffic).
"""

from __future__ import annotations

import logging
from typing import Any
from urllib.parse import urlparse

from .base import (
    ConnectionTestResult,
    LlmProvider,
    LlmRequest,
    LlmResponse,
    ProviderInfo,
    ProviderUnavailableError,
)
from .openai import OpenAiProvider

log = logging.getLogger("sbom.ai.providers.custom_openai_compatible")


def _validate_base_url(url: str) -> str:
    """Reject scheme-less or plaintext-public URLs.

    Allowed:
      * any ``https://`` URL
      * ``http://`` URLs that resolve to a local hostname
        (``localhost`` / ``127.0.0.1`` / ``::1`` / ``host.docker.internal``)

    Rejected:
      * scheme-less strings
      * non-localhost ``http://`` URLs (would leak API key + traffic
        to a plaintext public endpoint)
    """
    if not url:
        raise ProviderUnavailableError("custom_openai: base_url is required")
    parsed = urlparse(url)
    if parsed.scheme not in ("http", "https"):
        raise ProviderUnavailableError(
            f"custom_openai: base_url must start with https:// or http:// (got {url!r})"
        )
    if parsed.scheme == "http":
        host = (parsed.hostname or "").lower()
        if host not in {"localhost", "127.0.0.1", "::1", "host.docker.internal"}:
            raise ProviderUnavailableError(
                f"custom_openai: http:// only allowed for localhost; use https:// for {host!r}"
            )
    return url


class CustomOpenAiCompatibleProvider(LlmProvider):
    """Implements :class:`LlmProvider` for arbitrary OpenAI-compatible endpoints."""

    name: str = "custom_openai"

    def __init__(
        self,
        *,
        base_url: str,
        api_key: str = "EMPTY",
        default_model: str,
        client_factory: Any | None = None,
        max_concurrent: int = 8,
        rate_per_minute: float | None = None,
        max_retries: int = 2,
        breaker_threshold: int = 5,
        breaker_reset_seconds: float = 60.0,
        request_timeout_seconds: float = 60.0,
        cost_per_1k_input_usd: float = 0.0,
        cost_per_1k_output_usd: float = 0.0,
        is_local: bool = True,
    ) -> None:
        validated = _validate_base_url(base_url)
        if not default_model:
            raise ProviderUnavailableError("custom_openai: default_model is required (free-text)")

        self.default_model = default_model
        self.is_local = is_local
        self.max_concurrent = max_concurrent
        self._cost_in = float(cost_per_1k_input_usd)
        self._cost_out = float(cost_per_1k_output_usd)
        self._base_url = validated

        # No-rate-limit default — most local setups want full throughput.
        effective_rpm = float(rate_per_minute or 5000.0)

        self._inner = OpenAiProvider(
            api_key=api_key or "EMPTY",
            default_model=default_model,
            base_url=validated,
            client_factory=client_factory,
            max_concurrent=max_concurrent,
            rate_per_minute=effective_rpm,
            max_retries=max_retries,
            breaker_threshold=breaker_threshold,
            breaker_reset_seconds=breaker_reset_seconds,
            request_timeout_seconds=request_timeout_seconds,
        )
        self._inner.name = self.name

    async def generate(self, req: LlmRequest) -> LlmResponse:
        resp = await self._inner.generate(req)
        # Override the cost calculation: the OpenAI cost table doesn't
        # know this provider; the user supplied (possibly zero) overrides.
        cost = (
            (resp.usage.input_tokens / 1000.0) * self._cost_in
            + (resp.usage.output_tokens / 1000.0) * self._cost_out
        )
        return resp.model_copy(
            update={
                "provider": self.name,
                "usage": resp.usage.model_copy(update={"cost_usd": round(cost, 6)}),
            }
        )

    async def health_check(self) -> bool:
        return await self._inner.health_check()

    async def test_connection(self, *, model: str | None = None) -> ConnectionTestResult:
        result = await self._inner.test_connection(model=model)
        return result.model_copy(update={"provider": self.name})

    def info(self) -> ProviderInfo:
        return ProviderInfo(
            name=self.name,
            available=True,
            default_model=self.default_model,
            supports_structured_output=True,
            is_local=self.is_local,
            notes=f"Custom OpenAI-compatible endpoint at {self._base_url}",
        )

    def breaker_state(self) -> dict[str, object]:
        return self._inner.breaker_state()

    def estimate_cost_usd(self, *, model: str, input_text: str, max_output_tokens: int) -> float:
        from ..cost import estimate_tokens

        in_tok = estimate_tokens(input_text)
        return round(
            (in_tok / 1000.0) * self._cost_in
            + (max_output_tokens / 1000.0) * self._cost_out,
            6,
        )


__all__ = ["CustomOpenAiCompatibleProvider"]

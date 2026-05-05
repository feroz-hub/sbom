"""Google Gemini provider — OpenAI-compatible endpoint.

Phase 1 §1.1. Gemini exposes an OpenAI-compatible chat-completions
endpoint at ``https://generativelanguage.googleapis.com/v1beta/openai/``,
so the implementation is a thin specialisation of :class:`OpenAiProvider`
that overrides:

  * the base URL
  * the default model (``gemini-2.5-flash`` — the free-tier sweet spot)
  * the rate limit (15 RPM on Flash free tier; tighter for Pro)
  * the cost lookup (uses the Gemini ``PRICING`` table, not OpenAI's)

The ``tier`` argument sets the rate-limit bucket. ``"free"`` clamps to
15 RPM regardless of what the caller supplied, so the orchestrator
can't accidentally over-saturate a free key. ``"paid"`` uses whatever
``rate_per_minute`` the registry passed.

Reference: https://ai.google.dev/gemini-api/docs/openai
"""

from __future__ import annotations

import logging
from typing import Any, Literal

from .base import (
    ConnectionTestResult,
    LlmProvider,
    LlmRequest,
    LlmResponse,
    ProviderInfo,
    ProviderUnavailableError,
)
from .openai import OpenAiProvider

log = logging.getLogger("sbom.ai.providers.gemini")

_BASE_URL = "https://generativelanguage.googleapis.com/v1beta/openai"

# Free-tier rate limits (Flash 2.5; Pro is tighter at 5 RPM and the user
# is responsible for not selecting it for batch work).
_FREE_TIER_RPM = 15
_FREE_TIER_DAILY_TOKENS = 1_000_000


class GeminiProvider(LlmProvider):
    """Implements :class:`LlmProvider` against Gemini's OpenAI-compatible endpoint."""

    name: str = "gemini"

    def __init__(
        self,
        *,
        api_key: str,
        default_model: str = "gemini-2.5-flash",
        tier: Literal["free", "paid"] = "free",
        client_factory: Any | None = None,
        max_concurrent: int = 4,
        rate_per_minute: float | None = None,
        max_retries: int = 3,
        breaker_threshold: int = 5,
        breaker_reset_seconds: float = 60.0,
        request_timeout_seconds: float = 30.0,
    ) -> None:
        if not api_key:
            raise ProviderUnavailableError("gemini: api_key is required")

        # Free-tier clamp: never saturate above the documented limit.
        # Paid tier honors the caller's rate (default 1500 RPM is a safe
        # placeholder for paid Gemini, which is much higher in practice).
        if tier == "free":
            effective_rpm = float(min(_FREE_TIER_RPM, rate_per_minute or _FREE_TIER_RPM))
        else:
            effective_rpm = float(rate_per_minute or 1500.0)

        self._tier = tier
        self.default_model = default_model
        self.is_local = False
        self.max_concurrent = max_concurrent

        # Internal OpenAI-compatible client. The cost lookup picks the
        # Gemini PRICING table by way of ``provider="gemini"``.
        self._inner = OpenAiProvider(
            api_key=api_key,
            default_model=default_model,
            base_url=_BASE_URL,
            client_factory=client_factory,
            max_concurrent=max_concurrent,
            rate_per_minute=effective_rpm,
            max_retries=max_retries,
            breaker_threshold=breaker_threshold,
            breaker_reset_seconds=breaker_reset_seconds,
            request_timeout_seconds=request_timeout_seconds,
        )
        # Override the inner provider's identity so cost / metrics /
        # ledger rows attribute to "gemini", not "openai".
        self._inner.name = self.name

    @property
    def tier(self) -> Literal["free", "paid"]:
        return self._tier

    async def generate(self, req: LlmRequest) -> LlmResponse:
        return await self._inner.generate(req)

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
            is_local=False,
            notes=(
                "Free tier (15 req/min · 1M tokens/day)."
                if self._tier == "free"
                else "Paid tier."
            ),
        )

    def breaker_state(self) -> dict[str, object]:
        return self._inner.breaker_state()

    def estimate_cost_usd(self, *, model: str, input_text: str, max_output_tokens: int) -> float:
        return self._inner.estimate_cost_usd(
            model=model,
            input_text=input_text,
            max_output_tokens=max_output_tokens,
        )

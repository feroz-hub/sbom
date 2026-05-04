"""xAI Grok provider — OpenAI-compatible endpoint.

Phase 1 §1.2. Grok's xAI API speaks the OpenAI Chat Completions
protocol at ``https://api.x.ai/v1``, so the implementation is a thin
specialisation of :class:`OpenAiProvider` with provider-specific
defaults:

  * default model ``grok-2-mini`` (free tier)
  * free-tier rate ~ 60 RPM (~1 req/sec) with a 25k tokens/day daily
    cap that this layer cannot enforce — the orchestrator should treat
    the daily cap as advisory and stop the batch if it observes
    ``rate_limit`` errors

Reference: https://docs.x.ai/docs
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

log = logging.getLogger("sbom.ai.providers.grok")

_BASE_URL = "https://api.x.ai/v1"

_FREE_TIER_RPM = 60       # ~1 req/sec
_FREE_TIER_DAILY_TOKENS = 25_000


class GrokProvider(LlmProvider):
    """Implements :class:`LlmProvider` against xAI's Grok API."""

    name: str = "grok"

    def __init__(
        self,
        *,
        api_key: str,
        default_model: str = "grok-2-mini",
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
            raise ProviderUnavailableError("grok: api_key is required")

        if tier == "free":
            effective_rpm = float(min(_FREE_TIER_RPM, rate_per_minute or _FREE_TIER_RPM))
        else:
            effective_rpm = float(rate_per_minute or 600.0)

        self._tier = tier
        self.default_model = default_model
        self.is_local = False
        self.max_concurrent = max_concurrent

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
                f"Free tier (~{_FREE_TIER_RPM} req/min, {_FREE_TIER_DAILY_TOKENS} tokens/day cap). "
                "Tight for batch — best for one-off CVE clicks."
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

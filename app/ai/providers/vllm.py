"""vLLM provider — self-hosted, OpenAI-compatible.

vLLM exposes an OpenAI-compatible Chat Completions endpoint, so the
implementation is a thin specialisation of :class:`OpenAiProvider` with
no api key and ``is_local=True`` (zero billing).

Reference: https://docs.vllm.ai/en/latest/serving/openai_compatible_server.html
"""

from __future__ import annotations

import logging
from typing import Any

from .base import ConnectionTestResult, LlmProvider, LlmRequest, LlmResponse, ProviderInfo
from .openai import OpenAiProvider

log = logging.getLogger("sbom.ai.providers.vllm")


class VllmProvider(LlmProvider):
    """Self-hosted vLLM. Wraps :class:`OpenAiProvider`."""

    name: str = "vllm"

    def __init__(
        self,
        *,
        base_url: str,
        default_model: str,
        api_key: str = "EMPTY",
        client_factory: Any | None = None,
        max_concurrent: int = 32,
        rate_per_minute: float = 5000.0,
        max_retries: int = 2,
        breaker_threshold: int = 5,
        breaker_reset_seconds: float = 30.0,
        request_timeout_seconds: float = 120.0,
    ) -> None:
        # vLLM accepts any non-empty token by default, but operators can
        # configure a real key — pass it through unchanged.
        self._inner = OpenAiProvider(
            api_key=api_key,
            default_model=default_model,
            base_url=base_url,
            client_factory=client_factory,
            max_concurrent=max_concurrent,
            rate_per_minute=rate_per_minute,
            max_retries=max_retries,
            breaker_threshold=breaker_threshold,
            breaker_reset_seconds=breaker_reset_seconds,
            request_timeout_seconds=request_timeout_seconds,
        )
        self.default_model = default_model
        self.is_local = True
        self.max_concurrent = max_concurrent

    async def generate(self, req: LlmRequest) -> LlmResponse:
        resp = await self._inner.generate(req)
        # Override provider name + zero out cost (it's local, regardless of
        # what the OpenAI cost table thinks).
        return resp.model_copy(
            update={
                "provider": self.name,
                "usage": resp.usage.model_copy(update={"cost_usd": 0.0}),
            }
        )

    async def health_check(self) -> bool:
        return await self._inner.health_check()

    async def test_connection(self, *, model: str | None = None) -> ConnectionTestResult:
        result = await self._inner.test_connection(model=model)
        # Override the provider label so callers see "vllm", not "openai".
        return result.model_copy(update={"provider": self.name})

    def info(self) -> ProviderInfo:
        inner = self._inner.info()
        return ProviderInfo(
            name=self.name,
            available=inner.available,
            default_model=inner.default_model,
            supports_structured_output=inner.supports_structured_output,
            is_local=True,
            notes="Self-hosted vLLM (OpenAI-compatible).",
        )

    def breaker_state(self) -> dict[str, object]:
        return self._inner.breaker_state()

    def estimate_cost_usd(self, *, model: str, input_text: str, max_output_tokens: int) -> float:
        # Self-hosted = zero cost. Token estimation kept consistent with the
        # other providers for capacity-planning callers.
        return 0.0

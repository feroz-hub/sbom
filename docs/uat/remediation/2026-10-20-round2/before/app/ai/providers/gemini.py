"""Google Gemini provider — OpenAI-compatible endpoint.

Phase 1 §1.1. Gemini exposes an OpenAI-compatible chat-completions
endpoint at ``https://generativelanguage.googleapis.com/v1beta/openai/``,
so the implementation is a thin specialisation of :class:`OpenAiProvider`
that overrides:

  * the base URL
  * the default model (``gemini-3.6-flash``)
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
from urllib.parse import urlencode

import httpx

from .base import (
    ConnectionTestResult,
    DiscoveredModel,
    LlmProvider,
    LlmRequest,
    LlmResponse,
    ModelDiscoveryError,
    ProviderInfo,
    ProviderUnavailableError,
)
from .openai import OpenAiProvider

log = logging.getLogger("sbom.ai.providers.gemini")

_BASE_URL = "https://generativelanguage.googleapis.com/v1beta/openai"

# Conservative free-tier rate limit. Google may grant higher limits by account
# and model; staying at 15 RPM prevents a free key from being over-saturated.
_FREE_TIER_RPM = 15
_FREE_TIER_DAILY_TOKENS = 1_000_000


class GeminiProvider(LlmProvider):
    """Implements :class:`LlmProvider` against Gemini's OpenAI-compatible endpoint."""

    name: str = "gemini"

    def __init__(
        self,
        *,
        api_key: str,
        default_model: str = "gemini-3.6-flash",
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
        self._api_key = api_key
        self._client_factory = client_factory
        self._timeout = request_timeout_seconds
        self.default_model = default_model
        self.is_local = False
        self.max_concurrent = max_concurrent

        # Internal OpenAI-compatible client. The cost lookup picks the
        # Gemini PRICING table by way of ``provider="gemini"``.
        #
        # ``structured_output_mode="json_object"`` is the surgical bug
        # fix: Gemini's OpenAI-compat endpoint does NOT support the
        # ``json_schema`` strict mode that real OpenAI accepts. Passing
        # it through silently degrades to free-form generation, which
        # has been surfacing as ``schema_parse_failed`` errors in the
        # ledger (Gemini returns prose because it interpreted the
        # unsupported field as "respond freely"). ``json_object`` is the
        # only ``response_format`` Gemini honors here; the strict prompt
        # already in place + the lenient ``parse_llm_json`` layer enforce
        # the schema shape on top of valid-JSON-ness.
        # Reference: https://ai.google.dev/gemini-api/docs/openai
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
            structured_output_mode="json_object",
            # Gemini 3 is tuned for temperature 1.0; lower values can cause
            # looping/degraded answers. Low thinking keeps bounded dashboard
            # calls useful without consuming the output allowance on reasoning.
            reasoning_effort="minimal",
            temperature_override=1.0,
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

    async def list_models(self) -> list[DiscoveredModel]:
        client = await self._inner._client()
        url: str | None = "https://generativelanguage.googleapis.com/v1beta/models?pageSize=1000"
        discovered: list[DiscoveredModel] = []
        while url:
            try:
                response = await client.get(url, headers={"x-goog-api-key": self._api_key}, timeout=self._timeout)
            except httpx.TimeoutException as exc:
                raise ModelDiscoveryError("timeout", "gemini: model discovery timed out") from exc
            except httpx.RequestError as exc:
                raise ModelDiscoveryError("provider_unreachable", "gemini: provider unreachable") from exc
            if response.status_code in (401, 403):
                raise ModelDiscoveryError("authentication_failed", "gemini: authentication failed")
            if response.status_code == 429:
                raise ModelDiscoveryError("rate_limited", "gemini: model discovery was rate limited")
            if response.status_code >= 400:
                raise ModelDiscoveryError("invalid_response", f"gemini: model listing returned HTTP {response.status_code}")
            try:
                body = response.json()
                items = body.get("models", [])
                if not isinstance(items, list):
                    raise TypeError("models is not a list")
            except (ValueError, TypeError) as exc:
                raise ModelDiscoveryError("invalid_response", "gemini: invalid model listing response") from exc
            for item in items:
                if not isinstance(item, dict) or not isinstance(item.get("name"), str):
                    continue
                provider_id = item["name"].strip()
                runtime_id = provider_id.removeprefix("models/")
                methods = item.get("supportedGenerationMethods")
                method_list = methods if isinstance(methods, list) else []
                discovered.append(DiscoveredModel(
                    provider_model_id=provider_id,
                    runtime_model_id=runtime_id,
                    display_name=item.get("displayName") if isinstance(item.get("displayName"), str) else runtime_id,
                    provider_name=self.name,
                    supports_chat=("generateContent" in method_list) if methods is not None else None,
                    supports_streaming=("streamGenerateContent" in method_list) if methods is not None else None,
                    context_window=item.get("inputTokenLimit") if isinstance(item.get("inputTokenLimit"), int) else None,
                    max_output_tokens=item.get("outputTokenLimit") if isinstance(item.get("outputTokenLimit"), int) else None,
                    raw_metadata={"supported_generation_methods": method_list} if methods is not None else None,
                ))
            token = body.get("nextPageToken")
            url = (
                f"https://generativelanguage.googleapis.com/v1beta/models?{urlencode({'pageSize': 1000, 'pageToken': token})}"
                if isinstance(token, str) and token
                else None
            )
        return discovered

    def info(self) -> ProviderInfo:
        return ProviderInfo(
            name=self.name,
            available=True,
            default_model=self.default_model,
            supports_structured_output=True,
            is_local=False,
            notes=("Free tier (15 req/min · 1M tokens/day)." if self._tier == "free" else "Paid tier."),
        )

    def breaker_state(self) -> dict[str, object]:
        return self._inner.breaker_state()

    def estimate_cost_usd(self, *, model: str, input_text: str, max_output_tokens: int) -> float:
        return self._inner.estimate_cost_usd(
            model=model,
            input_text=input_text,
            max_output_tokens=max_output_tokens,
        )

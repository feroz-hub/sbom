"""OpenAI provider — Chat Completions API via httpx.

Reference: https://platform.openai.com/docs/api-reference/chat/create
"""

from __future__ import annotations

import asyncio
import json
import logging
import time
from typing import Any

import httpx

from ..cost import estimate_cost_usd, estimate_tokens
from ..limiter import CircuitBreaker, RateLimiter
from .base import (
    AiProviderError,
    ConnectionTestResult,
    LlmProvider,
    LlmRequest,
    LlmResponse,
    LlmUsage,
    ProviderInfo,
    ProviderUnavailableError,
)

log = logging.getLogger("sbom.ai.providers.openai")

_DEFAULT_BASE_URL = "https://api.openai.com/v1"


class OpenAiProvider(LlmProvider):
    """Implements :class:`LlmProvider` against OpenAI's Chat Completions API.

    The same class also covers OpenAI-compatible endpoints (Azure OpenAI,
    Together, Groq, …) when ``base_url`` is overridden.
    """

    name: str = "openai"

    def __init__(
        self,
        *,
        api_key: str,
        default_model: str = "gpt-4o-mini",
        base_url: str = _DEFAULT_BASE_URL,
        organization: str | None = None,
        client_factory: Any | None = None,
        max_concurrent: int = 20,
        rate_per_minute: float = 200.0,
        max_retries: int = 3,
        breaker_threshold: int = 5,
        breaker_reset_seconds: float = 60.0,
        request_timeout_seconds: float = 30.0,
    ) -> None:
        if not api_key:
            raise ProviderUnavailableError("openai: api_key is required")
        self._api_key = api_key
        self.default_model = default_model
        self._base_url = base_url.rstrip("/")
        self._organization = organization
        self.is_local = False
        self.max_concurrent = max_concurrent
        self._client_factory = client_factory
        self._sem = asyncio.Semaphore(max_concurrent)
        self._limiter = RateLimiter(rate=rate_per_minute, per=60.0)
        self._breaker = CircuitBreaker(threshold=breaker_threshold, reset_seconds=breaker_reset_seconds)
        self._max_retries = max_retries
        self._timeout = request_timeout_seconds

    async def generate(self, req: LlmRequest) -> LlmResponse:
        self._breaker.allow()
        client = await self._client()
        model = req.model or self.default_model
        body = self._build_body(req, model)

        async with self._sem:
            await self._limiter.acquire()
            t0 = time.perf_counter()
            data = await self._post_with_retries(client, body)
            latency_ms = int((time.perf_counter() - t0) * 1000)

        try:
            text = (data["choices"][0]["message"].get("content") or "").strip()
            usage_obj = data.get("usage") or {}
            in_tok = int(usage_obj.get("prompt_tokens") or 0)
            out_tok = int(usage_obj.get("completion_tokens") or 0)
        except Exception as exc:
            self._breaker.record_failure()
            raise AiProviderError(f"openai: malformed response — {exc}") from exc

        self._breaker.record_success()
        usage = LlmUsage(
            input_tokens=in_tok,
            output_tokens=out_tok,
            cost_usd=estimate_cost_usd(
                provider=self.name,
                model=model,
                input_tokens=in_tok,
                output_tokens=out_tok,
                is_local=self.is_local,
            ),
        )
        parsed = self._maybe_parse(text, req.response_schema)
        return LlmResponse(
            text=text,
            parsed=parsed,
            usage=usage,
            provider=self.name,
            model=model,
            latency_ms=latency_ms,
        )

    async def health_check(self) -> bool:
        result = await self.test_connection()
        return result.success

    async def test_connection(self, *, model: str | None = None) -> ConnectionTestResult:
        """Try ``GET /models`` first; fall back to a 1-token chat completion.

        The two-step probe keeps the test cost-free for providers that
        expose the models endpoint (Anthropic / OpenAI / Gemini / Grok all do)
        while still working against barebones OpenAI-compatible servers
        that only implement chat completions (LiteLLM / LM Studio).
        """
        from . import _probe

        client = await self._client()
        target_model = model or self.default_model
        t0 = time.perf_counter()
        try:
            probe = await _probe.probe_openai_compatible_models(
                client,
                base_url=self._base_url,
                headers=self._headers(),
            )
        except (httpx.HTTPError, httpx.RequestError) as exc:
            return _probe.network_failure(provider=self.name, model=target_model, exc=exc)

        if probe is None:
            # No /models endpoint — fall back to a tiny completion.
            return await self._probe_via_completion(target_model, client)

        models, status = probe
        latency = _probe.measure(t0)
        if status and status >= 400:
            return _probe.http_failure(
                provider=self.name,
                model=target_model,
                status=status,
                body_text="models endpoint returned error",
                latency_ms=latency,
            )
        return _probe.success(
            provider=self.name,
            model=target_model,
            detected_models=models,
            latency_ms=latency,
        )

    async def _probe_via_completion(
        self, model: str, client: httpx.AsyncClient
    ) -> ConnectionTestResult:
        from . import _probe

        body = {
            "model": model,
            "max_tokens": 4,
            "temperature": 0.0,
            "messages": [
                {"role": "system", "content": "You are a connectivity probe."},
                {"role": "user", "content": "Reply with the single word ok."},
            ],
        }
        t0 = time.perf_counter()
        try:
            resp = await client.post(
                f"{self._base_url}/chat/completions",
                headers=self._headers(),
                json=body,
                timeout=self._timeout,
            )
        except (httpx.HTTPError, httpx.RequestError) as exc:
            return _probe.network_failure(provider=self.name, model=model, exc=exc)
        latency = _probe.measure(t0)
        if resp.status_code >= 400:
            return _probe.http_failure(
                provider=self.name,
                model=model,
                status=resp.status_code,
                body_text=resp.text,
                latency_ms=latency,
            )
        return _probe.success(
            provider=self.name,
            model=model,
            detected_models=[model],
            latency_ms=latency,
        )

    def info(self) -> ProviderInfo:
        return ProviderInfo(
            name=self.name,
            available=True,
            default_model=self.default_model,
            supports_structured_output=True,
            is_local=False,
            notes="Chat Completions; JSON mode + json_schema response_format (Phase 2).",
        )

    # ------------------------------------------------------------------

    async def _client(self) -> httpx.AsyncClient:
        if self._client_factory is not None:
            return self._client_factory()
        from ...http_client import get_async_http_client

        return get_async_http_client()

    def _headers(self) -> dict[str, str]:
        h = {
            "Authorization": f"Bearer {self._api_key}",
            "content-type": "application/json",
        }
        if self._organization:
            h["OpenAI-Organization"] = self._organization
        return h

    def _build_body(self, req: LlmRequest, model: str) -> dict[str, Any]:
        body: dict[str, Any] = {
            "model": model,
            "max_tokens": req.max_output_tokens,
            "temperature": req.temperature,
            "messages": [
                {"role": "system", "content": req.system},
                {"role": "user", "content": req.user},
            ],
        }
        if req.response_schema is not None:
            # Use the strict json_schema response format. Falls back to
            # plain JSON mode on older models — see Phase 2 prompt notes.
            body["response_format"] = {
                "type": "json_schema",
                "json_schema": {
                    "name": "structured_output",
                    "strict": True,
                    "schema": req.response_schema,
                },
            }
        return body

    async def _post_with_retries(self, client: httpx.AsyncClient, body: dict[str, Any]) -> dict[str, Any]:
        attempt = 0
        backoff = 1.0
        last_exc: Exception | None = None
        url = f"{self._base_url}/chat/completions"
        while attempt <= self._max_retries:
            try:
                resp = await client.post(url, headers=self._headers(), json=body, timeout=self._timeout)
                if resp.status_code == 429 or 500 <= resp.status_code < 600:
                    raise httpx.HTTPStatusError(
                        f"openai transient {resp.status_code}",
                        request=resp.request,
                        response=resp,
                    )
                if resp.status_code >= 400:
                    self._breaker.record_failure()
                    raise AiProviderError(f"openai: HTTP {resp.status_code} — {resp.text[:200]}")
                return resp.json()
            except (httpx.HTTPStatusError, httpx.RequestError) as exc:
                last_exc = exc
                attempt += 1
                if attempt > self._max_retries:
                    self._breaker.record_failure()
                    raise AiProviderError(f"openai: retries exhausted — {exc}") from exc
                await asyncio.sleep(backoff)
                backoff *= 2
        self._breaker.record_failure()
        raise AiProviderError(f"openai: unreachable code — {last_exc}")

    @staticmethod
    def _maybe_parse(text: str, schema: dict[str, Any] | None) -> dict[str, Any] | None:
        if schema is None or not text:
            return None
        try:
            obj = json.loads(text)
            return obj if isinstance(obj, dict) else None
        except json.JSONDecodeError:
            return None

    def breaker_state(self) -> dict[str, object]:
        return self._breaker.state()

    def estimate_cost_usd(self, *, model: str, input_text: str, max_output_tokens: int) -> float:
        return estimate_cost_usd(
            provider=self.name,
            model=model,
            input_tokens=estimate_tokens(input_text),
            output_tokens=max_output_tokens,
        )

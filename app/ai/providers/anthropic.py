"""Anthropic provider — talks to the Messages API directly via httpx.

Why not the official ``anthropic`` SDK: the codebase already keeps a
shared :class:`httpx.AsyncClient` for connection pooling, retries, and
proxy handling. Routing through it means every outbound call benefits
from the same observability and TLS posture. Adding the SDK would
double-up that layer for one feature.

Reference: https://docs.anthropic.com/en/api/messages
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

log = logging.getLogger("sbom.ai.providers.anthropic")

_API_URL = "https://api.anthropic.com/v1/messages"
_API_VERSION = "2023-06-01"  # most-stable major; bumped only with a regression suite


class AnthropicProvider(LlmProvider):
    """Implements :class:`LlmProvider` against the Anthropic Messages API."""

    name: str = "anthropic"

    def __init__(
        self,
        *,
        api_key: str,
        default_model: str = "claude-sonnet-4-5",
        client_factory: Any | None = None,
        max_concurrent: int = 10,
        rate_per_minute: float = 50.0,
        max_retries: int = 3,
        breaker_threshold: int = 5,
        breaker_reset_seconds: float = 60.0,
        request_timeout_seconds: float = 30.0,
    ) -> None:
        if not api_key:
            raise ProviderUnavailableError("anthropic: api_key is required")
        self._api_key = api_key
        self.default_model = default_model
        self.is_local = False
        self.max_concurrent = max_concurrent
        self._client_factory = client_factory
        self._sem = asyncio.Semaphore(max_concurrent)
        self._limiter = RateLimiter(rate=rate_per_minute, per=60.0)
        self._breaker = CircuitBreaker(threshold=breaker_threshold, reset_seconds=breaker_reset_seconds)
        self._max_retries = max_retries
        self._timeout = request_timeout_seconds

    # ------------------------------------------------------------------
    # LlmProvider contract
    # ------------------------------------------------------------------

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
            text = self._extract_text(data)
            in_tok = int(data.get("usage", {}).get("input_tokens") or 0)
            out_tok = int(data.get("usage", {}).get("output_tokens") or 0)
        except Exception as exc:
            self._breaker.record_failure()
            raise AiProviderError(f"anthropic: malformed response — {exc}") from exc

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
        """Probe Anthropic via ``GET /v1/models``.

        The Messages API doesn't have an OpenAI-compatible /models
        endpoint shape, but Anthropic does ship a real /v1/models
        endpoint that returns the list of accessible models without
        consuming tokens — perfect for connectivity probes.
        """
        from . import _probe

        client = await self._client()
        target_model = model or self.default_model
        url = "https://api.anthropic.com/v1/models"
        t0 = time.perf_counter()
        try:
            resp = await client.get(url, headers=self._headers(), timeout=self._timeout)
        except (httpx.HTTPError, httpx.RequestError) as exc:
            return _probe.network_failure(provider=self.name, model=target_model, exc=exc)
        latency = _probe.measure(t0)
        if resp.status_code >= 400:
            return _probe.http_failure(
                provider=self.name,
                model=target_model,
                status=resp.status_code,
                body_text=resp.text,
                latency_ms=latency,
            )
        try:
            body = resp.json()
        except Exception:  # noqa: BLE001
            return ConnectionTestResult(
                success=False,
                latency_ms=latency,
                error_message="invalid JSON from /v1/models",
                error_kind="invalid_response",
                provider=self.name,
                model_tested=target_model,
            )
        items = body.get("data") or []
        models = [m.get("id") for m in items if isinstance(m, dict) and m.get("id")]
        return _probe.success(
            provider=self.name,
            model=target_model,
            detected_models=models,
            latency_ms=latency,
        )

    def info(self) -> ProviderInfo:
        return ProviderInfo(
            name=self.name,
            available=True,
            default_model=self.default_model,
            supports_structured_output=True,
            is_local=False,
            notes="Anthropic Messages API; tool-use enables JSON-schema output (Phase 2).",
        )

    # ------------------------------------------------------------------
    # Internals
    # ------------------------------------------------------------------

    async def _client(self) -> httpx.AsyncClient:
        if self._client_factory is not None:
            return self._client_factory()
        # Late import — keeps the module import cheap when AI is disabled.
        from ...http_client import get_async_http_client

        return get_async_http_client()

    def _headers(self) -> dict[str, str]:
        return {
            "x-api-key": self._api_key,
            "anthropic-version": _API_VERSION,
            "content-type": "application/json",
        }

    def _build_body(self, req: LlmRequest, model: str) -> dict[str, Any]:
        body: dict[str, Any] = {
            "model": model,
            "max_tokens": req.max_output_tokens,
            "temperature": req.temperature,
            "system": req.system,
            "messages": [{"role": "user", "content": req.user}],
        }
        # Structured output: in Phase 2 we'll wire a single tool whose
        # input_schema mirrors the Pydantic schema. For Phase 1 we ship the
        # plumbing and use prompt-level JSON instructions.
        if req.response_schema is not None:
            body["tool_choice"] = {"type": "tool", "name": "emit_structured_output"}
            body["tools"] = [
                {
                    "name": "emit_structured_output",
                    "description": "Emit the structured response.",
                    "input_schema": req.response_schema,
                }
            ]
        return body

    async def _post_with_retries(self, client: httpx.AsyncClient, body: dict[str, Any]) -> dict[str, Any]:
        attempt = 0
        backoff = 1.0
        last_exc: Exception | None = None
        while attempt <= self._max_retries:
            try:
                resp = await client.post(
                    _API_URL,
                    headers=self._headers(),
                    json=body,
                    timeout=self._timeout,
                )
                if resp.status_code == 429 or 500 <= resp.status_code < 600:
                    raise httpx.HTTPStatusError(
                        f"anthropic transient {resp.status_code}",
                        request=resp.request,
                        response=resp,
                    )
                if resp.status_code >= 400:
                    self._breaker.record_failure()
                    raise AiProviderError(
                        f"anthropic: HTTP {resp.status_code} — {resp.text[:200]}"
                    )
                return resp.json()
            except (httpx.HTTPStatusError, httpx.RequestError) as exc:
                last_exc = exc
                attempt += 1
                if attempt > self._max_retries:
                    self._breaker.record_failure()
                    raise AiProviderError(f"anthropic: retries exhausted — {exc}") from exc
                await asyncio.sleep(backoff)
                backoff *= 2
        # Defensive — loop should always return or raise.
        self._breaker.record_failure()
        raise AiProviderError(f"anthropic: unreachable code — {last_exc}")

    @staticmethod
    def _extract_text(data: dict[str, Any]) -> str:
        # Tool-use response: content[*].type == 'tool_use' carries 'input' dict.
        for block in data.get("content", []) or []:
            if block.get("type") == "tool_use":
                return json.dumps(block.get("input") or {})
        # Plain text response: content[*].type == 'text' carries 'text' str.
        chunks = []
        for block in data.get("content", []) or []:
            if block.get("type") == "text":
                chunks.append(block.get("text") or "")
        return "".join(chunks)

    @staticmethod
    def _maybe_parse(text: str, schema: dict[str, Any] | None) -> dict[str, Any] | None:
        if schema is None:
            return None
        if not text:
            return None
        try:
            obj = json.loads(text)
            return obj if isinstance(obj, dict) else None
        except json.JSONDecodeError:
            return None

    # Visible for tests / observability.
    def breaker_state(self) -> dict[str, object]:
        return self._breaker.state()

    def estimate_cost_usd(self, *, model: str, input_text: str, max_output_tokens: int) -> float:
        return estimate_cost_usd(
            provider=self.name,
            model=model,
            input_tokens=estimate_tokens(input_text),
            output_tokens=max_output_tokens,
        )

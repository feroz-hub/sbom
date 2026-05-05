"""Ollama provider — local LLM via the Ollama HTTP API.

Reference: https://github.com/ollama/ollama/blob/main/docs/api.md

Local providers are billed at $0 and use the same async-I/O concurrency
primitives as cloud providers — Ollama itself batches requests on its
GPU, so over-saturating with high concurrency just creates head-of-line
blocking. Tune ``max_concurrent`` to match the Ollama server's effective
parallelism (default 8 here).
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
)

log = logging.getLogger("sbom.ai.providers.ollama")


class OllamaProvider(LlmProvider):
    """Implements :class:`LlmProvider` against a local Ollama server."""

    name: str = "ollama"

    def __init__(
        self,
        *,
        base_url: str = "http://localhost:11434",
        default_model: str = "llama3.3:70b",
        client_factory: Any | None = None,
        max_concurrent: int = 8,
        rate_per_minute: float = 1000.0,  # local — effectively unlimited
        max_retries: int = 2,
        breaker_threshold: int = 5,
        breaker_reset_seconds: float = 30.0,
        request_timeout_seconds: float = 120.0,  # local inference can be slow
    ) -> None:
        self._base_url = base_url.rstrip("/")
        self.default_model = default_model
        self.is_local = True
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
            text = (data.get("message", {}).get("content") or "").strip()
            in_tok = int(data.get("prompt_eval_count") or 0)
            out_tok = int(data.get("eval_count") or 0)
        except Exception as exc:
            self._breaker.record_failure()
            raise AiProviderError(f"ollama: malformed response — {exc}") from exc

        self._breaker.record_success()
        usage = LlmUsage(
            input_tokens=in_tok,
            output_tokens=out_tok,
            cost_usd=estimate_cost_usd(
                provider=self.name,
                model=model,
                input_tokens=in_tok,
                output_tokens=out_tok,
                is_local=True,
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
        """Probe Ollama via ``GET /api/tags`` — lists installed models.

        No authentication, no token spend. If the requested ``model``
        isn't in the installed list we still report success (the model
        may be pulled lazily on first use), but include the model list
        so the UI can show "Model not found, available: ...".
        """
        from . import _probe

        client = await self._client()
        target_model = model or self.default_model
        t0 = time.perf_counter()
        try:
            resp = await client.get(f"{self._base_url}/api/tags", timeout=5.0)
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
                error_message="invalid JSON from /api/tags",
                error_kind="invalid_response",
                provider=self.name,
                model_tested=target_model,
            )
        items = body.get("models") or []
        models = [m.get("name") for m in items if isinstance(m, dict) and m.get("name")]
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
            is_local=True,
            notes="Local Ollama; format=json for structured output (Phase 2).",
        )

    # ------------------------------------------------------------------

    async def _client(self) -> httpx.AsyncClient:
        if self._client_factory is not None:
            return self._client_factory()
        from ...http_client import get_async_http_client

        return get_async_http_client()

    def _build_body(self, req: LlmRequest, model: str) -> dict[str, Any]:
        body: dict[str, Any] = {
            "model": model,
            "stream": False,
            "messages": [
                {"role": "system", "content": req.system},
                {"role": "user", "content": req.user},
            ],
            "options": {
                "temperature": req.temperature,
                "num_predict": req.max_output_tokens,
            },
        }
        if req.response_schema is not None:
            body["format"] = req.response_schema
        return body

    async def _post_with_retries(self, client: httpx.AsyncClient, body: dict[str, Any]) -> dict[str, Any]:
        attempt = 0
        backoff = 0.5
        last_exc: Exception | None = None
        url = f"{self._base_url}/api/chat"
        while attempt <= self._max_retries:
            try:
                resp = await client.post(url, json=body, timeout=self._timeout)
                if resp.status_code == 429 or 500 <= resp.status_code < 600:
                    raise httpx.HTTPStatusError(
                        f"ollama transient {resp.status_code}",
                        request=resp.request,
                        response=resp,
                    )
                if resp.status_code >= 400:
                    self._breaker.record_failure()
                    raise AiProviderError(f"ollama: HTTP {resp.status_code} — {resp.text[:200]}")
                return resp.json()
            except (httpx.HTTPStatusError, httpx.RequestError) as exc:
                last_exc = exc
                attempt += 1
                if attempt > self._max_retries:
                    self._breaker.record_failure()
                    raise AiProviderError(f"ollama: retries exhausted — {exc}") from exc
                await asyncio.sleep(backoff)
                backoff *= 2
        self._breaker.record_failure()
        raise AiProviderError(f"ollama: unreachable code — {last_exc}")

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
            is_local=True,
        )

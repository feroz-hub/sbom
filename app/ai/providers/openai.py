"""OpenAI provider — model-aware Chat Completions and Responses via httpx.

Reference: https://platform.openai.com/docs/api-reference/chat/create
"""

from __future__ import annotations

import asyncio
import json
import logging
import time
from typing import Any, Literal

import httpx

from ..cost import estimate_cost_usd, estimate_tokens
from ..limiter import CircuitBreaker, RateLimiter
from . import openai_compat as compat
from .base import (
    AiProviderError,
    ConnectionTestResult,
    DiscoveredModel,
    LlmProvider,
    LlmRequest,
    LlmResponse,
    LlmUsage,
    ModelDiscoveryError,
    ProviderInfo,
    ProviderUnavailableError,
    classify_http_failure,
    classify_network_failure,
    detect_quota_in_2xx_body,
)
from .openai_models import OpenAiModelProfile, profile_for

log = logging.getLogger("sbom.ai.providers.openai")

_DEFAULT_BASE_URL = "https://api.openai.com/v1"

# Structured-output modes — different OpenAI-compatible backends honor
# different ``response_format`` shapes. The provider picks the right
# shape per its endpoint; mismatched shapes are silently ignored by
# Gemini (producing prose) and 400-rejected by some custom proxies.
#
# * ``json_schema_strict`` — true OpenAI Chat Completions + Anthropic
#   passthroughs that speak the OpenAI dialect. Full schema enforcement.
# * ``json_object`` — Gemini's OpenAI-compat endpoint. Enforces "valid
#   JSON" but ignores the schema body; the strict prompt + post-validation
#   layer carries the schema shape.
# * ``none`` — emit no ``response_format`` at all. Conservative default
#   for unknown OpenAI-compat backends (LM Studio, LocalAI, vLLM with
#   older builds) that 400 on unrecognised ``response_format`` types.
StructuredOutputMode = Literal["json_schema_strict", "json_object", "none"]


class OpenAiProvider(LlmProvider):
    """Native OpenAI Chat Completions / Responses with reviewed capabilities.

    OpenAI-compatible adapters explicitly disable native capability routing,
    retaining their existing request parameters and response handling.
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
        structured_output_mode: StructuredOutputMode = "json_schema_strict",
        reasoning_effort: str | None = None,
        native_openai: bool = True,
        model_profiles: dict[str, OpenAiModelProfile] | None = None,
        temperature_override: float | None = None,
    ) -> None:
        if not api_key:
            raise ProviderUnavailableError(f"{self.name}: api_key is required")
        self._native_openai = native_openai
        self._model_profiles = model_profiles or {}
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
        self._structured_output_mode: StructuredOutputMode = structured_output_mode
        self._reasoning_effort = reasoning_effort
        self._temperature_override = temperature_override

    async def generate(self, req: LlmRequest) -> LlmResponse:
        self._breaker.allow()
        client = await self._client()
        model = req.model or self.default_model
        body = self._build_body(req, model)

        async with self._sem:
            await self._limiter.acquire()
            t0 = time.perf_counter()
            data = await self._post_with_retries(client, body, endpoint=self._profile(model).endpoint if self._native else "chat/completions", retry=not (self._native and req.purpose == "model_test"))
            latency_ms = int((time.perf_counter() - t0) * 1000)

        if self._native:
            return self._decode_native(data, req, model, latency_ms)

        try:
            text = (data["choices"][0]["message"].get("content") or "").strip()
            usage_obj = data.get("usage") or {}
            in_tok = int(usage_obj.get("prompt_tokens") or 0)
            out_tok = int(usage_obj.get("completion_tokens") or 0)
        except Exception as exc:
            self._breaker.record_failure()
            raise AiProviderError(f"{self.name}: malformed response — {exc}") from exc

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

    async def list_models(self) -> list[DiscoveredModel]:
        """List models exposed by an OpenAI-compatible ``/models`` endpoint."""
        client = await self._client()
        try:
            response = await client.get(
                f"{self._base_url}/models",
                headers=self._headers(),
                timeout=self._timeout,
            )
        except httpx.TimeoutException as exc:
            raise ModelDiscoveryError("timeout", f"{self.name}: model discovery timed out") from exc
        except httpx.RequestError as exc:
            raise ModelDiscoveryError("provider_unreachable", f"{self.name}: provider unreachable") from exc
        if response.status_code in (401, 403):
            raise ModelDiscoveryError("authentication_failed", f"{self.name}: authentication failed")
        if response.status_code == 404:
            raise ModelDiscoveryError("unsupported", f"{self.name}: model discovery is not supported")
        if response.status_code == 429:
            raise ModelDiscoveryError("rate_limited", f"{self.name}: model discovery was rate limited")
        if response.status_code >= 400:
            raise ModelDiscoveryError("invalid_response", f"{self.name}: model listing returned HTTP {response.status_code}")
        try:
            body = response.json()
            items = body["data"]
            if not isinstance(items, list):
                raise TypeError("data is not a list")
        except (ValueError, KeyError, TypeError) as exc:
            raise ModelDiscoveryError("invalid_response", f"{self.name}: invalid model listing response") from exc
        discovered: list[DiscoveredModel] = []
        for item in items:
            if not isinstance(item, dict) or not isinstance(item.get("id"), str) or not item["id"].strip():
                continue
            model_id = item["id"].strip()
            metadata = {
                key: item[key]
                for key in ("created", "owned_by", "object")
                if key in item and isinstance(item[key], (str, int, float, bool, type(None)))
            }
            discovered.append(
                DiscoveredModel(
                    provider_model_id=model_id,
                    runtime_model_id=model_id,
                    display_name=model_id,
                    provider_name=self.name,
                    **(self._discovered_capabilities(model_id) if self._native else {}),
                    raw_metadata=metadata or None,
                )
            )
        if items and not discovered:
            raise ModelDiscoveryError("invalid_response", f"{self.name}: model listing contained no valid model IDs")
        return discovered

    async def test_connection(self, *, model: str | None = None) -> ConnectionTestResult:
        """Enumerate models, then run a tiny completion with the selected model.

        A successful ``GET /models`` proves that the credential is accepted but
        does *not* prove that the configured model can generate for this account.
        Providers may continue listing deprecated or entitlement-restricted
        models.  The completion probe is therefore authoritative; enumeration is
        retained only to populate the diagnostic model list.
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
            return self._native_probe_error(compat.OpenAiError("timeout" if isinstance(exc, httpx.TimeoutException) else "network"), target_model) if self._native else _probe.network_failure(provider=self.name, model=target_model, exc=exc)
        except (ValueError, TypeError, AttributeError):
            return self._native_probe_error(compat.OpenAiError("invalid_response"), target_model)

        if probe is None:
            return await self._probe_via_completion(target_model, client)

        models, status, error_body = probe
        latency = _probe.measure(t0)
        if status and status >= 400:
            if self._native:
                return self._native_probe_error(compat.OpenAiError(compat.http_kind(status, error_body), status=status), target_model)
            return _probe.http_failure(
                provider=self.name,
                model=target_model,
                status=status,
                body_text=error_body,
                latency_ms=latency,
            )
        completion_result = await self._probe_via_completion(target_model, client)
        return completion_result.model_copy(update={"detected_models": models, **({"discovered": target_model in models} if self._native else {})})

    async def _probe_via_completion(self, model: str, client: httpx.AsyncClient) -> ConnectionTestResult:
        from . import _probe

        if self._native:
            return await self._probe_native(model, client)

        body = {
            "model": model,
            "max_tokens": 4,
            "temperature": self._temperature_override if self._temperature_override is not None else 0.0,
            "messages": [
                {"role": "system", "content": "You are a connectivity probe."},
                {"role": "user", "content": "Reply with the single word ok."},
            ],
        }
        if self._reasoning_effort is not None:
            body["reasoning_effort"] = self._reasoning_effort
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
            supports_structured_output=(self._profile(self.default_model).structured is True) if self._native else True,
            is_local=False,
            notes=("Model-aware Chat Completions / Responses; structured output validated locally."
                   if self._native else "Chat Completions; JSON mode + json_schema response_format (Phase 2)."),
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
        if self._native:
            body = compat.build_body(req, model, self._profile(model), effort=self._reasoning_effort, temperature=self._temperature_override)
            if req.response_schema is not None and self._structured_output_mode != "json_schema_strict":
                if self._profile(model).endpoint == "responses":
                    body.pop("text", None)
                    if self._structured_output_mode == "json_object":
                        body["text"] = {"format": {"type": "json_object"}}
                else:
                    body.pop("response_format", None)
                    if self._structured_output_mode == "json_object":
                        body["response_format"] = {"type": "json_object"}
            return body
        body: dict[str, Any] = {
            "model": model,
            "max_tokens": req.max_output_tokens,
            "temperature": (
                self._temperature_override if self._temperature_override is not None else req.temperature
            ),
            "messages": [
                {"role": "system", "content": req.system},
                {"role": "user", "content": req.user},
            ],
        }
        if self._reasoning_effort is not None:
            body["reasoning_effort"] = self._reasoning_effort
        if req.response_schema is not None:
            rf = self._build_response_format(req.response_schema)
            if rf is not None:
                body["response_format"] = rf
        return body

    def _build_response_format(self, schema: dict[str, Any]) -> dict[str, Any] | None:
        """Pick the ``response_format`` shape this endpoint actually honors.

        Real OpenAI Chat Completions and Anthropic-via-OpenAI accept the
        full ``json_schema`` strict mode. Gemini's OpenAI-compat endpoint
        does NOT — passing ``json_schema`` there silently degrades to
        unconstrained generation, which is the root cause of the
        ``schema_parse_failed`` rate observed in production. ``json_object``
        is the only mode Gemini honors through this endpoint; the strict
        prompt + post-validation layer enforces schema shape.

        ``none`` returns no ``response_format`` at all — for backends that
        400 on unrecognised types (some custom proxies). Schema enforcement
        falls entirely on the prompt + parser.
        """
        mode = self._structured_output_mode
        if mode == "json_schema_strict":
            return {
                "type": "json_schema",
                "json_schema": {
                    "name": "structured_output",
                    "strict": True,
                    "schema": schema,
                },
            }
        if mode == "json_object":
            return {"type": "json_object"}
        # mode == "none" — emit no response_format; let prompts do the work.
        return None

    async def _post_with_retries(self, client: httpx.AsyncClient, body: dict[str, Any], *, endpoint: str = "chat/completions", retry: bool = True) -> dict[str, Any]:
        attempt = 0
        backoff = 1.0
        last_failure = None
        last_message: str | None = None
        url = f"{self._base_url}/{endpoint}"
        retries = self._max_retries if retry else 0
        while attempt <= retries:
            try:
                resp = await client.post(url, headers=self._headers(), json=body, timeout=self._timeout)
            except (httpx.HTTPError, httpx.RequestError) as exc:
                last_failure = classify_network_failure(provider_name=self.name, exc=exc)
                last_message = f"{self.name}: network error — {exc}"
                if self._native:
                    error = compat.OpenAiError("timeout" if isinstance(exc, httpx.TimeoutException) else "network")
                    last_failure, last_message = error.failure, str(error)
                attempt += 1
                if attempt > retries:
                    self._breaker.record_failure()
                    raise (error if self._native else AiProviderError(last_message, failure=last_failure)) from None
                await asyncio.sleep(backoff)
                backoff *= 2
                continue

            if resp.status_code == 429 or 500 <= resp.status_code < 600:
                last_failure = classify_http_failure(
                    provider_name=self.name,
                    status=resp.status_code,
                    body=resp.text,
                    retry_after_header=resp.headers.get("Retry-After"),
                )
                last_message = f"{self.name}: HTTP {resp.status_code} — {(resp.text or '')[:200]}"
                if self._native:
                    error = compat.OpenAiError("quota" if last_failure.kind == "quota_exceeded" else compat.http_kind(resp.status_code, resp.text), status=resp.status_code)
                    error.failure.retry_after_seconds = last_failure.retry_after_seconds
                    last_failure, last_message = error.failure, str(error)
                # Daily-quota exhaustion is not transient — retrying just
                # burns more allowance without recovering. Short-circuit
                # so the failure surfaces immediately.
                if last_failure.kind == "quota_exceeded":
                    self._breaker.record_failure()
                    raise (error if self._native else AiProviderError(last_message, failure=last_failure))
                attempt += 1
                if attempt > retries:
                    self._breaker.record_failure()
                    raise (error if self._native else AiProviderError(last_message, failure=last_failure))
                await asyncio.sleep(backoff)
                backoff *= 2
                continue

            if resp.status_code >= 400:
                if self._native:
                    self._breaker.record_failure()
                    raise compat.OpenAiError(compat.http_kind(resp.status_code, resp.text), status=resp.status_code)
                failure = classify_http_failure(
                    provider_name=self.name,
                    status=resp.status_code,
                    body=resp.text,
                    retry_after_header=resp.headers.get("Retry-After"),
                )
                self._breaker.record_failure()
                raise AiProviderError(
                    f"{self.name}: HTTP {resp.status_code} — {(resp.text or '')[:200]}",
                    failure=failure,
                )

            # Gemini's OpenAI-compat endpoint returns quota errors as
            # HTTP 200 with the quota text embedded in the assistant
            # message. Without this scan the prose flows through to
            # ``parse_llm_json`` and surfaces as ``schema_parse_failed``.
            quota_failure = detect_quota_in_2xx_body(resp.text, provider_name=self.name, status=resp.status_code)
            if quota_failure is not None:
                self._breaker.record_failure()
                if self._native:
                    error = compat.OpenAiError("quota", status=resp.status_code)
                    error.failure.retry_after_seconds = quota_failure.retry_after_seconds
                    raise error
                raise AiProviderError(
                    f"{self.name}: HTTP {resp.status_code} quota — {(quota_failure.upstream_message or '')[:200]}",
                    failure=quota_failure,
                )

            try:
                data = resp.json()
                if not isinstance(data, dict):
                    raise ValueError()
                return data
            except ValueError:
                if self._native:
                    raise compat.OpenAiError("invalid_response") from None
                raise AiProviderError(f"{self.name}: invalid response") from None

        self._breaker.record_failure()
        raise AiProviderError(
            f"{self.name}: unreachable code — {last_message or 'no attempts succeeded'}",
            failure=last_failure,
        )

    @property
    def _native(self) -> bool:
        return self._native_openai and self.name == "openai"

    def _profile(self, model: str) -> OpenAiModelProfile:
        return self._model_profiles.get(model) or profile_for(model)

    def _discovered_capabilities(self, model: str) -> dict[str, Any]:
        profile = self._profile(model)
        return dict(
            supports_chat=profile.chat,
            supports_structured_output=profile.structured,
            supports_tools=profile.tools,
            context_window=profile.context_window,
            max_output_tokens=profile.max_output_tokens,
        )

    def _decode_native(self, data, req, model, latency_ms) -> LlmResponse:
        profile = self._profile(model)
        responses = profile.endpoint == "responses"
        raw_usage = data.get("usage") or {}
        try:
            usage = LlmUsage(
                input_tokens=int(raw_usage.get("input_tokens" if responses else "prompt_tokens") or 0),
                output_tokens=int(raw_usage.get("output_tokens" if responses else "completion_tokens") or 0),
                cost_usd=0,
            )
            in_rate, out_rate = profile.pricing or (0, 0)
            usage.cost_usd = (
                estimate_cost_usd(
                    provider=self.name, model=model, input_tokens=usage.input_tokens, output_tokens=usage.output_tokens
                )
                if model not in self._model_profiles
                else round((usage.input_tokens * in_rate + usage.output_tokens * out_rate) / 1000, 6)
            )
        except (ValueError, TypeError, AttributeError):
            raise compat.OpenAiError("invalid_response", accessible=True) from None
        try:
            text, problem = compat.extract(data, responses=responses)
            if problem:
                raise compat.OpenAiError(problem, accessible=True, generated=bool(text))
            parsed = compat.validate_output(text, req.response_schema)
        except compat.OpenAiError as error:
            error.usage = usage
            error.model = model
            raise
        self._breaker.record_success()
        return LlmResponse(
            text=text, parsed=parsed, usage=usage, provider=self.name, model=model, latency_ms=latency_ms
        )

    def _native_probe_error(self, error, model, latency_ms=None) -> ConnectionTestResult:
        return ConnectionTestResult(
            success=False,
            provider=self.name,
            model_tested=model,
            latency_ms=latency_ms,
            error_kind=error.kind,
            error_message=compat.MESSAGES[error.kind],
            http_status=error.failure.upstream_status,
            accessible=error.accessible,
            generation_verified=error.generated,
            workload_compatible=False if error.accessible else None,
            usage=error.usage,
        )

    async def _probe_native(self, model: str, client: httpx.AsyncClient) -> ConnectionTestResult:
        from ._probe import structured_probe_request

        req = structured_probe_request(
            model,
            max_output_tokens=2048 if self._profile(model).reasoning_efforts else 256,
            request_id="connection-test",
        )
        started = time.perf_counter()
        try:
            body = self._build_body(req, model)
            async with self._sem:
                await self._limiter.acquire()
                data = await self._post_with_retries(client, body, endpoint=self._profile(model).endpoint, retry=False)
            response = self._decode_native(data, req, model, int((time.perf_counter() - started) * 1000))
        except compat.OpenAiError as error:
            return self._native_probe_error(error, model, int((time.perf_counter() - started) * 1000))
        return ConnectionTestResult(
            success=True,
            provider=self.name,
            model_tested=model,
            detected_models=[],
            latency_ms=response.latency_ms,
            accessible=True,
            generation_verified=True,
            workload_compatible=True,
            usage=response.usage,
        )

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

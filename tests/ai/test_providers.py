"""Provider-level tests using ``httpx.MockTransport``.

Mirrors the pattern in ``tests/test_cve_clients.py``: each provider is
exercised against a scripted upstream so we never touch the real
Anthropic / OpenAI / Ollama / vLLM endpoints. The provider's ``client_factory``
hook lets us inject the mocked client without monkeypatching.
"""

from __future__ import annotations

import json

import httpx
import pytest
from app.ai.providers.anthropic import AnthropicProvider
from app.ai.providers.base import (
    AiProviderError,
    CircuitBreakerOpenError,
    LlmRequest,
    ProviderUnavailableError,
)
from app.ai.providers.ollama import OllamaProvider
from app.ai.providers.openai import OpenAiProvider
from app.ai.providers.vllm import VllmProvider


def _make_client(handler):
    return httpx.AsyncClient(transport=httpx.MockTransport(handler))


def _llm_req(**overrides):
    base = dict(
        system="You are a security engineer.",
        user="Summarise CVE-2099-9001.",
        max_output_tokens=64,
        temperature=0.2,
        request_id="test-1",
        purpose="remediation_prose",
    )
    base.update(overrides)
    return LlmRequest(**base)


# ============================================================ Anthropic


@pytest.mark.asyncio
async def test_anthropic_happy_path():
    def handler(request: httpx.Request) -> httpx.Response:
        body = json.loads(request.content.decode())
        assert body["model"] == "claude-sonnet-4-5"
        assert body["max_tokens"] == 64
        assert body["temperature"] == 0.2
        assert body["messages"] == [{"role": "user", "content": "Summarise CVE-2099-9001."}]
        assert request.headers["x-api-key"] == "sk-test"
        return httpx.Response(
            200,
            json={
                "content": [{"type": "text", "text": "Looks risky."}],
                "usage": {"input_tokens": 30, "output_tokens": 10},
            },
        )

    fake = _make_client(handler)
    provider = AnthropicProvider(api_key="sk-test", client_factory=lambda: fake)
    resp = await provider.generate(_llm_req())

    assert resp.text == "Looks risky."
    assert resp.usage.input_tokens == 30
    assert resp.usage.output_tokens == 10
    # claude-sonnet-4-5: $0.003/1k in, $0.015/1k out
    expected = round(30 / 1000 * 0.003 + 10 / 1000 * 0.015, 6)
    assert resp.usage.cost_usd == expected
    assert resp.provider == "anthropic"
    assert resp.model == "claude-sonnet-4-5"
    assert resp.parsed is None


@pytest.mark.asyncio
async def test_anthropic_tool_use_for_structured_output():
    schema = {"type": "object", "properties": {"summary": {"type": "string"}}}

    def handler(request: httpx.Request) -> httpx.Response:
        body = json.loads(request.content.decode())
        assert body["tools"][0]["name"] == "emit_structured_output"
        assert body["tools"][0]["input_schema"] == schema
        return httpx.Response(
            200,
            json={
                "content": [
                    {"type": "tool_use", "name": "emit_structured_output", "input": {"summary": "hi"}}
                ],
                "usage": {"input_tokens": 5, "output_tokens": 3},
            },
        )

    provider = AnthropicProvider(api_key="sk-test", client_factory=lambda: _make_client(handler))
    resp = await provider.generate(_llm_req(response_schema=schema))
    assert resp.parsed == {"summary": "hi"}
    assert json.loads(resp.text) == {"summary": "hi"}


@pytest.mark.asyncio
async def test_anthropic_4xx_raises_immediately_no_retry():
    calls = {"n": 0}

    def handler(request: httpx.Request) -> httpx.Response:
        calls["n"] += 1
        return httpx.Response(401, text="bad key")

    provider = AnthropicProvider(api_key="sk-test", client_factory=lambda: _make_client(handler), max_retries=2)
    with pytest.raises(AiProviderError):
        await provider.generate(_llm_req())
    assert calls["n"] == 1


@pytest.mark.asyncio
async def test_anthropic_5xx_retries_then_fails():
    calls = {"n": 0}

    def handler(request: httpx.Request) -> httpx.Response:
        calls["n"] += 1
        return httpx.Response(503, text="upstream")

    provider = AnthropicProvider(api_key="sk-test", client_factory=lambda: _make_client(handler), max_retries=2)
    with pytest.raises(AiProviderError):
        await provider.generate(_llm_req())
    # 1 initial + 2 retries = 3 attempts.
    assert calls["n"] == 3


@pytest.mark.asyncio
async def test_anthropic_circuit_breaker_opens_after_threshold():
    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(503)

    provider = AnthropicProvider(
        api_key="sk-test",
        client_factory=lambda: _make_client(handler),
        max_retries=0,
        breaker_threshold=2,
    )
    # 1 → fail, 2 → fail (threshold reached) → breaker open
    for _ in range(2):
        with pytest.raises(AiProviderError):
            await provider.generate(_llm_req())

    # Next call short-circuits before any HTTP attempt.
    with pytest.raises(CircuitBreakerOpenError):
        await provider.generate(_llm_req())


def test_anthropic_requires_api_key():
    with pytest.raises(ProviderUnavailableError):
        AnthropicProvider(api_key="")


# ============================================================ OpenAI


@pytest.mark.asyncio
async def test_openai_happy_path():
    def handler(request: httpx.Request) -> httpx.Response:
        body = json.loads(request.content.decode())
        assert body["model"] == "gpt-4o-mini"
        assert body["messages"] == [
            {"role": "system", "content": "You are a security engineer."},
            {"role": "user", "content": "Summarise CVE-2099-9001."},
        ]
        assert request.headers["Authorization"] == "Bearer sk-openai-test"
        return httpx.Response(
            200,
            json={
                "choices": [{"message": {"content": "Risky."}}],
                "usage": {"prompt_tokens": 100, "completion_tokens": 5},
            },
        )

    provider = OpenAiProvider(api_key="sk-openai-test", client_factory=lambda: _make_client(handler))
    resp = await provider.generate(_llm_req())
    assert resp.text == "Risky."
    assert resp.usage.input_tokens == 100
    assert resp.usage.output_tokens == 5
    # gpt-4o-mini: $0.00015/1k in, $0.0006/1k out
    assert resp.usage.cost_usd == round(100 / 1000 * 0.00015 + 5 / 1000 * 0.0006, 6)


@pytest.mark.asyncio
async def test_openai_response_format_with_schema():
    schema = {"type": "object", "properties": {"x": {"type": "integer"}}}

    def handler(request: httpx.Request) -> httpx.Response:
        body = json.loads(request.content.decode())
        rf = body["response_format"]
        assert rf["type"] == "json_schema"
        assert rf["json_schema"]["schema"] == schema
        return httpx.Response(
            200,
            json={
                "choices": [{"message": {"content": '{"x": 7}'}}],
                "usage": {"prompt_tokens": 1, "completion_tokens": 1},
            },
        )

    provider = OpenAiProvider(api_key="sk-test", client_factory=lambda: _make_client(handler))
    resp = await provider.generate(_llm_req(response_schema=schema))
    assert resp.parsed == {"x": 7}


@pytest.mark.asyncio
async def test_openai_structured_output_mode_json_object_sends_only_type():
    """Provider-aware response_format: ``json_object`` mode sends ``{"type": "json_object"}``.

    Schema is NOT inlined — Gemini's OpenAI-compat endpoint rejects
    ``json_schema`` and silently degrades on the inlined schema. Only
    the type marker is sent; schema enforcement is delegated to prompts +
    post-validation.
    """
    schema = {"type": "object", "properties": {"x": {"type": "integer"}}}
    captured: dict[str, object] = {}

    def handler(request: httpx.Request) -> httpx.Response:
        captured["body"] = json.loads(request.content.decode())
        return httpx.Response(
            200,
            json={
                "choices": [{"message": {"content": '{"x": 1}'}}],
                "usage": {"prompt_tokens": 1, "completion_tokens": 1},
            },
        )

    provider = OpenAiProvider(
        api_key="sk-test",
        client_factory=lambda: _make_client(handler),
        structured_output_mode="json_object",
    )
    await provider.generate(_llm_req(response_schema=schema))
    rf = captured["body"]["response_format"]
    assert rf == {"type": "json_object"}
    # Must NOT leak the schema body — that's the Gemini failure mode.
    assert "json_schema" not in rf
    serialised = json.dumps(captured["body"])
    assert "json_schema" not in serialised


@pytest.mark.asyncio
async def test_openai_structured_output_mode_none_omits_response_format():
    """``none`` mode suppresses response_format entirely (custom-proxy escape hatch)."""
    schema = {"type": "object", "properties": {"x": {"type": "integer"}}}
    captured: dict[str, object] = {}

    def handler(request: httpx.Request) -> httpx.Response:
        captured["body"] = json.loads(request.content.decode())
        return httpx.Response(
            200,
            json={
                "choices": [{"message": {"content": '{"x": 1}'}}],
                "usage": {"prompt_tokens": 1, "completion_tokens": 1},
            },
        )

    provider = OpenAiProvider(
        api_key="sk-test",
        client_factory=lambda: _make_client(handler),
        structured_output_mode="none",
    )
    await provider.generate(_llm_req(response_schema=schema))
    assert "response_format" not in captured["body"]


@pytest.mark.asyncio
async def test_openai_no_schema_means_no_response_format_in_any_mode():
    """When the request carries no schema, no response_format is sent regardless of mode."""
    captured: dict[str, object] = {}

    def handler(request: httpx.Request) -> httpx.Response:
        captured["body"] = json.loads(request.content.decode())
        return httpx.Response(
            200,
            json={
                "choices": [{"message": {"content": "free-text reply"}}],
                "usage": {"prompt_tokens": 1, "completion_tokens": 1},
            },
        )

    for mode in ("json_schema_strict", "json_object", "none"):
        captured.clear()
        provider = OpenAiProvider(
            api_key="sk-test",
            client_factory=lambda: _make_client(handler),
            structured_output_mode=mode,  # type: ignore[arg-type]
        )
        await provider.generate(_llm_req())  # no response_schema
        assert "response_format" not in captured["body"], f"mode={mode}"


@pytest.mark.asyncio
async def test_openai_unknown_model_warns_and_costs_zero(caplog):
    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(
            200,
            json={
                "choices": [{"message": {"content": "ok"}}],
                "usage": {"prompt_tokens": 100, "completion_tokens": 10},
            },
        )

    provider = OpenAiProvider(
        api_key="sk-test", default_model="future-model-not-in-table",
        client_factory=lambda: _make_client(handler),
    )
    with caplog.at_level("WARNING"):
        resp = await provider.generate(_llm_req())
    assert resp.usage.cost_usd == 0.0
    assert any("unknown_model" in m for m in caplog.messages)


def test_openai_requires_api_key():
    with pytest.raises(ProviderUnavailableError):
        OpenAiProvider(api_key="")


# ============================================================ OpenAI — typed upstream failures (Phase 5)


_GEMINI_QUOTA_BODY = (
    '{"error":{"code":429,"message":"You exceeded your current quota. '
    "* Quota exceeded for metric: generativelanguage.googleapis.com/"
    "generate_content_free_tier_requests, limit: 20, model: gemini-2.5-flash"
    '","status":"RESOURCE_EXHAUSTED",'
    '"details":[{"@type":"type.googleapis.com/google.rpc.RetryInfo",'
    '"retryDelay":"35s"}]}}'
)


@pytest.mark.asyncio
async def test_openai_429_resource_exhausted_classified_as_quota_exceeded_and_short_circuits():
    calls = {"n": 0}

    def handler(request: httpx.Request) -> httpx.Response:
        calls["n"] += 1
        return httpx.Response(429, text=_GEMINI_QUOTA_BODY)

    provider = OpenAiProvider(
        api_key="sk-test",
        client_factory=lambda: _make_client(handler),
        max_retries=3,
    )
    with pytest.raises(AiProviderError) as ei:
        await provider.generate(_llm_req())

    # Quota errors short-circuit (no retries — would just burn more quota).
    assert calls["n"] == 1
    failure = ei.value.failure
    assert failure is not None
    assert failure.kind == "quota_exceeded"
    assert failure.upstream_status == 429
    assert failure.retry_after_seconds == 35
    assert failure.upstream_message and "exceeded your current quota" in failure.upstream_message
    # The error string must NOT be tagged "openai" when the wrapping
    # provider has overridden ``self.name`` (we simulate a Gemini wrap
    # by mutating the inner provider's name attribute below).


@pytest.mark.asyncio
async def test_openai_inner_name_override_propagates_into_error_strings():
    """Wrappers (Gemini, Grok, custom) override ``inner.name`` after construction.
    Error strings emitted by the inner OpenAi must carry the new name.
    """
    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(429, text=_GEMINI_QUOTA_BODY)

    provider = OpenAiProvider(
        api_key="sk-test",
        client_factory=lambda: _make_client(handler),
        max_retries=2,
    )
    provider.name = "gemini"  # what GeminiProvider does in its __init__

    with pytest.raises(AiProviderError) as ei:
        await provider.generate(_llm_req())

    # The error string starts with the wrapping provider's name, not "openai:".
    assert str(ei.value).startswith("gemini:")
    assert "openai" not in str(ei.value).lower()
    assert ei.value.failure is not None
    assert ei.value.failure.provider_name == "gemini"


@pytest.mark.asyncio
async def test_openai_429_plain_rate_limit_classified_as_rate_limited_and_retries():
    calls = {"n": 0}

    def handler(request: httpx.Request) -> httpx.Response:
        calls["n"] += 1
        # 429 with no quota signals — plain RPS throttle.
        return httpx.Response(
            429,
            headers={"Retry-After": "2"},
            json={"error": {"message": "slow down"}},
        )

    provider = OpenAiProvider(
        api_key="sk-test",
        client_factory=lambda: _make_client(handler),
        max_retries=2,
    )
    with pytest.raises(AiProviderError) as ei:
        await provider.generate(_llm_req())

    # rate_limited is genuinely transient → retried (1 + max_retries).
    assert calls["n"] == 3
    assert ei.value.failure is not None
    assert ei.value.failure.kind == "rate_limited"
    assert ei.value.failure.retry_after_seconds == 2


@pytest.mark.asyncio
async def test_openai_401_classified_as_auth_failed():
    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(401, json={"error": {"message": "Invalid API key."}})

    provider = OpenAiProvider(
        api_key="sk-test",
        client_factory=lambda: _make_client(handler),
        max_retries=2,
    )
    with pytest.raises(AiProviderError) as ei:
        await provider.generate(_llm_req())
    assert ei.value.failure is not None
    assert ei.value.failure.kind == "auth_failed"
    assert ei.value.failure.upstream_status == 401
    assert ei.value.failure.upstream_message == "Invalid API key."


@pytest.mark.asyncio
async def test_openai_404_with_model_in_body_classified_as_model_not_found():
    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(
            404,
            json={"error": {"message": "The model 'gpt-9000' does not exist"}},
        )

    provider = OpenAiProvider(
        api_key="sk-test",
        client_factory=lambda: _make_client(handler),
        max_retries=2,
    )
    with pytest.raises(AiProviderError) as ei:
        await provider.generate(_llm_req())
    assert ei.value.failure is not None
    assert ei.value.failure.kind == "model_not_found"


@pytest.mark.asyncio
async def test_openai_503_classified_as_provider_down():
    calls = {"n": 0}

    def handler(request: httpx.Request) -> httpx.Response:
        calls["n"] += 1
        return httpx.Response(503, text="upstream unavailable")

    provider = OpenAiProvider(
        api_key="sk-test",
        client_factory=lambda: _make_client(handler),
        max_retries=2,
    )
    with pytest.raises(AiProviderError) as ei:
        await provider.generate(_llm_req())
    # 5xx is transient → retries before failing.
    assert calls["n"] == 3
    assert ei.value.failure is not None
    assert ei.value.failure.kind == "provider_down"


@pytest.mark.asyncio
async def test_openai_400_classified_as_invalid_request():
    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(
            400,
            json={"error": {"message": "Unsupported response_format"}},
        )

    provider = OpenAiProvider(
        api_key="sk-test",
        client_factory=lambda: _make_client(handler),
        max_retries=2,
    )
    with pytest.raises(AiProviderError) as ei:
        await provider.generate(_llm_req())
    assert ei.value.failure is not None
    assert ei.value.failure.kind == "invalid_request"
    assert ei.value.failure.upstream_status == 400


@pytest.mark.asyncio
async def test_openai_network_error_classified_as_network_unreachable():
    def handler(request: httpx.Request) -> httpx.Response:
        raise httpx.ConnectError("no route to host")

    provider = OpenAiProvider(
        api_key="sk-test",
        client_factory=lambda: _make_client(handler),
        max_retries=2,
    )
    with pytest.raises(AiProviderError) as ei:
        await provider.generate(_llm_req())
    assert ei.value.failure is not None
    assert ei.value.failure.kind == "network_unreachable"
    assert ei.value.failure.upstream_status is None


def test_classify_http_failure_unit_quota_keywords():
    """Unit-level: the classifier accepts several quota-like phrasings."""
    from app.ai.providers.base import classify_http_failure

    for body in (
        '{"error":{"status":"RESOURCE_EXHAUSTED"}}',
        '{"error":{"message":"You exceeded your current quota"}}',
        '{"error":{"message":"daily quota reached"}}',
    ):
        f = classify_http_failure(provider_name="gemini", status=429, body=body)
        assert f.kind == "quota_exceeded", body


def test_classify_http_failure_unit_retry_after_parsing():
    from app.ai.providers.base import classify_http_failure

    # Header form (RFC 7231 — integer seconds).
    f1 = classify_http_failure(
        provider_name="openai", status=429, body="too many", retry_after_header="42"
    )
    assert f1.retry_after_seconds == 42
    # Body form (Gemini structured retryDelay).
    f2 = classify_http_failure(
        provider_name="gemini",
        status=429,
        body='{"error":{"status":"RESOURCE_EXHAUSTED"},"details":[{"retryDelay":"60s"}]}',
    )
    assert f2.retry_after_seconds == 60
    # Body form (Gemini prose).
    f3 = classify_http_failure(
        provider_name="gemini",
        status=429,
        body="Quota exceeded. Please retry in 35.6s.",
    )
    assert f3.retry_after_seconds == 35


# ============================================================ Ollama


@pytest.mark.asyncio
async def test_ollama_happy_path_zero_cost():
    def handler(request: httpx.Request) -> httpx.Response:
        assert str(request.url).endswith("/api/chat")
        body = json.loads(request.content.decode())
        assert body["model"] == "llama3.3:70b"
        assert body["stream"] is False
        return httpx.Response(
            200,
            json={
                "message": {"content": "Local answer."},
                "prompt_eval_count": 50,
                "eval_count": 20,
            },
        )

    provider = OllamaProvider(client_factory=lambda: _make_client(handler))
    resp = await provider.generate(_llm_req())
    assert resp.text == "Local answer."
    assert resp.usage.input_tokens == 50
    assert resp.usage.output_tokens == 20
    assert resp.usage.cost_usd == 0.0
    assert resp.provider == "ollama"


@pytest.mark.asyncio
async def test_ollama_format_passthrough_when_schema_given():
    schema = {"type": "object", "properties": {"y": {"type": "string"}}}

    captured = {}

    def handler(request: httpx.Request) -> httpx.Response:
        captured["body"] = json.loads(request.content.decode())
        return httpx.Response(
            200,
            json={"message": {"content": '{"y": "ok"}'}, "prompt_eval_count": 1, "eval_count": 1},
        )

    provider = OllamaProvider(client_factory=lambda: _make_client(handler))
    resp = await provider.generate(_llm_req(response_schema=schema))
    assert captured["body"]["format"] == schema
    assert resp.parsed == {"y": "ok"}


@pytest.mark.asyncio
async def test_ollama_health_check_uses_tags_endpoint():
    def handler(request: httpx.Request) -> httpx.Response:
        assert str(request.url).endswith("/api/tags")
        return httpx.Response(200, json={"models": []})

    provider = OllamaProvider(client_factory=lambda: _make_client(handler))
    assert await provider.health_check() is True


# ============================================================ vLLM


@pytest.mark.asyncio
async def test_vllm_costs_zero_even_when_model_priced():
    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(
            200,
            json={
                "choices": [{"message": {"content": "vllm answer"}}],
                "usage": {"prompt_tokens": 200, "completion_tokens": 50},
            },
        )

    provider = VllmProvider(
        base_url="http://vllm:8000/v1",
        default_model="gpt-4o-mini",  # priced in OpenAI table on purpose
        client_factory=lambda: _make_client(handler),
    )
    resp = await provider.generate(_llm_req())
    assert resp.provider == "vllm"
    # Even though gpt-4o-mini is priced in PRICING['openai'], vLLM is local — $0.
    assert resp.usage.cost_usd == 0.0

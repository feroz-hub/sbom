"""SBO-99: native OpenAI transport contracts. All inference is mocked."""

import json
from dataclasses import replace

import httpx
import pytest
from app.ai.cost import BudgetCaps, BudgetGuard, estimate_cost_usd
from app.ai.providers.base import BudgetExceededError, LlmRequest
from app.ai.providers.openai import OpenAiProvider
from app.ai.providers.openai_compat import OpenAiError
from app.ai.providers.openai_models import PROFILES, profile_for

SCHEMA = {
    "type": "object",
    "properties": {"ok": {"type": "boolean", "enum": [True]}},
    "required": ["ok"],
    "additionalProperties": False,
}


def request(**kwargs):
    return LlmRequest(
        system="Return only JSON matching the schema.",
        user='Return {"ok": true}.',
        response_schema=SCHEMA,
        request_id="synthetic-sbo99",
        **kwargs,
    )


def response(model, text='{"ok":true}', **kwargs):
    if profile_for(model).endpoint == "responses":
        return {
            "status": "completed",
            "output": [
                {"type": "reasoning", "summary": [], "encrypted_content": "never surface internal reasoning"},
                {"type": "message", "content": [{"type": "output_text", "text": text}]},
            ],
            "usage": {"input_tokens": 20, "output_tokens": 125, "output_tokens_details": {"reasoning_tokens": 100}},
            **kwargs,
        }
    return {
        "choices": [{"finish_reason": "stop", "message": {"content": text}}],
        "usage": {"prompt_tokens": 20, "completion_tokens": 125},
        **kwargs,
    }


@pytest.mark.asyncio
@pytest.mark.parametrize("model", list(PROFILES))
async def test_exact_documented_ids_use_supported_endpoint_and_bounded_parameters(model):
    profile = profile_for(model)
    calls = []

    def handler(req):
        body = json.loads(req.content)
        calls.append(body)
        assert req.url.path == "/v1/" + profile.endpoint
        assert body["model"] == model  # Never replace an exact ID with an alias.
        assert body[profile.token_parameter] == 2048
        assert sum(key in body for key in ("max_tokens", "max_completion_tokens", "max_output_tokens")) == 1
        if profile.reasoning_efforts:
            assert "temperature" not in body
            assert body["reasoning"] == {"effort": "low"}
            assert body["store"] is False
            assert body["text"]["format"]["schema"] == SCHEMA
        else:
            assert body["temperature"] == 0.2
            assert body["response_format"]["json_schema"]["schema"] == SCHEMA
        return httpx.Response(200, json=response(model))

    async with httpx.AsyncClient(transport=httpx.MockTransport(handler)) as client:
        provider = OpenAiProvider(api_key="synthetic-key", default_model=model, client_factory=lambda: client)
        result = await provider.generate(request(max_output_tokens=2048))
    assert result.parsed == {"ok": True}
    assert result.model == model
    assert result.usage.output_tokens == 125  # Includes reasoning; do not add it twice.
    assert result.usage.cost_usd == estimate_cost_usd(
        provider="openai", model=model, input_tokens=20, output_tokens=125
    )
    assert "internal reasoning" not in result.text
    assert len(calls) == 1


@pytest.mark.asyncio
@pytest.mark.parametrize(
    ("status", "code", "kind"),
    [
        (401, "invalid_api_key", "auth"),
        (403, "permission_denied", "permission"),
        (404, "model_not_found", "model_not_found"),
        (400, "unsupported_parameter", "unsupported_parameter"),
        (400, "invalid_request_error", "configuration"),
        (429, "insufficient_quota", "quota"),
        (429, "rate_limit_exceeded", "rate_limit"),
        (503, "server_error", "provider_unavailable"),
    ],
)
async def test_probe_errors_are_distinct_sanitized_and_never_retried(status, code, kind, caplog):
    calls = []

    def handler(req):
        calls.append(req)
        if req.method == "GET":
            return httpx.Response(200, json={"data": [{"id": "gpt-6-luna"}]})
        return httpx.Response(status, json={"error": {"code": code, "message": "sensitive-prompt-and-key"}})

    async with httpx.AsyncClient(transport=httpx.MockTransport(handler)) as client:
        provider = OpenAiProvider(
            api_key="sensitive-prompt-and-key", default_model="gpt-6-luna", client_factory=lambda: client
        )
        result = await provider.test_connection()
    assert result.discovered is True
    assert not result.success
    assert result.error_kind == kind
    assert len([c for c in calls if c.method == "POST"]) == 1
    assert "sensitive-prompt-and-key" not in result.model_dump_json() + caplog.text


@pytest.mark.asyncio
@pytest.mark.parametrize(
    ("payload", "kind", "generated"),
    [
        (
            response("gpt-6-luna", status="incomplete", incomplete_details={"reason": "max_output_tokens"}),
            "incomplete",
            True,
        ),
        (
            response(
                "gpt-6-luna", output=[{"type": "message", "content": [{"type": "refusal", "refusal": "private"}]}]
            ),
            "refusal",
            False,
        ),
        (response("gpt-6-luna", "not JSON"), "invalid_json", True),
        (response("gpt-6-luna", '{"ok":false}'), "invalid_json", True),
        (response("gpt-6-luna", '{"ok":true,"extra":1}'), "invalid_json", True),
        (response("gpt-6-luna", ""), "invalid_response", False),
        (response("gpt-6-luna", output=[{"type": "message", "content": 7}]), "invalid_response", False),
    ],
)
async def test_output_failures_retain_billable_usage(payload, kind, generated):
    async with httpx.AsyncClient(
        transport=httpx.MockTransport(lambda req: httpx.Response(200, json=payload))
    ) as client:
        provider = OpenAiProvider(api_key="fake", default_model="gpt-6-luna", client_factory=lambda: client)
        with pytest.raises(OpenAiError) as error:
            await provider.generate(request())
    assert error.value.kind == kind
    assert error.value.accessible is True
    assert error.value.generated is generated
    assert error.value.usage.output_tokens == 125
    assert error.value.usage.cost_usd > 0


@pytest.mark.asyncio
@pytest.mark.parametrize("exc", [httpx.ReadTimeout, httpx.ConnectError])
async def test_network_failure_categories_and_no_secret_echo(exc):
    def handler(req):
        raise exc("sensitive-request", request=req)

    async with httpx.AsyncClient(transport=httpx.MockTransport(handler)) as client:
        provider = OpenAiProvider(api_key="fake", client_factory=lambda: client, max_retries=0)
        with pytest.raises(OpenAiError) as error:
            await provider.generate(request())
    assert error.value.kind == ("timeout" if exc is httpx.ReadTimeout else "network")
    assert "sensitive-request" not in str(error.value)
    assert error.value.failure.upstream_body is None


@pytest.mark.asyncio
async def test_discovery_does_not_claim_access_or_generation_and_unknown_models_fail_closed():
    models = ["gpt-6-luna", "text-embedding-3-small", "future-generation-model", "gpt-6-terra"]
    calls = []

    def handler(req):
        calls.append(req)
        return httpx.Response(200, json={"data": [{"id": model} for model in models]})

    async with httpx.AsyncClient(transport=httpx.MockTransport(handler)) as client:
        provider = OpenAiProvider(api_key="fake", client_factory=lambda: client)
        discovered = await provider.list_models()
        assert [m.runtime_model_id for m in discovered] == models
        assert discovered[0].supports_chat is True
        assert discovered[1].supports_chat is False
        assert discovered[2].supports_chat is None
        for model in models[1:]:
            result = await provider.test_connection(model=model)
            assert result.discovered is True
            assert result.accessible is None
            assert result.workload_compatible is None
            assert result.error_kind == "unsupported_model"
    assert all(req.method == "GET" for req in calls)


@pytest.mark.asyncio
async def test_future_profile_can_explicitly_select_modern_chat_parameters():
    profile = replace(PROFILES["gpt-6-luna"], endpoint="chat/completions", token_parameter="max_completion_tokens")

    def handler(req):
        body = json.loads(req.content)
        assert body["model"] == "future-reviewed-model"
        assert body["max_completion_tokens"] == 1024
        assert body["reasoning_effort"] == "low"
        assert "max_tokens" not in body and "temperature" not in body
        return httpx.Response(200, json=response("gpt-4o"))

    async with httpx.AsyncClient(transport=httpx.MockTransport(handler)) as client:
        provider = OpenAiProvider(
            api_key="fake",
            default_model="future-reviewed-model",
            model_profiles={"future-reviewed-model": profile},
            client_factory=lambda: client,
        )
        assert (await provider.generate(request())).parsed == {"ok": True}


def test_schema_normalization_keeps_caller_unchanged_and_handles_nested_objects():
    schema = {
        "type": "object",
        "properties": {"nested": {"type": "object", "properties": {"x": {"type": "string", "default": ""}}}},
    }
    original = json.dumps(schema)
    provider = OpenAiProvider(api_key="fake")
    body = provider._build_body(request().model_copy(update={"response_schema": schema}), "gpt-6-luna")
    strict = body["text"]["format"]["schema"]
    assert strict["required"] == ["nested"]
    assert strict["properties"]["nested"]["additionalProperties"] is False
    assert "default" not in strict["properties"]["nested"]["properties"]["x"]
    assert json.dumps(schema) == original


def test_reasoning_budget_is_not_silently_increased_and_costs_are_not_zero():
    model = "gpt-6.1-sol"
    provider = OpenAiProvider(api_key="fake", default_model=model)
    body = provider._build_body(request(max_output_tokens=900), model)
    assert body["max_output_tokens"] == 900
    estimated = estimate_cost_usd(provider="openai", model=model, input_tokens=500, output_tokens=900)
    assert estimated > 0
    guard = BudgetGuard(BudgetCaps(per_request_usd=0.0001, per_scan_usd=None, per_day_org_usd=None))
    with pytest.raises(BudgetExceededError):
        guard.check_request(estimated_usd=estimated)


@pytest.mark.asyncio
async def test_one_provider_can_switch_model_families_without_stale_parameters():
    bodies = []

    def handler(req):
        body = json.loads(req.content)
        bodies.append(body)
        return httpx.Response(200, json=response(body["model"]))

    async with httpx.AsyncClient(transport=httpx.MockTransport(handler)) as client:
        provider = OpenAiProvider(api_key="fake", client_factory=lambda: client)
        for model in ("gpt-4o", "gpt-6-luna", "gpt-4o-mini"):
            await provider.generate(request(model=model))
    assert ["max_tokens" in body for body in bodies] == [True, False, True]


@pytest.mark.asyncio
async def test_probe_requires_structured_generation_even_when_model_is_discovered():
    def handler(req):
        if req.method == "GET":
            return httpx.Response(200, json={"data": [{"id": "gpt-6-luna"}]})
        body = json.loads(req.content)
        assert body["max_output_tokens"] == 2048
        assert body["text"]["format"]["schema"] == SCHEMA
        return httpx.Response(200, json=response("gpt-6-luna", "ok"))

    async with httpx.AsyncClient(transport=httpx.MockTransport(handler)) as client:
        result = await OpenAiProvider(api_key="fake", client_factory=lambda: client).test_connection(model="gpt-6-luna")
    assert not result.success
    assert result.accessible is True and result.generation_verified is True
    assert result.workload_compatible is False and result.error_kind == "invalid_json"


@pytest.mark.asyncio
@pytest.mark.parametrize("name", ["gemini", "grok", "vllm", "custom_openai", "sarvam"])
async def test_compatible_providers_do_not_inherit_native_model_routing(name):
    from app.ai.config_types import ProviderConfig
    from app.ai.provider_factory import build_provider

    def handler(req):
        body = json.loads(req.content)
        assert req.url.path.endswith("/chat/completions")
        assert "max_tokens" in body and "max_output_tokens" not in body
        assert "messages" in body and "input" not in body
        return httpx.Response(200, json=response("gpt-4o"))

    async with httpx.AsyncClient(transport=httpx.MockTransport(handler)) as client:
        provider = build_provider(
            ProviderConfig(
                name=name,
                enabled=True,
                api_key="synthetic-only",
                default_model="gpt-6-luna",
                base_url="http://localhost:8000/v1",
            ),
            client_factory=lambda: client,
        )
        assert (await provider.generate(request())).provider == name


@pytest.mark.asyncio
async def test_registry_fallback_rebuilds_request_for_exact_fallback_model():
    from app.ai.config_types import ProviderConfig
    from app.ai.registry import ProviderRegistry

    calls = []

    def handler(req):
        body = json.loads(req.content)
        calls.append((req.url.path, body))
        if body["model"] == "gpt-4o-mini":
            return httpx.Response(429, json={"error": {"code": "rate_limit_exceeded"}})
        assert body["model"] == "gpt-6-luna"
        assert "max_output_tokens" in body and "max_tokens" not in body
        return httpx.Response(200, json=response("gpt-6-luna"))

    configs = [
        ProviderConfig(name="openai", enabled=True, default_model="gpt-4o-mini", credential_id=1, is_default=True),
        ProviderConfig(name="openai", enabled=True, default_model="gpt-6-luna", credential_id=2, is_fallback=True),
    ]
    registry = ProviderRegistry(configs, default_provider="credential:1")
    async with httpx.AsyncClient(transport=httpx.MockTransport(handler)) as client:
        for config in configs:
            registry.register_instance(
                OpenAiProvider(
                    api_key="synthetic-only",
                    default_model=config.default_model,
                    client_factory=lambda: client,
                    max_retries=0,
                ),
                selector=config.selection_key,
            )
        result = await registry.generate_with_fallback(request())
    assert result.fallback_used and result.response.model == "gpt-6-luna"
    assert [path for path, body in calls] == ["/v1/chat/completions", "/v1/responses"]


def test_unsupported_reasoning_setting_is_rejected_before_invocation():
    provider = OpenAiProvider(api_key="synthetic-only", reasoning_effort="none")
    with pytest.raises(OpenAiError) as error:
        provider._build_body(request(), "gpt-6.1-sol")
    assert error.value.kind == "unsupported_parameter"
    assert provider._build_body(request(), "gpt-6-sol")["reasoning"] == {"effort": "none"}

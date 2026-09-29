"""Tests for ``test_connection`` across every provider.

Phase 1 §1.6: every provider must classify connection failures into
typed :class:`ConnectionErrorKind` values so the Settings UI can pick a
specific message. These tests exercise each error kind on each
provider via ``httpx.MockTransport``.
"""

from __future__ import annotations

import httpx
import pytest
from app.ai.providers.anthropic import AnthropicProvider
from app.ai.providers.custom_openai_compatible import CustomOpenAiCompatibleProvider
from app.ai.providers.gemini import GeminiProvider
from app.ai.providers.grok import GrokProvider
from app.ai.providers.ollama import OllamaProvider
from app.ai.providers.openai import OpenAiProvider
from app.ai.providers.vllm import VllmProvider


def _make_client(handler):
    return httpx.AsyncClient(transport=httpx.MockTransport(handler))


# ============================================================ Success (models endpoint)


@pytest.mark.asyncio
async def test_openai_test_connection_via_models_endpoint():
    def handler(request: httpx.Request) -> httpx.Response:
        if str(request.url).endswith("/models"):
            return httpx.Response(
                200,
                json={"data": [{"id": "gpt-4o-mini"}, {"id": "gpt-4o"}]},
            )
        assert str(request.url).endswith("/chat/completions")
        return httpx.Response(200, json={"choices": [{"message": {"content": "ok"}}]})

    provider = OpenAiProvider(api_key="sk-test", client_factory=lambda: _make_client(handler))
    result = await provider.test_connection()
    assert result.success is True
    assert "gpt-4o-mini" in result.detected_models
    assert result.error_kind is None
    assert result.provider == "openai"
    assert result.latency_ms is not None and result.latency_ms >= 0


@pytest.mark.asyncio
async def test_anthropic_test_connection_via_v1_models():
    def handler(request: httpx.Request) -> httpx.Response:
        assert "anthropic.com/v1/models" in str(request.url)
        return httpx.Response(
            200,
            json={"data": [{"id": "claude-sonnet-4-5"}, {"id": "claude-haiku-4-5"}]},
        )

    provider = AnthropicProvider(api_key="sk-ant", client_factory=lambda: _make_client(handler))
    result = await provider.test_connection()
    assert result.success is True
    assert "claude-sonnet-4-5" in result.detected_models


@pytest.mark.asyncio
async def test_ollama_test_connection_via_api_tags():
    def handler(request: httpx.Request) -> httpx.Response:
        assert str(request.url).endswith("/api/tags")
        return httpx.Response(200, json={"models": [{"name": "llama3.3:70b"}]})

    provider = OllamaProvider(client_factory=lambda: _make_client(handler))
    result = await provider.test_connection()
    assert result.success is True
    assert "llama3.3:70b" in result.detected_models


# ============================================================ Failure modes — typed error_kind


@pytest.mark.asyncio
async def test_openai_test_connection_auth_failure():
    def handler(request):
        return httpx.Response(401, text="invalid api key")

    provider = OpenAiProvider(api_key="bad", client_factory=lambda: _make_client(handler))
    result = await provider.test_connection()
    assert result.success is False
    assert result.error_kind == "auth"


@pytest.mark.asyncio
async def test_openai_test_connection_rate_limit():
    def handler(request):
        return httpx.Response(429, text="rate limited")

    provider = OpenAiProvider(api_key="k", client_factory=lambda: _make_client(handler))
    result = await provider.test_connection()
    assert result.success is False
    assert result.error_kind == "rate_limit"


@pytest.mark.asyncio
async def test_openai_test_connection_network_error():
    def handler(request):
        raise httpx.ConnectError("connection refused")

    provider = OpenAiProvider(api_key="k", client_factory=lambda: _make_client(handler))
    result = await provider.test_connection()
    assert result.success is False
    assert result.error_kind == "network"


@pytest.mark.asyncio
async def test_openai_falls_back_to_completion_when_models_404():
    """Some OpenAI-compatible servers don't have /models — fall back."""
    requests = []

    def handler(request: httpx.Request) -> httpx.Response:
        requests.append(str(request.url))
        if request.url.path.endswith("/models"):
            return httpx.Response(404, text="not implemented")
        # Chat-completion fallback succeeds.
        return httpx.Response(
            200,
            json={
                "choices": [{"message": {"content": "ok"}}],
                "usage": {"prompt_tokens": 1, "completion_tokens": 1},
            },
        )

    provider = OpenAiProvider(api_key="k", client_factory=lambda: _make_client(handler))
    result = await provider.test_connection()
    assert result.success is True
    # Both endpoints were probed.
    assert any("/models" in u for u in requests)
    assert any("/chat/completions" in u for u in requests)


@pytest.mark.asyncio
async def test_openai_test_connection_rejects_listed_but_unusable_model():
    """A models listing is not proof that generation is enabled for the model."""

    def handler(request: httpx.Request) -> httpx.Response:
        if request.method == "GET":
            return httpx.Response(200, json={"data": [{"id": "retired-model"}]})
        return httpx.Response(404, json={"error": {"message": "model is unavailable"}})

    provider = OpenAiProvider(
        api_key="k",
        default_model="retired-model",
        client_factory=lambda: _make_client(handler),
    )
    result = await provider.test_connection()
    assert result.success is False
    assert result.error_kind == "model_not_found"
    assert result.detected_models == ["retired-model"]


@pytest.mark.asyncio
async def test_anthropic_invalid_json_response():
    def handler(request):
        return httpx.Response(200, content=b"not json", headers={"content-type": "application/json"})

    provider = AnthropicProvider(api_key="k", client_factory=lambda: _make_client(handler))
    result = await provider.test_connection()
    assert result.success is False
    assert result.error_kind == "invalid_response"


# ============================================================ Wrappers (vLLM / Gemini / Grok / Custom)


@pytest.mark.asyncio
async def test_vllm_test_connection_overrides_provider_label():
    def handler(request):
        if request.method == "GET":
            return httpx.Response(200, json={"data": [{"id": "llama-70b"}]})
        return httpx.Response(200, json={"choices": [{"message": {"content": "ok"}}]})

    provider = VllmProvider(
        base_url="http://localhost:8000/v1",
        default_model="llama-70b",
        client_factory=lambda: _make_client(handler),
    )
    result = await provider.test_connection()
    assert result.success is True
    # Wrapper must report its own name, not "openai".
    assert result.provider == "vllm"


@pytest.mark.asyncio
async def test_gemini_test_connection_labels_correctly():
    def handler(request):
        if request.method == "GET":
            return httpx.Response(200, json={"data": [{"id": "gemini-3.6-flash"}]})
        return httpx.Response(200, json={"choices": [{"message": {"content": "ok"}}]})

    provider = GeminiProvider(api_key="k", client_factory=lambda: _make_client(handler))
    result = await provider.test_connection()
    assert result.provider == "gemini"
    assert result.success is True


@pytest.mark.asyncio
async def test_grok_test_connection_labels_correctly():
    def handler(request):
        if request.method == "GET":
            return httpx.Response(200, json={"data": [{"id": "grok-2-mini"}]})
        return httpx.Response(200, json={"choices": [{"message": {"content": "ok"}}]})

    provider = GrokProvider(api_key="k", client_factory=lambda: _make_client(handler))
    result = await provider.test_connection()
    assert result.provider == "grok"
    assert result.success is True


@pytest.mark.asyncio
async def test_custom_test_connection_labels_correctly():
    def handler(request):
        if request.method == "GET":
            return httpx.Response(200, json={"data": [{"id": "my-model"}]})
        return httpx.Response(200, json={"choices": [{"message": {"content": "ok"}}]})

    provider = CustomOpenAiCompatibleProvider(
        base_url="http://localhost:8000/v1",
        default_model="my-model",
        client_factory=lambda: _make_client(handler),
    )
    result = await provider.test_connection()
    assert result.provider == "custom_openai"
    assert result.success is True

# Every adapter shares probe classification, including delegated OpenAI-compatible adapters.
@pytest.mark.asyncio
@pytest.mark.parametrize('name', ['anthropic', 'openai', 'gemini', 'grok', 'sarvam', 'ollama', 'vllm', 'custom_openai'])
@pytest.mark.parametrize(('status', 'kind'), [(401, 'auth'), (403, 'auth'), (408, 'network'), (429, 'rate_limit'), (500, 'provider_unavailable'), (502, 'provider_unavailable'), (503, 'provider_unavailable'), (504, 'provider_unavailable'), (400, 'configuration')])
async def test_all_adapters_classify_and_sanitize_failures(name, status, kind, caplog):
    from app.ai.config_types import ProviderConfig
    from app.ai.provider_factory import build_provider
    secret = 'sentinel-private-api-key'
    def handler(request):
        return httpx.Response(status, json={'error': {'message': secret, 'status': 'UNAVAILABLE'}})
    provider = build_provider(ProviderConfig(name=name, enabled=True, api_key=secret, base_url='http://localhost:8000/v1', default_model='test-model'), client_factory=lambda: _make_client(handler))
    result = await provider.test_connection()
    assert not result.success
    assert result.error_kind == kind
    assert result.http_status == status
    assert secret not in result.model_dump_json()
    assert secret not in caplog.text


@pytest.mark.asyncio
@pytest.mark.parametrize('exc_type', [httpx.ReadTimeout, httpx.ConnectTimeout, httpx.ConnectError])
async def test_probe_network_exception_never_exposes_secrets(exc_type, caplog):
    def handler(request):
        raise exc_type('secret-key-in-url', request=request)
    provider = OpenAiProvider(api_key='secret-key-in-url', client_factory=lambda: _make_client(handler))
    result = await provider.test_connection()
    assert result.error_kind == 'network'
    assert 'secret-key-in-url' not in result.model_dump_json()
    assert 'secret-key-in-url' not in caplog.text


def test_gemini_400_requires_explicit_invalid_key_reason():
    from app.ai.providers._probe import classify_http_error
    assert classify_http_error(400, '{"error":{"details":[{"reason":"API_KEY_INVALID"}]}}') == 'auth'
    assert classify_http_error(400, '{"error":{"message":"invalid model"}}') == 'configuration'

@pytest.mark.asyncio
async def test_gemini_invalid_key_on_models_endpoint_is_auth():
    def handler(request):
        return httpx.Response(400, json={'error': {'details': [{'reason': 'API_KEY_INVALID'}]}})
    provider = GeminiProvider(api_key='bad-key', client_factory=lambda: _make_client(handler))
    assert (await provider.test_connection()).error_kind == 'auth'

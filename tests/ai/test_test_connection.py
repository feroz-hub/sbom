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
        assert str(request.url).endswith("/models")
        return httpx.Response(
            200,
            json={"data": [{"id": "gpt-4o-mini"}, {"id": "gpt-4o"}]},
        )

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
        return httpx.Response(200, json={"data": [{"id": "llama-70b"}]})

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
        return httpx.Response(200, json={"data": [{"id": "gemini-2.5-flash"}]})

    provider = GeminiProvider(api_key="k", client_factory=lambda: _make_client(handler))
    result = await provider.test_connection()
    assert result.provider == "gemini"
    assert result.success is True


@pytest.mark.asyncio
async def test_grok_test_connection_labels_correctly():
    def handler(request):
        return httpx.Response(200, json={"data": [{"id": "grok-2-mini"}]})

    provider = GrokProvider(api_key="k", client_factory=lambda: _make_client(handler))
    result = await provider.test_connection()
    assert result.provider == "grok"
    assert result.success is True


@pytest.mark.asyncio
async def test_custom_test_connection_labels_correctly():
    def handler(request):
        return httpx.Response(200, json={"data": [{"id": "my-model"}]})

    provider = CustomOpenAiCompatibleProvider(
        base_url="http://localhost:8000/v1",
        default_model="my-model",
        client_factory=lambda: _make_client(handler),
    )
    result = await provider.test_connection()
    assert result.provider == "custom_openai"
    assert result.success is True

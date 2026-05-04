"""Tests for the Phase 1 free-tier providers + Custom OpenAI-compatible.

Same MockTransport pattern as ``test_providers.py`` — no real network.
"""

from __future__ import annotations

import httpx
import pytest
from app.ai.providers.base import (
    LlmRequest,
    ProviderUnavailableError,
)
from app.ai.providers.custom_openai_compatible import (
    CustomOpenAiCompatibleProvider,
    _validate_base_url,
)
from app.ai.providers.gemini import GeminiProvider
from app.ai.providers.grok import GrokProvider


def _make_client(handler):
    return httpx.AsyncClient(transport=httpx.MockTransport(handler))


def _llm_req(**overrides):
    base = dict(
        system="You are a security engineer.",
        user="Summarise CVE-2099-9001.",
        max_output_tokens=64,
        temperature=0.2,
        request_id="t-1",
        purpose="remediation_prose",
    )
    base.update(overrides)
    return LlmRequest(**base)


# ============================================================ Gemini


@pytest.mark.asyncio
async def test_gemini_uses_openai_compatible_endpoint():
    captured = {}

    def handler(request: httpx.Request) -> httpx.Response:
        captured["url"] = str(request.url)
        captured["headers"] = dict(request.headers)
        return httpx.Response(
            200,
            json={
                "choices": [{"message": {"content": "Looks risky."}}],
                "usage": {"prompt_tokens": 30, "completion_tokens": 10},
            },
        )

    provider = GeminiProvider(
        api_key="AIzaSy-test",
        client_factory=lambda: _make_client(handler),
        tier="free",
    )
    resp = await provider.generate(_llm_req())
    # Endpoint = Gemini's OpenAI-compatible path.
    assert "generativelanguage.googleapis.com/v1beta/openai" in captured["url"]
    # Cost falls under Gemini's pricing table — gemini-2.5-flash:
    # $0.000075 / 1k input + $0.0003 / 1k output.
    expected = round(30 / 1000 * 0.000075 + 10 / 1000 * 0.0003, 6)
    assert resp.usage.cost_usd == expected
    assert resp.provider == "gemini"


@pytest.mark.asyncio
async def test_gemini_free_tier_clamps_rpm():
    """Free tier must clamp RPM to 15 even if caller passes higher."""

    def handler(request):
        return httpx.Response(
            200,
            json={"choices": [{"message": {"content": "ok"}}], "usage": {"prompt_tokens": 1, "completion_tokens": 1}},
        )

    provider = GeminiProvider(
        api_key="key",
        tier="free",
        rate_per_minute=10000,  # caller asks for 10k — registry must clamp
        client_factory=lambda: _make_client(handler),
    )
    # The inner provider's limiter receives the clamped rate.
    assert provider._inner._limiter.rate <= 15.0


@pytest.mark.asyncio
async def test_gemini_paid_tier_honors_rate():
    def handler(request):
        return httpx.Response(
            200,
            json={"choices": [{"message": {"content": "ok"}}], "usage": {"prompt_tokens": 1, "completion_tokens": 1}},
        )

    provider = GeminiProvider(
        api_key="key",
        tier="paid",
        rate_per_minute=2000,
        client_factory=lambda: _make_client(handler),
    )
    assert provider._inner._limiter.rate == 2000.0


def test_gemini_requires_api_key():
    with pytest.raises(ProviderUnavailableError):
        GeminiProvider(api_key="")


# ============================================================ Grok


@pytest.mark.asyncio
async def test_grok_uses_xai_endpoint():
    captured = {}

    def handler(request: httpx.Request) -> httpx.Response:
        captured["url"] = str(request.url)
        return httpx.Response(
            200,
            json={
                "choices": [{"message": {"content": "ok"}}],
                "usage": {"prompt_tokens": 50, "completion_tokens": 20},
            },
        )

    provider = GrokProvider(
        api_key="xai-test",
        client_factory=lambda: _make_client(handler),
        tier="free",
    )
    resp = await provider.generate(_llm_req())
    assert "api.x.ai/v1" in captured["url"]
    assert resp.provider == "grok"
    # grok-2-mini: $0.0002 / 1k input + $0.001 / 1k output.
    expected = round(50 / 1000 * 0.0002 + 20 / 1000 * 0.001, 6)
    assert resp.usage.cost_usd == expected


@pytest.mark.asyncio
async def test_grok_free_tier_info_warns_about_batch():
    provider = GrokProvider(api_key="x", tier="free", client_factory=lambda: _make_client(lambda r: None))
    info = provider.info()
    # Free-tier note should mention the daily cap or rate.
    assert any(s in info.notes.lower() for s in ("free tier", "tight"))


def test_grok_requires_api_key():
    with pytest.raises(ProviderUnavailableError):
        GrokProvider(api_key="")


# ============================================================ Custom OpenAI-compatible


def test_custom_validates_https_required_for_remote():
    with pytest.raises(ProviderUnavailableError):
        # Plaintext public URL — banned.
        CustomOpenAiCompatibleProvider(
            base_url="http://api.evil-public-host.com/v1",
            default_model="my-model",
        )


def test_custom_allows_https_remote():
    provider = CustomOpenAiCompatibleProvider(
        base_url="https://litellm.example.com/v1",
        default_model="claude-3-haiku",
    )
    assert provider.default_model == "claude-3-haiku"


def test_custom_allows_http_localhost():
    provider = CustomOpenAiCompatibleProvider(
        base_url="http://localhost:1234/v1",
        default_model="local-model",
    )
    assert provider.is_local


def test_custom_rejects_scheme_less_url():
    with pytest.raises(ProviderUnavailableError):
        CustomOpenAiCompatibleProvider(base_url="api.example.com/v1", default_model="m")


def test_custom_requires_default_model():
    with pytest.raises(ProviderUnavailableError):
        CustomOpenAiCompatibleProvider(base_url="https://x/v1", default_model="")


@pytest.mark.asyncio
async def test_custom_zero_cost_by_default():
    def handler(request):
        return httpx.Response(
            200,
            json={
                "choices": [{"message": {"content": "ok"}}],
                "usage": {"prompt_tokens": 1000, "completion_tokens": 500},
            },
        )

    provider = CustomOpenAiCompatibleProvider(
        base_url="http://localhost:8000/v1",
        default_model="llama-3-70b",
        client_factory=lambda: _make_client(handler),
    )
    resp = await provider.generate(_llm_req())
    # Default cost is $0 — most local setups have no per-token cost.
    assert resp.usage.cost_usd == 0.0
    assert resp.provider == "custom_openai"


@pytest.mark.asyncio
async def test_custom_honors_supplied_cost_overrides():
    def handler(request):
        return httpx.Response(
            200,
            json={
                "choices": [{"message": {"content": "ok"}}],
                "usage": {"prompt_tokens": 1000, "completion_tokens": 500},
            },
        )

    provider = CustomOpenAiCompatibleProvider(
        base_url="https://litellm.proxy.internal/v1",
        default_model="proxied-model",
        client_factory=lambda: _make_client(handler),
        cost_per_1k_input_usd=0.001,
        cost_per_1k_output_usd=0.002,
        is_local=False,
    )
    resp = await provider.generate(_llm_req())
    expected = round(1000 / 1000 * 0.001 + 500 / 1000 * 0.002, 6)
    assert resp.usage.cost_usd == expected


def test_validate_base_url_helper():
    assert _validate_base_url("https://api.example.com/v1")
    assert _validate_base_url("http://localhost:11434")
    assert _validate_base_url("http://127.0.0.1:8080/v1")
    with pytest.raises(ProviderUnavailableError):
        _validate_base_url("ftp://example.com/v1")
    with pytest.raises(ProviderUnavailableError):
        _validate_base_url("")

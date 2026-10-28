"""Real-provider integration smoke tests — env-gated.

Phase 1 §1.7 deliverable: integration test calling Gemini and Grok
free-tier endpoints. **Skipped by default** so CI doesn't burn rate
limits on every PR. Run manually with:

    GEMINI_API_KEY=AIzaSy... pytest tests/ai/test_real_provider_smoke.py -v
    GROK_API_KEY=xai-...    pytest tests/ai/test_real_provider_smoke.py -v
    ANTHROPIC_API_KEY=...   pytest tests/ai/test_real_provider_smoke.py -v

Each test takes < 5 seconds and a few cents (or $0 on free tiers).
"""

from __future__ import annotations

import os

import pytest
from app.ai.providers.anthropic import AnthropicProvider
from app.ai.providers.gemini import GeminiProvider
from app.ai.providers.grok import GrokProvider
from app.ai.providers.openai import OpenAiProvider


@pytest.mark.skipif(
    not os.getenv("GEMINI_API_KEY"),
    reason="GEMINI_API_KEY not set — skipping real-provider smoke",
)
@pytest.mark.asyncio
async def test_real_gemini_free_tier_test_connection():  # pragma: no cover
    provider = GeminiProvider(api_key=os.environ["GEMINI_API_KEY"], tier="free")
    result = await provider.test_connection()
    assert result.success is True, f"Gemini test failed: {result.error_message}"
    assert "gemini" in (m.lower() for m in result.detected_models)
    assert result.latency_ms is not None


@pytest.mark.skipif(
    not os.getenv("GROK_API_KEY"),
    reason="GROK_API_KEY not set — skipping real-provider smoke",
)
@pytest.mark.asyncio
async def test_real_grok_free_tier_test_connection():  # pragma: no cover
    provider = GrokProvider(api_key=os.environ["GROK_API_KEY"], tier="free")
    result = await provider.test_connection()
    assert result.success is True, f"Grok test failed: {result.error_message}"
    assert any("grok" in m.lower() for m in result.detected_models)


@pytest.mark.skipif(
    not os.getenv("ANTHROPIC_API_KEY"),
    reason="ANTHROPIC_API_KEY not set — skipping real-provider smoke",
)
@pytest.mark.asyncio
async def test_real_anthropic_test_connection():  # pragma: no cover
    provider = AnthropicProvider(api_key=os.environ["ANTHROPIC_API_KEY"])
    result = await provider.test_connection()
    assert result.success is True, f"Anthropic test failed: {result.error_message}"


@pytest.mark.skipif(
    not os.getenv("OPENAI_API_KEY"),
    reason="OPENAI_API_KEY not set — skipping real-provider smoke",
)
@pytest.mark.asyncio
async def test_real_openai_test_connection():  # pragma: no cover
    provider = OpenAiProvider(api_key=os.environ["OPENAI_API_KEY"])
    result = await provider.test_connection()
    assert result.success is True, f"OpenAI test failed: {result.error_message}"

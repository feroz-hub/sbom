"""Optional local HTTP simulation. This test can never target paid endpoints."""

import os
from urllib.parse import urlsplit

import httpx
import pytest
from app.ai.providers.openai import OpenAiProvider


@pytest.mark.asyncio
async def test_local_postman_http_simulation():
    base = os.getenv("SBO99_MOCK_BASE_URL")
    if not base:
        pytest.skip("Set SBO99_MOCK_BASE_URL to the local Postman simulation's /openai/v1 URL")
    target = urlsplit(base)
    assert target.scheme == "http" and target.hostname in {"localhost", "127.0.0.1", "::1"}
    async with httpx.AsyncClient(trust_env=False) as client:
        provider = OpenAiProvider(api_key="synthetic-local-only", base_url=base, client_factory=lambda: client)
        for model in ("gpt-4o-mini", "gpt-6-luna"):
            result = await provider.test_connection(model=model)
            assert result.success and result.workload_compatible and result.usage.cost_usd > 0
        result = await provider.test_connection(model="gpt-6.1-sol")
        assert result.error_kind == "quota"

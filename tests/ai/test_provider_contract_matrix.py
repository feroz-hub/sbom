"""Catalog-driven end-to-end contract for every supported AI provider.

No upstream network call is made.  The real provider implementations run
against an httpx MockTransport through both Test Connection and generation.
"""

from __future__ import annotations

import importlib
from collections.abc import Callable

import httpx
import pytest
from app.ai.catalog import PROVIDER_CATALOG
from app.ai.config_loader import get_loader
from app.ai.provider_factory import build_provider as real_build_provider
from app.ai.providers.base import LlmRequest
from app.ai.registry import get_registry, reset_registry
from app.db import SessionLocal
from app.models import AiCredentialAuditLog, AiProviderCredential
from app.security.secrets import generate_master_key, reset_cipher

PROVIDER_CASES = [
    pytest.param("anthropic", "claude-sonnet-4-5", "secret-anthropic", None, "paid", False, id="anthropic"),
    pytest.param(
        "openai", "gpt-4o-mini", "secret-openai", "https://mock.openai.example/v1", "paid", False, id="openai"
    ),
    pytest.param("gemini", "gemini-3.6-flash", "secret-gemini", None, "free", False, id="gemini"),
    pytest.param("grok", "grok-2-mini", "secret-grok", None, "free", False, id="grok"),
    pytest.param(
        "sarvam", "sarvam-m", "secret-sarvam", "https://mock.sarvam.example/v1", "paid", False, id="sarvam"
    ),
    pytest.param("ollama", "llama3.2", None, "http://localhost:11434", "paid", True, id="ollama"),
    pytest.param("vllm", "local-model", None, "http://localhost:8001/v1", "paid", True, id="vllm"),
    pytest.param(
        "custom_openai",
        "custom-model",
        None,
        "http://localhost:8002/v1",
        "paid",
        True,
        id="custom-openai",
    ),
]


@pytest.fixture(autouse=True)
def _isolated_credentials(monkeypatch):
    monkeypatch.setenv("AI_CONFIG_ENCRYPTION_KEY", generate_master_key())
    reset_cipher()
    db = SessionLocal()
    try:
        db.query(AiCredentialAuditLog).delete()
        db.query(AiProviderCredential).delete()
        db.commit()
    finally:
        db.close()
    get_loader().invalidate()
    reset_registry()
    yield
    reset_cipher()
    reset_registry()


def _mock_provider_builder(requests: list[httpx.Request]) -> Callable:
    def handler(request: httpx.Request) -> httpx.Response:
        requests.append(request)
        if request.method == "GET" and request.url.path.endswith("/api/tags"):
            return httpx.Response(200, json={"models": [{"name": "llama3.2"}]})
        if request.method == "GET" and request.url.path.endswith("/models"):
            return httpx.Response(200, json={"data": [{"id": "mock-model"}]})
        if request.method == "POST" and request.url.path.endswith("/messages"):
            return httpx.Response(
                200,
                json={
                    "content": [{"type": "text", "text": "ok"}],
                    "usage": {"input_tokens": 1, "output_tokens": 1},
                },
            )
        if request.method == "POST" and request.url.path.endswith("/api/chat"):
            return httpx.Response(
                200,
                json={"message": {"content": "ok"}, "prompt_eval_count": 1, "eval_count": 1},
            )
        if request.method == "POST" and request.url.path.endswith("/chat/completions"):
            return httpx.Response(
                200,
                json={
                    "choices": [{"message": {"content": "ok"}}],
                    "usage": {"prompt_tokens": 1, "completion_tokens": 1},
                },
            )
        return httpx.Response(404, json={"error": {"message": "unexpected mocked path"}})

    transport = httpx.MockTransport(handler)

    def builder(config):
        return real_build_provider(
            config,
            client_factory=lambda: httpx.AsyncClient(transport=transport),
        )

    return builder


@pytest.mark.parametrize(
    ("provider_name", "model", "api_key", "base_url", "tier", "is_local"),
    PROVIDER_CASES,
)
def test_complete_provider_contract_matrix(
    client,
    monkeypatch,
    provider_name: str,
    model: str,
    api_key: str | None,
    base_url: str | None,
    tier: str,
    is_local: bool,
):
    captured: list[httpx.Request] = []
    builder = _mock_provider_builder(captured)
    credentials_router = importlib.import_module("app.routers.ai_credentials")
    registry_module = importlib.import_module("app.ai.registry")
    monkeypatch.setattr(credentials_router, "build_provider", builder)
    monkeypatch.setattr(registry_module, "build_provider", builder)

    catalog = client.get("/api/v1/ai/providers/available")
    assert catalog.status_code == 200
    assert provider_name in {entry["name"] for entry in catalog.json()}
    assert provider_name in {entry.name for entry in PROVIDER_CATALOG}

    payload = {
        "provider_name": provider_name,
        "api_key": api_key,
        "base_url": base_url,
        "default_model": model,
        "tier": tier,
        "is_local": is_local,
        "cost_per_1k_input_usd": 0.001 if provider_name == "custom_openai" else 0.0,
        "cost_per_1k_output_usd": 0.002 if provider_name == "custom_openai" else 0.0,
        "max_concurrent": 3,
        "rate_per_minute": 17.0,
    }

    unsaved = client.post("/api/v1/ai/credentials/test", json=payload)
    assert unsaved.status_code == 200, unsaved.text
    assert unsaved.json()["success"] is True, unsaved.text

    saved = client.post(
        "/api/v1/ai/credentials",
        json={**payload, "label": f"matrix-{provider_name}"},
    )
    assert saved.status_code == 201, saved.text
    credential_id = saved.json()["id"]
    assert api_key not in saved.text if api_key else True

    saved_test = client.post(f"/api/v1/ai/credentials/{credential_id}/test")
    assert saved_test.status_code == 200, saved_test.text
    assert saved_test.json()["success"] is True, saved_test.text
    assert client.put(f"/api/v1/ai/credentials/{credential_id}/set-default").status_code == 200

    configs = get_loader().resolve_configs()
    selected = next(config for config in configs if config.credential_id == credential_id)
    assert selected.default_model == model
    assert selected.base_url == (base_url or "")
    assert selected.max_concurrent == 3
    assert selected.rate_per_minute == 17.0
    assert selected.is_default is True
    assert selected.is_local is is_local

    reset_registry()
    registry = get_registry()
    assert registry.get_default_config().credential_id == credential_id
    import anyio

    generated = anyio.run(
        registry.get_default().generate,
        LlmRequest(system="system", user="user", request_id=f"matrix-{provider_name}"),
    )
    assert generated.text == "ok"
    assert generated.model == model

    generation_requests = [request for request in captured if request.method == "POST"]
    assert generation_requests
    final_request = generation_requests[-1]
    request_body = final_request.content.decode("utf-8")
    assert model in request_body
    if base_url:
        assert str(final_request.url).startswith(base_url.rstrip("/"))
    if provider_name == "openai":
        serialized_headers = "\n".join(f"{key}: {value}" for key, value in final_request.headers.items())
        for marker in ("__default__", "__fallback__", "**default**", "**fallback**"):
            assert marker not in serialized_headers
        assert "openai-organization" not in final_request.headers

"""Dynamic model discovery, lifecycle, selection, and runtime resolution."""

from __future__ import annotations

from datetime import UTC, datetime

import httpx
import pytest
from app.ai.config_loader import AiConfigLoader, _VersionCounter
from app.ai.model_registry import refresh_models, select_model
from app.ai.model_resolver import resolve_model_for_credential
from app.ai.providers.anthropic import AnthropicProvider
from app.ai.providers.base import DiscoveredModel, LlmRequest, LlmResponse, LlmUsage, ModelDiscoveryError
from app.ai.providers.custom_openai_compatible import CustomOpenAiCompatibleProvider
from app.ai.providers.gemini import GeminiProvider
from app.ai.providers.grok import GrokProvider
from app.ai.providers.ollama import OllamaProvider
from app.ai.providers.openai import OpenAiProvider
from app.ai.providers.sarvam import SarvamProvider
from app.ai.providers.vllm import VllmProvider
from app.ai.registry import ProviderRegistry
from app.core.security import permission_for_request
from app.db import Base
from app.models import AiProviderCredential, AiProviderModel, AiSettings
from sqlalchemy import create_engine, select
from sqlalchemy.orm import sessionmaker
from starlette.requests import Request


def _now() -> str:
    return datetime.now(UTC).isoformat()


@pytest.fixture
def session_factory():
    engine = create_engine("sqlite:///:memory:")
    Base.metadata.create_all(engine, tables=[AiProviderCredential.__table__, AiProviderModel.__table__, AiSettings.__table__])
    return sessionmaker(bind=engine, expire_on_commit=False)


class FakeDiscoveryProvider:
    name = "openai"
    default_model = "legacy-model"
    is_local = False
    max_concurrent = 1

    def __init__(self, ids: list[str]):
        self.ids = ids

    async def list_models(self):
        return [
            DiscoveredModel(
                provider_model_id=model_id,
                runtime_model_id=model_id,
                display_name=model_id,
                provider_name=self.name,
            )
            for model_id in self.ids
        ]


@pytest.mark.asyncio
async def test_registry_upserts_marks_missing_and_never_switches_active(session_factory):
    with session_factory() as db:
        credential = AiProviderCredential(
            provider_name="openai", label="default", default_model="legacy-model",
            enabled=True, tier="paid", is_default=True, is_fallback=False,
            is_local=False, cost_per_1k_input_usd=0, cost_per_1k_output_usd=0,
            created_at=_now(), updated_at=_now(),
        )
        db.add(credential)
        db.commit()
        old = AiProviderModel(
            provider_credential_id=credential.id, provider_name="openai",
            provider_model_id="legacy-model", runtime_model_id="legacy-model",
            is_available=None, is_enabled=True, is_selected=True,
            discovery_source="legacy", created_at=_now(), updated_at=_now(),
        )
        db.add(old)
        db.commit()

        first = await refresh_models(db, credential, provider=FakeDiscoveryProvider(["legacy-model", "new-model"]))
        assert (first.created, first.updated) == (1, 1)
        assert resolve_model_for_credential(db, credential).model_id == "legacy-model"

        second = await refresh_models(db, credential, provider=FakeDiscoveryProvider(["new-model"]))
        assert second.created == 0
        rows = db.scalars(select(AiProviderModel).order_by(AiProviderModel.provider_model_id)).all()
        assert len(rows) == 2
        assert next(row for row in rows if row.provider_model_id == "legacy-model").is_available is False
        assert resolve_model_for_credential(db, credential).model_id == "legacy-model"

        new = next(row for row in rows if row.provider_model_id == "new-model")
        select_model(db, credential, new)
        assert resolve_model_for_credential(db, credential).model_id == "new-model"
        assert credential.default_model == "new-model"


@pytest.mark.asyncio
async def test_config_loader_and_registry_stamp_selected_model_on_runtime_request(session_factory):
    with session_factory() as db:
        credential = AiProviderCredential(
            provider_name="openai", label="default", default_model="legacy-model",
            enabled=True, tier="paid", is_default=True, is_fallback=False,
            is_local=False, cost_per_1k_input_usd=0, cost_per_1k_output_usd=0,
            created_at=_now(), updated_at=_now(),
        )
        db.add(credential)
        db.commit()
        db.add(AiProviderModel(
            provider_credential_id=credential.id, provider_name="openai",
            provider_model_id="live-model", runtime_model_id="live-model",
            is_available=True, is_enabled=True, is_selected=True,
            discovery_source="live", created_at=_now(), updated_at=_now(),
        ))
        db.commit()

    loader = AiConfigLoader(session_factory, version_counter=_VersionCounter())
    config = next(item for item in loader.resolve_configs() if item.credential_id == credential.id)
    assert config.default_model == "live-model"

    captured: list[str | None] = []

    class RuntimeProvider(FakeDiscoveryProvider):
        async def generate(self, request: LlmRequest):
            captured.append(request.model)
            return LlmResponse(
                text="ok", provider=self.name, model=request.model or "",
                latency_ms=1, usage=LlmUsage(input_tokens=1, output_tokens=1, cost_usd=0),
            )

    registry = ProviderRegistry([config], default_provider=config.selection_key)
    runtime_provider = RuntimeProvider([])
    runtime_provider.default_model = config.default_model
    registry.register_instance(runtime_provider, selector=config.selection_key)
    await registry.generate_with_fallback(LlmRequest(system="s", user="u", request_id="r"))
    assert captured == ["live-model"]


@pytest.mark.asyncio
@pytest.mark.parametrize(
    ("provider_name", "provider_factory", "path", "payload", "expected_provider_id", "expected_runtime_id"),
    [
        ("openai", lambda cf: OpenAiProvider(api_key="x", client_factory=cf), "/v1/models", {"data": [{"id": "oa-new"}]}, "oa-new", "oa-new"),
        ("anthropic", lambda cf: AnthropicProvider(api_key="x", client_factory=cf), "/v1/models", {"data": [{"id": "claude-new", "display_name": "Claude New"}], "has_more": False}, "claude-new", "claude-new"),
        ("gemini", lambda cf: GeminiProvider(api_key="x", client_factory=cf), "/v1beta/models", {"models": [{"name": "models/gemini-new", "displayName": "Gemini New", "inputTokenLimit": 100, "outputTokenLimit": 20, "supportedGenerationMethods": ["generateContent"]}]}, "models/gemini-new", "gemini-new"),
        ("grok", lambda cf: GrokProvider(api_key="x", client_factory=cf), "/v1/models", {"data": [{"id": "grok-new"}]}, "grok-new", "grok-new"),
        ("sarvam", lambda cf: SarvamProvider(api_key="x", client_factory=cf), "/v1/models", {"data": [{"id": "sarvam-new"}]}, "sarvam-new", "sarvam-new"),
        ("ollama", lambda cf: OllamaProvider(client_factory=cf), "/api/tags", {"models": [{"name": "local-new", "details": {"family": "llama"}}]}, "local-new", "local-new"),
        ("vllm", lambda cf: VllmProvider(base_url="http://localhost:8000/v1", default_model="old", client_factory=cf), "/v1/models", {"data": [{"id": "vllm-new"}]}, "vllm-new", "vllm-new"),
        ("custom_openai", lambda cf: CustomOpenAiCompatibleProvider(base_url="http://localhost:8000/v1", default_model="old", client_factory=cf), "/v1/models", {"data": [{"id": "custom-new"}]}, "custom-new", "custom-new"),
    ],
)
async def test_every_provider_discovers_and_normalizes_models(
    provider_name, provider_factory, path, payload, expected_provider_id, expected_runtime_id,
):
    def handler(request: httpx.Request) -> httpx.Response:
        assert request.url.path == path
        return httpx.Response(200, json=payload)

    client = httpx.AsyncClient(transport=httpx.MockTransport(handler))
    provider = provider_factory(lambda: client)
    models = await provider.list_models()
    await client.aclose()
    assert len(models) == 1
    assert models[0].provider_name == provider_name
    assert models[0].provider_model_id == expected_provider_id
    assert models[0].runtime_model_id == expected_runtime_id


def test_custom_discovery_keeps_existing_ssrf_policy():
    with pytest.raises(Exception, match="http:// only allowed for localhost"):
        CustomOpenAiCompatibleProvider(base_url="http://169.254.169.254/v1", default_model="x")


@pytest.mark.asyncio
async def test_custom_unsupported_models_endpoint_is_controlled():
    client = httpx.AsyncClient(transport=httpx.MockTransport(lambda request: httpx.Response(404)))
    provider = CustomOpenAiCompatibleProvider(
        base_url="http://localhost:8000/v1",
        default_model="configured-model",
        client_factory=lambda: client,
    )
    with pytest.raises(ModelDiscoveryError) as caught:
        await provider.list_models()
    await client.aclose()
    assert caught.value.kind == "unsupported"


@pytest.mark.asyncio
async def test_refresh_failure_does_not_change_existing_registry(session_factory):
    class FailingProvider(FakeDiscoveryProvider):
        async def list_models(self):
            raise ModelDiscoveryError("timeout", "provider timed out")

    with session_factory() as db:
        credential = AiProviderCredential(
            provider_name="openai", label="default", default_model="working",
            enabled=True, tier="paid", is_default=True, is_fallback=False,
            is_local=False, cost_per_1k_input_usd=0, cost_per_1k_output_usd=0,
            created_at=_now(), updated_at=_now(),
        )
        db.add(credential)
        db.commit()
        existing = AiProviderModel(
            provider_credential_id=credential.id, provider_name="openai",
            provider_model_id="working", runtime_model_id="working",
            is_available=True, is_enabled=True, is_selected=True,
            discovery_source="live", created_at=_now(), updated_at=_now(),
        )
        db.add(existing)
        db.commit()
        with pytest.raises(ModelDiscoveryError):
            await refresh_models(db, credential, provider=FailingProvider([]))
        db.refresh(existing)
        assert existing.is_available is True
        assert existing.is_selected is True


@pytest.mark.asyncio
async def test_discovery_metadata_is_sanitized_before_persistence(session_factory):
    class MetadataProvider(FakeDiscoveryProvider):
        async def list_models(self):
            return [
                DiscoveredModel(
                    provider_model_id="safe-model",
                    runtime_model_id="safe-model",
                    provider_name="openai",
                    raw_metadata={
                        "owned_by": "vendor",
                        "api_key": "must-not-persist",
                        "nested": {"authorization_header": "must-not-persist"},
                    },
                )
            ]

    with session_factory() as db:
        credential = AiProviderCredential(
            provider_name="openai", label="default", default_model="legacy",
            enabled=True, tier="paid", is_default=True, is_fallback=False,
            is_local=False, cost_per_1k_input_usd=0, cost_per_1k_output_usd=0,
            created_at=_now(), updated_at=_now(),
        )
        db.add(credential)
        db.commit()
        await refresh_models(db, credential, provider=MetadataProvider([]))
        model = db.scalar(select(AiProviderModel).where(AiProviderModel.provider_model_id == "safe-model"))
        assert model is not None
        assert model.raw_metadata == {"owned_by": "vendor", "nested": {}}
        assert "must-not-persist" not in str(model.raw_metadata)


@pytest.mark.parametrize(
    ("method", "path", "expected"),
    [
        ("GET", "/api/v1/ai/credentials/4/models", "dashboard:read"),
        ("POST", "/api/v1/ai/credentials/4/models/refresh", "tenant:settings:update"),
        ("POST", "/api/v1/ai/credentials/4/models/9/select", "tenant:settings:update"),
        ("POST", "/api/v1/ai/credentials/4/models/9/test", "tenant:settings:update"),
    ],
)
def test_model_administration_uses_existing_settings_permission_boundary(method, path, expected):
    request = Request({"type": "http", "method": method, "path": path, "headers": []})
    assert permission_for_request(request) == expected


def test_daily_model_refresh_uses_existing_celery_beat():
    from app.workers.celery_app import celery_app

    entry = celery_app.conf.beat_schedule["ai-model-registry-daily"]
    assert entry["task"] == "ai_models.refresh_all"

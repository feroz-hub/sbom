"""SBO-99: registry evidence, credential preservation and bounded test costs."""

import httpx
import pytest
from app.ai.cost import BudgetCaps, BudgetGuard
from app.ai.model_registry import refresh_models
from app.ai.model_registry import test_model as verify_model
from app.ai.providers.base import DiscoveredModel
from app.ai.providers.openai import OpenAiProvider
from app.db import SessionLocal
from app.models import AiProviderCredential, AiProviderModel, AiUsageLog
from app.routers.ai_credentials import _model_response
from sqlalchemy import select

from tests.ai.test_openai_modern import response


def add_rows(db):
    stamp = "2026-10-30T00:00:00+00:00"
    credential = AiProviderCredential(
        provider_name="openai",
        label="synthetic",
        default_model="gpt-4o-mini",
        enabled=True,
        is_default=True,
        is_fallback=False,
        is_local=False,
        tier="paid",
        created_at=stamp,
        updated_at=stamp,
    )
    db.add(credential)
    db.flush()
    model = AiProviderModel(
        provider_credential_id=credential.id,
        provider_name="openai",
        provider_model_id="gpt-6-luna",
        runtime_model_id="gpt-6-luna",
        is_available=True,
        is_enabled=True,
        is_selected=False,
        discovery_source="live",
        last_discovered_at=stamp,
        created_at=stamp,
        updated_at=stamp,
    )
    db.add(model)
    db.commit()
    return credential, model


@pytest.mark.asyncio
@pytest.mark.parametrize(
    ("text", "status", "success", "kind"),
    [
        ('{"ok":true}', "completed", True, None),
        ('{"ok":false}', "completed", False, "invalid_json"),
        ("", "incomplete", False, "incomplete"),
    ],
)
async def test_model_verification_tracks_observed_stages_and_preserves_active_credentials(text, status, success, kind):
    async with httpx.AsyncClient(
        transport=httpx.MockTransport(lambda req: httpx.Response(200, json=response("gpt-6-luna", text, status=status)))
    ) as client:
        provider = OpenAiProvider(api_key="synthetic-only", client_factory=lambda: client)
        with SessionLocal() as db:
            credential, model = add_rows(db)
            ok, error = await verify_model(db, credential, model, provider=provider)
            assert ok is success
            assert credential.enabled is True and credential.default_model == "gpt-4o-mini"
            assert model.is_selected is False
            result = _model_response(model)
            assert result.discovered is True and result.accessible is True
            assert result.generation_verified is bool(text)
            assert result.workload_compatible is success
            assert result.error_kind == kind
            row = db.scalars(select(AiUsageLog).where(AiUsageLog.purpose == "model_test")).one()
            assert row.output_tokens == 125 and row.cost_usd > 0

            class Discovery:
                async def list_models(self):
                    return [
                        DiscoveredModel(
                            provider_name="openai",
                            provider_model_id="gpt-6-luna",
                            runtime_model_id="gpt-6-luna",
                            raw_metadata={"verification": {"accessible": False}},
                        )
                    ]

            await refresh_models(db, credential, provider=Discovery())
            assert _model_response(model).accessible is True  # Discovery cannot forge/erase test evidence.


@pytest.mark.asyncio
async def test_budget_blocks_model_verification_before_any_paid_request(monkeypatch):
    calls = []
    async with httpx.AsyncClient(
        transport=httpx.MockTransport(lambda req: calls.append(req) or httpx.Response(200, json=response("gpt-6-luna")))
    ) as client:
        provider = OpenAiProvider(api_key="synthetic-only", client_factory=lambda: client)
        monkeypatch.setattr(
            "app.ai.model_registry.build_budget_guard",
            lambda: BudgetGuard(BudgetCaps(per_request_usd=0, per_scan_usd=None, per_day_org_usd=None)),
        )
        with SessionLocal() as db:
            credential, model = add_rows(db)
            success, error = await verify_model(db, credential, model, provider=provider)
            assert not success and "budget" in error
            assert model.raw_metadata["verification"]["error_kind"] == "budget_exceeded"
            assert credential.enabled and credential.default_model == "gpt-4o-mini"
    assert calls == []


@pytest.mark.asyncio
async def test_mismatched_credential_cannot_invoke_model():
    with SessionLocal() as db:
        credential, model = add_rows(db)
        model.provider_credential_id = credential.id + 1
        with pytest.raises(ValueError, match="does not belong"):
            await verify_model(db, credential, model)


@pytest.mark.asyncio
@pytest.mark.usefixtures("temporary_cipher")
async def test_late_old_key_model_result_cannot_restore_rotated_verification():
    from app.ai.model_registry import CONFIGURATION_CHANGED, invalidate_model_verification
    from app.security.secrets import get_cipher

    with SessionLocal() as db:
        credential, model = add_rows(db)

        def rotate_during_call(request):
            with SessionLocal() as other:
                changed = other.get(AiProviderCredential, credential.id)
                changed.api_key_encrypted = get_cipher().encrypt("synthetic-rotated-key")
                invalidate_model_verification(other, changed)
                other.commit()
            return httpx.Response(200, json=response("gpt-6-luna"))

        async with httpx.AsyncClient(transport=httpx.MockTransport(rotate_during_call)) as client:
            provider = OpenAiProvider(api_key="synthetic-old-key", client_factory=lambda: client)
            ok, error = await verify_model(db, credential, model, provider=provider)
        assert not ok and error == CONFIGURATION_CHANGED
        assert "verification" not in (model.raw_metadata or {})
        assert model.last_test_success is None and model.last_verified_at is None
        assert credential.enabled


@pytest.fixture
def temporary_cipher(monkeypatch):
    from app.security.secrets import generate_master_key, reset_cipher

    monkeypatch.setenv("AI_CONFIG_ENCRYPTION_KEY", generate_master_key())
    reset_cipher()
    yield
    reset_cipher()


@pytest.mark.usefixtures("temporary_cipher")
@pytest.mark.parametrize(("status", "kind", "enabled"), [(401, "auth", False), (403, "permission", True)])
def test_saved_credential_permission_failure_preserves_working_settings(client, monkeypatch, status, kind, enabled):
    import importlib

    def build(config):
        transport = httpx.MockTransport(
            lambda req: httpx.Response(status, json={"error": {"message": "never expose this upstream payload"}})
        )
        return OpenAiProvider(
            api_key="synthetic-only",
            default_model=config.default_model,
            client_factory=lambda: httpx.AsyncClient(transport=transport),
        )

    router = importlib.import_module("app.routers.ai_credentials")
    monkeypatch.setattr(router, "build_provider", build)
    created = client.post(
        "/api/v1/ai/credentials",
        json={"provider_name": "openai", "api_key": "synthetic-only", "default_model": "gpt-4o-mini", "enabled": True},
    )
    assert created.status_code == 201, created.text
    credential_id = created.json()["id"]
    result = client.post(f"/api/v1/ai/credentials/{credential_id}/test")
    assert result.status_code == 200, result.text
    assert result.json()["error_kind"] == kind
    assert "never expose this upstream payload" not in result.text
    with SessionLocal() as db:
        credential = db.get(AiProviderCredential, credential_id)
        assert credential.enabled is enabled
        assert credential.default_model == "gpt-4o-mini"

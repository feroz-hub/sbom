"""Copilot integration through the shared effective config and budget path."""

from __future__ import annotations

import pytest
from app.ai.config_loader import reset_loader
from app.ai.providers.base import LlmRequest, LlmResponse, LlmUsage, ProviderInfo
from app.ai.registry import ProviderRegistry
from app.db import SessionLocal
from app.models import AiSettings, AiUsageLog


class _CopilotProvider:
    name = "fake"
    default_model = "fake-copilot"
    is_local = True
    max_concurrent = 1

    def __init__(self) -> None:
        self.requested_models: list[str | None] = []

    async def generate(self, request: LlmRequest) -> LlmResponse:
        self.requested_models.append(request.model)
        return LlmResponse(
            text="Use the prioritized findings and validate each remediation.",
            parsed=None,
            usage=LlmUsage(input_tokens=5, output_tokens=7, cost_usd=0.0),
            provider=self.name,
            model=self.default_model,
            latency_ms=1,
        )

    async def health_check(self) -> bool:
        return True

    def info(self) -> ProviderInfo:
        return ProviderInfo(
            name=self.name,
            available=True,
            default_model=self.default_model,
            supports_structured_output=True,
            is_local=True,
        )


@pytest.fixture
def _enabled_db_settings(client):
    db = SessionLocal()
    try:
        db.query(AiUsageLog).delete()
        db.query(AiSettings).delete()
        db.add(
            AiSettings(
                id=1,
                feature_enabled=True,
                kill_switch_active=False,
                budget_per_request_usd=1.0,
                budget_per_scan_usd=2.0,
                budget_daily_usd=3.0,
                updated_at="2026-09-06T00:00:00+00:00",
            )
        )
        db.commit()
    finally:
        db.close()
    reset_loader()


def test_copilot_ask_uses_effective_config_registry_and_durable_ledger(
    client,
    monkeypatch,
    _enabled_db_settings,
):
    provider = _CopilotProvider()
    registry = ProviderRegistry(configs=[], default_provider="fake")
    registry.register_instance(provider)
    monkeypatch.setattr("app.ai.copilot.get_registry", lambda db=None: registry)

    response = client.post("/api/ai/copilot/ask", json={"question": "What should we fix first?"})

    assert response.status_code == 200, response.text
    assert response.json()["provider"] == "fake"
    assert provider.requested_models == [provider.default_model]
    db = SessionLocal()
    try:
        rows = db.query(AiUsageLog).filter(AiUsageLog.purpose == "copilot_ask").all()
        assert len(rows) == 1
        assert rows[0].provider == "fake"
    finally:
        db.close()

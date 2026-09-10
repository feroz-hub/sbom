"""Telemetry endpoint smoke tests against the FastAPI app + temp SQLite DB.

Uses the session-level ``client`` fixture defined in ``tests/conftest.py``.
"""

from __future__ import annotations

from datetime import UTC, datetime

import pytest
from app.ai.config_loader import reset_loader
from app.ai.cost import BudgetCaps, BudgetGuard
from app.ai.providers.base import BudgetExceededError
from app.db import SessionLocal
from app.models import AiSettings, AiUsageLog


@pytest.fixture(autouse=True)
def _clean_ai_usage_log(client):
    """Wipe the ledger between tests so spend totals are deterministic.

    Depends on ``client`` so the FastAPI lifespan has run and
    ``Base.metadata.create_all`` has materialised the table.
    """
    db = SessionLocal()
    try:
        db.query(AiUsageLog).delete()
        db.commit()
    finally:
        db.close()


def _add_log(
    *,
    provider: str = "anthropic",
    model: str = "claude-sonnet-4-5",
    purpose: str = "remediation_prose",
    cost: float = 0.001,
    input_tokens: int = 100,
    output_tokens: int = 50,
    cache_hit: bool = False,
    when: str | None = None,
) -> None:
    db = SessionLocal()
    try:
        db.add(
            AiUsageLog(
                request_id="r-1",
                provider=provider,
                model=model,
                purpose=purpose,
                finding_cache_key=None,
                input_tokens=input_tokens,
                output_tokens=output_tokens,
                cost_usd=cost,
                latency_ms=200,
                cache_hit=cache_hit,
                error=None,
                created_at=when or datetime.now(UTC).isoformat(),
            )
        )
        db.commit()
    finally:
        db.close()


def test_get_ai_usage_empty(client):
    resp = client.get("/api/v1/ai/usage")
    assert resp.status_code == 200, resp.text
    body = resp.json()
    assert body["today"]["total_calls"] == 0
    assert body["today"]["total_cost_usd"] == 0.0
    assert body["today"]["cache_hit_ratio"] == 0.0
    assert body["spent_today_usd"] == 0.0
    assert body["budget_caps_usd"]["per_request_usd"] > 0


def test_get_ai_usage_aggregates(client):
    _add_log(provider="anthropic", purpose="remediation_prose", cost=0.01)
    _add_log(provider="openai", purpose="upgrade_command", cost=0.005)
    _add_log(provider="anthropic", purpose="remediation_prose", cost=0.0, cache_hit=True)

    body = client.get("/api/v1/ai/usage").json()
    assert body["today"]["total_calls"] == 3
    assert body["today"]["total_cache_hits"] == 1
    # 1 hit / 3 calls
    assert body["today"]["cache_hit_ratio"] == round(1 / 3, 4)
    assert body["today"]["total_cost_usd"] == round(0.01 + 0.005 + 0.0, 6)

    by_purpose = {b["label"]: b for b in body["by_purpose"]}
    assert by_purpose["remediation_prose"]["calls"] == 2
    assert by_purpose["upgrade_command"]["calls"] == 1

    by_provider = {b["label"]: b for b in body["by_provider"]}
    assert by_provider["anthropic"]["calls"] == 2
    assert by_provider["openai"]["calls"] == 1


def test_usage_caps_are_the_db_backed_runtime_caps(client, monkeypatch):
    monkeypatch.setenv("AI_BUDGET_PER_REQUEST_USD", "9.0")
    monkeypatch.setenv("AI_BUDGET_PER_SCAN_USD", "90.0")
    monkeypatch.setenv("AI_BUDGET_PER_DAY_ORG_USD", "900.0")
    db = SessionLocal()
    try:
        db.query(AiSettings).delete()
        db.add(
            AiSettings(
                id=1,
                feature_enabled=True,
                kill_switch_active=False,
                budget_per_request_usd=0.02,
                budget_per_scan_usd=0.30,
                budget_daily_usd=4.0,
                updated_at="2026-09-06T00:00:00+00:00",
            )
        )
        db.commit()
    finally:
        db.close()
    reset_loader()

    body = client.get("/api/v1/ai/usage").json()
    assert body["budget_caps_usd"] == {
        "per_request_usd": 0.02,
        "per_scan_usd": 0.30,
        "per_day_org_usd": 4.0,
    }


def test_analysis_config_matches_effective_db_kill_switch(client):
    db = SessionLocal()
    try:
        db.query(AiSettings).delete()
        db.add(
            AiSettings(
                id=1,
                feature_enabled=True,
                kill_switch_active=True,
                budget_per_request_usd=0.02,
                budget_per_scan_usd=0.30,
                budget_daily_usd=4.0,
                updated_at="2026-09-06T00:00:00+00:00",
            )
        )
        db.commit()
    finally:
        db.close()
    reset_loader()

    body = client.get("/api/analysis/config").json()
    assert body["ai_fixes_enabled"] is False
    assert body["ai_settings_source"] == "db"


def test_analysis_config_fails_closed_when_effective_config_is_unavailable(client, monkeypatch):
    from app.ai import config_loader, runtime_config

    def unavailable():
        raise RuntimeError("synthetic configuration failure")

    monkeypatch.setattr(runtime_config, "get_effective_ai_config", unavailable)
    monkeypatch.setattr(config_loader, "get_loader", unavailable)

    body = client.get("/api/analysis/config").json()
    assert body["ai_fixes_enabled"] is False
    assert body["ai_settings_source"] == "unavailable"
    assert body["ai_default_provider"] == ""


def test_daily_budget_reconciles_spend_written_by_another_session(client):
    _add_log(cost=0.009)
    guard = BudgetGuard(
        BudgetCaps(per_request_usd=1.0, per_scan_usd=1.0, per_day_org_usd=0.01),
        db_session_factory=SessionLocal,
        recheck_seconds=0.0,
    )

    with pytest.raises(BudgetExceededError) as exc_info:
        guard.check_request(estimated_usd=0.002)
    assert exc_info.value.scope == "per_day_org"


def test_list_providers_endpoint(client):
    resp = client.get("/api/v1/ai/providers")
    assert resp.status_code == 200
    payload = resp.json()
    # In test mode no API keys configured — at least one provider is reported,
    # and they all have a name + default_model.
    assert isinstance(payload, list)
    for entry in payload:
        assert "name" in entry
        assert "default_model" in entry
        assert "available" in entry


def test_list_pricing_endpoint(client):
    resp = client.get("/api/v1/ai/pricing")
    assert resp.status_code == 200
    payload = resp.json()
    names = {(p["provider"], p["model"]) for p in payload}
    # Spot check: claude-sonnet-4-5 + gpt-4o-mini should both be present.
    assert ("anthropic", "claude-sonnet-4-5") in names
    assert ("openai", "gpt-4o-mini") in names


def test_reset_registry_endpoint(client):
    resp = client.post("/api/v1/ai/registry/reset")
    assert resp.status_code == 204

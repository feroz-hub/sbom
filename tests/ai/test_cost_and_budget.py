"""Cost-table, token-counter, and BudgetGuard tests."""

from __future__ import annotations

import pytest
from app.ai.cost import (
    BudgetCaps,
    BudgetGuard,
    estimate_cost_usd,
    estimate_tokens,
)
from app.ai.providers.base import BudgetExceededError

# ============================================================ pricing


def test_estimate_cost_known_model():
    # claude-sonnet-4-5: $0.003/1k in, $0.015/1k out
    cost = estimate_cost_usd(
        provider="anthropic",
        model="claude-sonnet-4-5",
        input_tokens=2000,
        output_tokens=500,
    )
    assert cost == round(2.0 * 0.003 + 0.5 * 0.015, 6)


def test_estimate_cost_local_provider_is_zero():
    cost = estimate_cost_usd(
        provider="ollama",
        model="llama3.3:70b",
        input_tokens=10_000,
        output_tokens=10_000,
        is_local=True,
    )
    assert cost == 0.0


def test_estimate_cost_unknown_model_logs_and_returns_zero(caplog):
    with caplog.at_level("WARNING"):
        cost = estimate_cost_usd(
            provider="anthropic",
            model="claude-some-future-thing",
            input_tokens=100,
            output_tokens=50,
        )
    assert cost == 0.0
    assert any("unknown_model" in m for m in caplog.messages)


def test_estimate_tokens_heuristic():
    assert estimate_tokens("") == 0
    # 12 chars / 4 = 3 tokens
    assert estimate_tokens("abcdefghijkl") == 3
    # ceiling: 13 chars / 4 → 4
    assert estimate_tokens("abcdefghijklm") == 4


# ============================================================ BudgetGuard


def test_budget_guard_per_request_cap():
    guard = BudgetGuard(BudgetCaps(per_request_usd=0.05, per_scan_usd=None, per_day_org_usd=None))
    guard.check_request(estimated_usd=0.04)  # under cap — ok
    with pytest.raises(BudgetExceededError) as excinfo:
        guard.check_request(estimated_usd=0.06)
    assert excinfo.value.scope == "per_request"
    assert excinfo.value.cap_usd == 0.05


def test_budget_guard_per_scan_accumulates():
    guard = BudgetGuard(BudgetCaps(per_request_usd=10.0, per_scan_usd=0.10, per_day_org_usd=None))
    # First two calls fit.
    guard.check_request(estimated_usd=0.04, scan_id=42)
    guard.record(actual_usd=0.04, scan_id=42)
    guard.check_request(estimated_usd=0.04, scan_id=42)
    guard.record(actual_usd=0.04, scan_id=42)
    # 0.08 spent + 0.05 estimated = 0.13 > 0.10 → blocked.
    with pytest.raises(BudgetExceededError) as excinfo:
        guard.check_request(estimated_usd=0.05, scan_id=42)
    assert excinfo.value.scope == "per_scan"


def test_budget_guard_per_day_cap():
    guard = BudgetGuard(BudgetCaps(per_request_usd=10.0, per_scan_usd=None, per_day_org_usd=0.20))
    guard.check_request(estimated_usd=0.10)
    guard.record(actual_usd=0.10)
    guard.check_request(estimated_usd=0.05)
    guard.record(actual_usd=0.05)
    with pytest.raises(BudgetExceededError) as excinfo:
        guard.check_request(estimated_usd=0.10)
    assert excinfo.value.scope == "per_day_org"
    assert excinfo.value.cap_usd == 0.20


def test_budget_guard_negative_estimate_rejected():
    guard = BudgetGuard(BudgetCaps())
    with pytest.raises(ValueError):
        guard.check_request(estimated_usd=-0.01)


def test_budget_guard_none_caps_disable_levels():
    guard = BudgetGuard(BudgetCaps(per_request_usd=None, per_scan_usd=None, per_day_org_usd=None))
    # Even an absurd cost passes when every cap is None.
    guard.check_request(estimated_usd=999_999.0, scan_id=1)


def test_budget_guard_reset_clears_in_memory_state():
    guard = BudgetGuard(BudgetCaps(per_request_usd=10.0, per_scan_usd=0.10, per_day_org_usd=None))
    guard.record(actual_usd=0.09, scan_id=7)
    # Already at 0.09; +0.05 = 0.14 → would exceed.
    with pytest.raises(BudgetExceededError):
        guard.check_request(estimated_usd=0.05, scan_id=7)
    guard.reset()
    # After reset, the same call passes.
    guard.check_request(estimated_usd=0.05, scan_id=7)

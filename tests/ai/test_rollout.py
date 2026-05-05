"""Rollout-gate tests — kill switch, master flag, canary sampling."""

from __future__ import annotations

import pytest
from app.ai.rollout import _canary_bucket, evaluate_access
from app.settings import reset_settings


@pytest.fixture
def _env(monkeypatch):
    """Per-test env helper that always resets the settings singleton."""

    def _set(**kv: str) -> None:
        for k, v in kv.items():
            monkeypatch.setenv(k, v)
        reset_settings()

    yield _set
    reset_settings()


# ============================================================ Layer 1 — kill switch


def test_kill_switch_overrides_master_flag(_env):
    _env(
        AI_FIXES_KILL_SWITCH="true",
        AI_FIXES_ENABLED="true",
        AI_CANARY_PERCENTAGE="100",
    )
    decision = evaluate_access(rollout_key="run:1")
    assert decision.allowed is False
    assert decision.reason == "kill_switch"
    assert decision.http_status == 409


def test_kill_switch_overrides_canary(_env):
    _env(
        AI_FIXES_KILL_SWITCH="true",
        AI_FIXES_ENABLED="true",
        AI_CANARY_PERCENTAGE="0",  # canary would also block
    )
    decision = evaluate_access(rollout_key="run:1")
    # Kill-switch wins: reason should reflect operator pause, not canary.
    assert decision.reason == "kill_switch"


# ============================================================ Layer 2 — master flag


def test_master_flag_off_returns_not_enabled(_env):
    _env(
        AI_FIXES_KILL_SWITCH="false",
        AI_FIXES_ENABLED="false",
        AI_CANARY_PERCENTAGE="100",
    )
    decision = evaluate_access(rollout_key="run:1")
    assert decision.allowed is False
    assert decision.reason == "not_enabled"


# ============================================================ Layer 3 — canary


def test_canary_zero_blocks(_env):
    _env(
        AI_FIXES_KILL_SWITCH="false",
        AI_FIXES_ENABLED="true",
        AI_CANARY_PERCENTAGE="0",
    )
    decision = evaluate_access(rollout_key="run:1")
    assert decision.allowed is False
    assert decision.reason == "canary_excluded"


def test_canary_full_allows(_env):
    _env(
        AI_FIXES_KILL_SWITCH="false",
        AI_FIXES_ENABLED="true",
        AI_CANARY_PERCENTAGE="100",
    )
    decision = evaluate_access(rollout_key="run:42")
    assert decision.allowed is True
    assert decision.reason == "ok"


def test_canary_no_key_falls_back_to_allowed(_env):
    """Admin tools without a stable key still pass once master flag is on."""
    _env(
        AI_FIXES_KILL_SWITCH="false",
        AI_FIXES_ENABLED="true",
        AI_CANARY_PERCENTAGE="50",
    )
    decision = evaluate_access(rollout_key=None)
    assert decision.allowed is True


def test_canary_deterministic_per_key(_env):
    _env(
        AI_FIXES_KILL_SWITCH="false",
        AI_FIXES_ENABLED="true",
        AI_CANARY_PERCENTAGE="50",
    )
    decisions = {evaluate_access(rollout_key="run:777").allowed for _ in range(10)}
    assert len(decisions) == 1


def test_canary_50pct_distribution_within_tolerance(_env):
    _env(
        AI_FIXES_KILL_SWITCH="false",
        AI_FIXES_ENABLED="true",
        AI_CANARY_PERCENTAGE="50",
    )
    allowed = sum(
        1 for i in range(1000) if evaluate_access(rollout_key=f"run:{i}").allowed
    )
    # 50% ± 5% on 1000 samples — very wide bound, but catches a stuck-at-0/100 bug.
    assert 450 <= allowed <= 550


def test_canary_ramp_is_additive(_env):
    """Bumping percentage 10 → 50 keeps every key from the 10% cohort."""
    keys = [f"k:{i}" for i in range(500)]

    _env(
        AI_FIXES_KILL_SWITCH="false",
        AI_FIXES_ENABLED="true",
        AI_CANARY_PERCENTAGE="10",
    )
    in_at_10 = {k for k in keys if evaluate_access(rollout_key=k).allowed}

    _env(
        AI_FIXES_KILL_SWITCH="false",
        AI_FIXES_ENABLED="true",
        AI_CANARY_PERCENTAGE="50",
    )
    in_at_50 = {k for k in keys if evaluate_access(rollout_key=k).allowed}

    # Every key allowed at 10% must still be allowed at 50%.
    assert in_at_10 <= in_at_50
    assert len(in_at_50) > len(in_at_10)


def test_canary_bucket_is_zero_to_99(_env):
    buckets = [_canary_bucket(f"k:{i}") for i in range(200)]
    assert all(0 <= b < 100 for b in buckets)
    # High cardinality — sanity check the hash isn't degenerate.
    assert len(set(buckets)) > 50


def test_canary_bucket_empty_key_is_zero():
    assert _canary_bucket("") == 0


# ============================================================ Router integration


def test_router_kill_switch_returns_409(client, _env):
    _env(AI_FIXES_KILL_SWITCH="true", AI_FIXES_ENABLED="true", AI_CANARY_PERCENTAGE="100")
    resp = client.post("/api/v1/runs/1/ai-fixes")
    assert resp.status_code == 409
    body = resp.json()["detail"]
    assert body["error_code"] == "AI_FIXES_KILL_SWITCH"


def test_router_canary_excluded_returns_409(client, _env):
    _env(AI_FIXES_KILL_SWITCH="false", AI_FIXES_ENABLED="true", AI_CANARY_PERCENTAGE="0")
    resp = client.post("/api/v1/runs/1/ai-fixes")
    assert resp.status_code == 409
    assert resp.json()["detail"]["error_code"] == "AI_FIXES_CANARY_EXCLUDED"


def test_router_master_flag_off_returns_409(client, _env):
    _env(AI_FIXES_KILL_SWITCH="false", AI_FIXES_ENABLED="false", AI_CANARY_PERCENTAGE="100")
    resp = client.post("/api/v1/runs/1/ai-fixes")
    assert resp.status_code == 409
    assert resp.json()["detail"]["error_code"] == "AI_FIXES_DISABLED"

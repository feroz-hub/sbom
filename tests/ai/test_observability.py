"""Telemetry registry, Prometheus rendering, structured logger tests."""

from __future__ import annotations

import logging

import pytest
from app.ai.observability import (
    AiTelemetry,
    ai_telemetry,
    hash_response,
    log_ai_call,
    record_call,
    update_budget_remaining,
    update_cache_hit_ratio,
)


@pytest.fixture(autouse=True)
def _reset():
    ai_telemetry.reset()
    yield
    ai_telemetry.reset()


# ============================================================ AiTelemetry primitives


def test_counter_inc_accumulates():
    t = AiTelemetry()
    t.inc("ai_request_total", {"provider": "anthropic", "purpose": "fix_bundle", "outcome": "ok"})
    t.inc("ai_request_total", {"provider": "anthropic", "purpose": "fix_bundle", "outcome": "ok"})
    snap = t.snapshot()
    series = snap["counters"]["ai_request_total"]
    assert len(series) == 1
    assert series[0]["value"] == 2.0


def test_counter_separate_label_combinations():
    t = AiTelemetry()
    t.inc("ai_request_total", {"provider": "anthropic", "purpose": "fix_bundle", "outcome": "ok"})
    t.inc("ai_request_total", {"provider": "openai", "purpose": "fix_bundle", "outcome": "ok"})
    series = t.snapshot()["counters"]["ai_request_total"]
    assert len(series) == 2


def test_counter_negative_value_ignored():
    t = AiTelemetry()
    t.inc("metric", value=-5.0)
    assert "metric" not in t.snapshot()["counters"]


def test_histogram_observe_buckets():
    t = AiTelemetry()
    t.observe("ai_request_latency_seconds", 0.04, {"provider": "anthropic"})
    t.observe("ai_request_latency_seconds", 1.5, {"provider": "anthropic"})
    t.observe("ai_request_latency_seconds", 35.0, {"provider": "anthropic"})
    series = t.snapshot()["histograms"]["ai_request_latency_seconds"]
    assert len(series) == 1
    assert series[0]["count"] == 3
    assert abs(series[0]["sum"] - (0.04 + 1.5 + 35.0)) < 1e-6
    # Last bucket (+Inf) always has the full count.
    assert series[0]["buckets"][-1]["count"] == 3


def test_gauge_set_replaces():
    t = AiTelemetry()
    t.set_gauge("ai_budget_remaining_daily_usd", 50.0)
    t.set_gauge("ai_budget_remaining_daily_usd", 49.95)
    series = t.snapshot()["gauges"]["ai_budget_remaining_daily_usd"]
    assert series[0]["value"] == 49.95


def test_render_prometheus_includes_types_and_buckets():
    t = AiTelemetry()
    t.inc("ai_request_total", {"provider": "anthropic", "purpose": "fix_bundle", "outcome": "ok"})
    t.observe("ai_request_latency_seconds", 0.5, {"provider": "anthropic"})
    t.set_gauge("ai_budget_remaining_daily_usd", 49.5)
    out = t.render_prometheus()
    assert "# TYPE ai_request_total counter" in out
    assert "# TYPE ai_request_latency_seconds histogram" in out
    assert "# TYPE ai_budget_remaining_daily_usd gauge" in out
    # Counter line.
    assert 'ai_request_total{outcome="ok",provider="anthropic",purpose="fix_bundle"} 1.0' in out
    # Histogram bucket + sum + count lines.
    assert "ai_request_latency_seconds_bucket{provider=\"anthropic\",le=\"0.5\"} 1" in out
    assert "ai_request_latency_seconds_sum{provider=\"anthropic\"} 0.5" in out
    assert "ai_request_latency_seconds_count{provider=\"anthropic\"} 1" in out


def test_render_prometheus_escapes_label_values():
    t = AiTelemetry()
    t.inc("metric", {"provider": 'evil"break\nlf'})
    out = t.render_prometheus()
    assert r'evil\"break\nlf' in out


# ============================================================ High-level recorders


def test_record_call_emits_counter_histogram_cost():
    record_call(
        provider="anthropic",
        model="claude-sonnet-4-5",
        purpose="fix_bundle",
        outcome="ok",
        latency_seconds=1.2,
        cost_usd=0.0042,
        cache_hit=False,
    )
    snap = ai_telemetry.snapshot()
    assert snap["counters"]["ai_request_total"][0]["value"] == 1.0
    assert snap["histograms"]["ai_request_latency_seconds"][0]["count"] == 1
    cost_series = snap["counters"]["ai_cost_usd_total"]
    assert cost_series[0]["value"] == 0.0042


def test_record_call_cache_hit_emits_extra_label():
    record_call(
        provider="anthropic",
        model="claude-sonnet-4-5",
        purpose="fix_bundle",
        outcome="cache_hit",
        latency_seconds=0.0,
        cost_usd=0.0,
        cache_hit=True,
    )
    series = ai_telemetry.snapshot()["counters"]["ai_request_total"]
    outcomes = {s["labels"].get("outcome") for s in series}
    assert "cache_hit" in outcomes


def test_update_cache_hit_ratio_handles_zero_total():
    update_cache_hit_ratio(hits=0, total=0)
    assert ai_telemetry.snapshot()["gauges"]["ai_cache_hit_ratio"][0]["value"] == 0.0


def test_update_cache_hit_ratio_publishes_ratio():
    update_cache_hit_ratio(hits=8, total=10)
    assert ai_telemetry.snapshot()["gauges"]["ai_cache_hit_ratio"][0]["value"] == 0.8


def test_update_budget_remaining_clamps_negative():
    update_budget_remaining(remaining_usd=-5.0)
    assert ai_telemetry.snapshot()["gauges"]["ai_budget_remaining_daily_usd"][0]["value"] == 0.0


def test_update_budget_remaining_none_is_noop():
    update_budget_remaining(remaining_usd=None)
    assert "ai_budget_remaining_daily_usd" not in ai_telemetry.snapshot()["gauges"]


# ============================================================ Structured logger


def test_log_ai_call_never_logs_response_body(caplog):
    secret_body = "highly sensitive vulnerability summary that must not leak"
    with caplog.at_level(logging.INFO, logger="sbom.ai.audit"):
        log_ai_call(
            request_id="r-1",
            provider="anthropic",
            model="claude-sonnet-4-5",
            purpose="fix_bundle",
            finding_cache_key="abc",
            input_tokens=10,
            output_tokens=20,
            cost_usd=0.001,
            latency_ms=1234,
            cache_hit=False,
            outcome="ok",
            response_text=secret_body,
        )
    # The raw text must not appear anywhere in the captured log records
    # (message, args, or extra dict serialisations).
    serialized = "\n".join(
        [r.getMessage() + " " + str(r.__dict__) for r in caplog.records]
    )
    assert secret_body not in serialized
    # The hash of the response must be present.
    assert hash_response(secret_body) in serialized


def test_log_ai_call_truncates_error():
    long_err = "x" * 1000
    log_ai_call(
        request_id="r-2",
        provider="anthropic",
        model="m",
        purpose="fix_bundle",
        finding_cache_key=None,
        input_tokens=0,
        output_tokens=0,
        cost_usd=0.0,
        latency_ms=0,
        cache_hit=False,
        outcome="provider_error",
        response_text=None,
        error=long_err,
    )
    # No assertion on capture — we're confirming truncation path doesn't raise.
    # Hash of empty response is empty string.
    assert hash_response(None) == ""
    assert hash_response("") == ""


def test_hash_response_deterministic():
    assert hash_response("hello") == hash_response("hello")
    assert hash_response("hello") != hash_response("hello!")

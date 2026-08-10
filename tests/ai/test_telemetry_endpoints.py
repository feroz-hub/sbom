"""Phase 5 telemetry endpoint smoke tests."""

from __future__ import annotations

from datetime import UTC, datetime, timedelta

import pytest
from app.ai.observability import ai_telemetry, record_call
from app.db import SessionLocal
from app.models import AiFixCache, AiUsageLog


@pytest.fixture(autouse=True)
def _wipe_state(client):
    """Wipe telemetry + ai_usage_log + ai_fix_cache between tests."""
    ai_telemetry.reset()
    db = SessionLocal()
    try:
        db.query(AiUsageLog).delete()
        db.query(AiFixCache).delete()
        db.commit()
    finally:
        db.close()
    yield
    ai_telemetry.reset()


def _add_log_row(*, when: datetime, cost: float = 0.001, cache_hit: bool = False) -> None:
    db = SessionLocal()
    try:
        db.add(
            AiUsageLog(
                request_id="r-1",
                provider="anthropic",
                model="claude-sonnet-4-5",
                purpose="fix_bundle",
                finding_cache_key="key-1",
                input_tokens=100,
                output_tokens=50,
                cost_usd=cost,
                latency_ms=200,
                cache_hit=cache_hit,
                error=None,
                created_at=when.isoformat(),
            )
        )
        db.commit()
    finally:
        db.close()


def _add_cache_row(*, key: str, cost: float, vuln_id: str = "CVE-1") -> None:
    db = SessionLocal()
    try:
        db.add(
            AiFixCache(
                cache_key=key,
                vuln_id=vuln_id,
                component_name="pkg",
                component_version="1.0.0",
                prompt_version="v1",
                schema_version=1,
                remediation_prose={"x": 1},
                upgrade_command={"x": 1},
                decision_recommendation={"x": 1},
                provider_used="anthropic",
                model_used="claude-sonnet-4-5",
                total_cost_usd=cost,
                generated_at=datetime.now(UTC).isoformat(),
                expires_at=(datetime.now(UTC) + timedelta(days=30)).isoformat(),
                last_accessed_at=datetime.now(UTC).isoformat(),
            )
        )
        db.commit()
    finally:
        db.close()


# ============================================================ /usage/trend


def test_trend_endpoint_groups_by_day(client):
    today = datetime.now(UTC)
    yesterday = today - timedelta(days=1)
    _add_log_row(when=today, cost=0.005)
    _add_log_row(when=today, cost=0.010, cache_hit=True)
    _add_log_row(when=yesterday, cost=0.020)
    resp = client.get("/api/v1/ai/usage/trend?days=7")
    assert resp.status_code == 200
    body = resp.json()
    assert body["days"] == 7
    by_day = {p["day"]: p for p in body["points"]}
    assert today.date().isoformat() in by_day
    assert by_day[today.date().isoformat()]["calls"] == 2
    assert by_day[today.date().isoformat()]["cost_usd"] == 0.015
    assert by_day[today.date().isoformat()]["cache_hits"] == 1


def test_trend_endpoint_validates_days_range(client):
    assert client.get("/api/v1/ai/usage/trend?days=0").status_code == 422
    assert client.get("/api/v1/ai/usage/trend?days=181").status_code == 422


# ============================================================ /usage/top-cached


def test_top_cached_returns_most_expensive_first(client):
    _add_cache_row(key="cheap", cost=0.001)
    _add_cache_row(key="medium", cost=0.012)
    _add_cache_row(key="expensive", cost=0.150)
    resp = client.get("/api/v1/ai/usage/top-cached?limit=10")
    assert resp.status_code == 200
    body = resp.json()
    assert [r["cache_key"] for r in body] == ["expensive", "medium", "cheap"]
    assert body[0]["total_cost_usd"] == 0.150


def test_top_cached_respects_limit(client):
    for i in range(5):
        _add_cache_row(key=f"k{i}", cost=float(i))
    resp = client.get("/api/v1/ai/usage/top-cached?limit=3")
    assert resp.status_code == 200
    assert len(resp.json()) == 3


def test_top_cached_validates_limit(client):
    assert client.get("/api/v1/ai/usage/top-cached?limit=0").status_code == 422
    assert client.get("/api/v1/ai/usage/top-cached?limit=101").status_code == 422


# ============================================================ /metrics + Prometheus


def test_metrics_json_round_trip(client):
    record_call(
        provider="anthropic",
        model="claude-sonnet-4-5",
        purpose="fix_bundle",
        outcome="ok",
        latency_seconds=0.42,
        cost_usd=0.0042,
        cache_hit=False,
    )
    resp = client.get("/api/v1/ai/metrics")
    assert resp.status_code == 200
    body = resp.json()
    assert "counters" in body
    assert "histograms" in body
    assert "gauges" in body
    assert body["counters"]["ai_request_total"][0]["value"] == 1.0


def test_metrics_prometheus_text_format(client):
    record_call(
        provider="anthropic",
        model="claude-sonnet-4-5",
        purpose="fix_bundle",
        outcome="ok",
        latency_seconds=0.5,
        cost_usd=0.001,
        cache_hit=False,
    )
    resp = client.get("/api/v1/ai/metrics/prometheus")
    assert resp.status_code == 200
    assert resp.headers["content-type"].startswith("text/plain")
    text = resp.text
    assert "# TYPE ai_request_total counter" in text
    assert "ai_request_latency_seconds_bucket" in text
    assert 'provider="anthropic"' in text

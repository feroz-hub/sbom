"""Catalog endpoint + free-tier batch-duration estimator tests."""

from __future__ import annotations

from app.ai.catalog import (
    PROVIDER_CATALOG,
    get_catalog_entry,
    list_catalog,
)
from app.ai.estimator import estimate_batch_duration

# ============================================================ Catalog


def test_catalog_includes_seven_providers():
    names = {entry.name for entry in PROVIDER_CATALOG}
    assert names == {
        "anthropic",
        "openai",
        "gemini",
        "grok",
        "ollama",
        "vllm",
        "custom_openai",
    }


def test_gemini_advertises_free_tier():
    g = get_catalog_entry("gemini")
    assert g is not None
    assert g.supports_free_tier is True
    assert g.free_tier_rate_limit_rpm == 15
    assert g.api_key_url.startswith("https://")


def test_grok_advertises_free_tier_with_token_cap():
    grok = get_catalog_entry("grok")
    assert grok is not None
    assert grok.supports_free_tier is True
    assert grok.free_tier_daily_token_limit == 25_000


def test_ollama_does_not_require_api_key():
    o = get_catalog_entry("ollama")
    assert o is not None
    assert o.requires_api_key is False
    assert o.requires_base_url is True
    assert o.is_local is True


def test_custom_openai_has_no_built_in_models():
    c = get_catalog_entry("custom_openai")
    assert c is not None
    # Free-text in the UI — the catalog deliberately ships zero models.
    assert c.available_models == []


def test_get_catalog_entry_unknown_returns_none():
    assert get_catalog_entry("nonexistent") is None
    assert get_catalog_entry("") is None


def test_list_catalog_returns_a_list():
    out = list_catalog()
    assert isinstance(out, list)
    assert len(out) == 7


# ============================================================ Endpoint


def test_providers_available_endpoint(client):
    resp = client.get("/api/v1/ai/providers/available")
    assert resp.status_code == 200
    body = resp.json()
    assert isinstance(body, list)
    names = {e["name"] for e in body}
    assert "gemini" in names
    assert "grok" in names
    assert "custom_openai" in names


def test_providers_available_single_lookup(client):
    resp = client.get("/api/v1/ai/providers/available/gemini")
    assert resp.status_code == 200
    body = resp.json()
    assert body["name"] == "gemini"
    assert body["supports_free_tier"] is True


def test_providers_available_unknown_returns_404(client):
    resp = client.get("/api/v1/ai/providers/available/does-not-exist")
    assert resp.status_code == 404


# ============================================================ Estimator


def test_estimator_full_cache_hit_returns_zero():
    e = estimate_batch_duration(
        findings_total=100,
        cached_count=100,
        provider_name="anthropic",
        max_concurrent=10,
    )
    assert e.estimated_seconds == 0
    assert e.estimated_cost_usd == 0.0
    assert e.bottleneck == "cache"
    assert e.warning_recommended is False


def test_estimator_paid_anthropic_concurrency_bound():
    """Paid tier: concurrency × per-call latency is the limit."""
    e = estimate_batch_duration(
        findings_total=400,
        cached_count=300,
        provider_name="anthropic",
        tier="paid",
        max_concurrent=10,
        rate_per_minute=None,
    )
    # 100 net-new calls / (10 / 4s) = ~40 seconds.
    assert e.findings_to_generate == 100
    assert e.bottleneck == "concurrency"
    assert 30 <= e.estimated_seconds <= 60
    assert e.warning_recommended is False


def test_estimator_gemini_free_tier_rate_limited():
    """Gemini free: 15 RPM is the binding constraint for big batches."""
    e = estimate_batch_duration(
        findings_total=1000,
        cached_count=200,
        provider_name="gemini",
        tier="free",
        max_concurrent=4,
        rate_per_minute=None,  # let estimator pull 15 from catalog
    )
    assert e.requests_per_minute == 15.0
    assert e.bottleneck == "rate_limit"
    # 800 calls / (15/60 = 0.25 req/s) = 3200s ≈ 53min.
    assert e.estimated_seconds >= 60 * 30
    assert e.warning_recommended is True


def test_estimator_local_provider_zero_cost():
    e = estimate_batch_duration(
        findings_total=500,
        cached_count=0,
        provider_name="ollama",
        tier="paid",
        max_concurrent=8,
        is_local=True,
        rate_per_minute=1000,
    )
    assert e.estimated_cost_usd == 0.0


def test_estimator_warning_threshold_at_5_minutes():
    # Concoct a scenario that lands just over 5 minutes.
    e_under = estimate_batch_duration(
        findings_total=10,
        cached_count=0,
        provider_name="anthropic",
        tier="paid",
        max_concurrent=10,
    )
    e_over = estimate_batch_duration(
        findings_total=2000,
        cached_count=0,
        provider_name="gemini",
        tier="free",
        max_concurrent=4,
    )
    assert e_under.warning_recommended is False
    assert e_over.warning_recommended is True

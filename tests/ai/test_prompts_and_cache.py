"""Prompt loader + cache key/TTL helper tests."""

from __future__ import annotations

import json
from datetime import UTC, datetime, timedelta

import pytest
from app.ai.cache import (
    compute_ttl,
    expires_at_iso,
    make_cache_key,
    read_cache,
    write_cache,
)
from app.ai.prompts import (
    PROMPT_VERSION,
    reload_prompts,
    system_prompt,
    user_prompt,
)
from app.ai.schemas import AiFixBundle
from app.db import SessionLocal

from tests.ai.fixtures import EX1_CRITICAL_KEV_WITH_FIX_BUNDLE

# ============================================================ Prompt loader


def test_system_prompt_contains_hard_rules():
    p = system_prompt()
    assert "Never invent" in p or "NEVER invent" in p
    assert "actively_exploited" in p
    assert "JSON" in p


def test_user_prompt_substitutes_grounding():
    schema = {"type": "object", "properties": {}}
    grounding = '{"cve_id":"CVE-X"}'
    rendered = user_prompt(grounding_json=grounding, schema=schema)
    assert grounding in rendered
    assert json.dumps(schema, separators=(",", ":"), sort_keys=True) in rendered


def test_user_prompt_handles_braces_in_grounding_json():
    # Real grounding JSON contains literal braces; str.format would break.
    schema = {"type": "object"}
    grounding = '{"cve_id":"CVE-1","nested":{"x":"{}"}}'
    rendered = user_prompt(grounding_json=grounding, schema=schema)
    assert grounding in rendered


def test_prompt_version_stable_for_phase_2():
    # Bumping is a deliberate cache invalidation. Tests pin it to v1.
    assert PROMPT_VERSION == "v1"


def test_reload_prompts_clears_cache():
    # Sanity: reload doesn't break — used by dev hot-reload paths.
    reload_prompts()
    assert "actively_exploited" in system_prompt()


# ============================================================ Cache key + TTL


def test_make_cache_key_deterministic_and_normalised():
    a = make_cache_key(vuln_id="CVE-2021-44832", component_name="log4j-core", component_version="2.16.0")
    b = make_cache_key(vuln_id=" CVE-2021-44832 ", component_name="LOG4J-CORE", component_version="2.16.0")
    c = make_cache_key(vuln_id="CVE-2021-44832", component_name="log4j-core", component_version="2.17.0")
    assert a == b
    assert a != c


def test_compute_ttl_kev_vs_default():
    assert compute_ttl(kev_listed=True) == timedelta(days=7)
    assert compute_ttl(kev_listed=False) == timedelta(days=30)
    assert compute_ttl(kev_listed=True, is_negative=True) == timedelta(hours=1)


def test_expires_at_in_future():
    iso = expires_at_iso(ttl=timedelta(days=1))
    parsed = datetime.fromisoformat(iso)
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=UTC)
    assert parsed > datetime.now(UTC) + timedelta(hours=23)


# ============================================================ Cache R/W round-trip


@pytest.fixture(autouse=True)
def _clean_cache(client):  # pragma: no cover — fixture
    from app.models import AiFixCache

    db = SessionLocal()
    try:
        db.query(AiFixCache).delete()
        db.commit()
    finally:
        db.close()


def test_cache_round_trip_returns_bundle(client):
    bundle = AiFixBundle.model_validate(EX1_CRITICAL_KEV_WITH_FIX_BUNDLE)
    key = make_cache_key(vuln_id="CVE-2021-44832", component_name="log4j-core", component_version="2.16.0")

    db = SessionLocal()
    try:
        write_cache(
            db,
            cache_key=key,
            vuln_id="CVE-2021-44832",
            component_name="log4j-core",
            component_version="2.16.0",
            bundle=bundle,
            provider_used="anthropic",
            model_used="claude-sonnet-4-5",
            total_cost_usd=0.0042,
            kev_listed=True,
        )
        hit = read_cache(db, cache_key=key)
    finally:
        db.close()

    assert hit is not None
    assert hit.metadata.cache_hit is True
    assert hit.metadata.provider_used == "anthropic"
    assert hit.bundle.upgrade_command.target_version == "2.17.1"


def test_cache_miss_when_expired(client, monkeypatch):
    bundle = AiFixBundle.model_validate(EX1_CRITICAL_KEV_WITH_FIX_BUNDLE)
    key = make_cache_key(vuln_id="CVE-9999-1", component_name="x", component_version="1")

    # Force the row's expiry into the past by patching now() in the cache module.
    db = SessionLocal()
    try:
        write_cache(
            db,
            cache_key=key,
            vuln_id="CVE-9999-1",
            component_name="x",
            component_version="1",
            bundle=bundle,
            provider_used="anthropic",
            model_used="claude-sonnet-4-5",
            total_cost_usd=0.0,
            kev_listed=False,
        )
        # Manually set expires_at into the past.
        from app.models import AiFixCache

        row = db.query(AiFixCache).filter_by(cache_key=key).one()
        row.expires_at = (datetime.now(UTC) - timedelta(minutes=1)).isoformat()
        db.commit()
        hit = read_cache(db, cache_key=key)
    finally:
        db.close()

    assert hit is None


def test_cache_upsert_overwrites_existing(client):
    bundle = AiFixBundle.model_validate(EX1_CRITICAL_KEV_WITH_FIX_BUNDLE)
    key = make_cache_key(vuln_id="CVE-9999-2", component_name="y", component_version="2")

    db = SessionLocal()
    try:
        write_cache(
            db,
            cache_key=key,
            vuln_id="CVE-9999-2",
            component_name="y",
            component_version="2",
            bundle=bundle,
            provider_used="openai",
            model_used="gpt-4o-mini",
            total_cost_usd=0.001,
            kev_listed=False,
        )
        # Second write same key — must upsert, not duplicate-PK error.
        write_cache(
            db,
            cache_key=key,
            vuln_id="CVE-9999-2",
            component_name="y",
            component_version="2",
            bundle=bundle,
            provider_used="anthropic",
            model_used="claude-sonnet-4-5",
            total_cost_usd=0.005,
            kev_listed=True,
        )
        hit = read_cache(db, cache_key=key)
    finally:
        db.close()

    assert hit is not None
    assert hit.metadata.provider_used == "anthropic"
    assert hit.metadata.total_cost_usd == 0.005

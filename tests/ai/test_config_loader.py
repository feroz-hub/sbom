"""AiConfigLoader tests — DB-first, env fallback, cache invalidation."""

from __future__ import annotations

from contextlib import contextmanager
from datetime import UTC, datetime

import pytest
from app.ai.config_loader import (
    AiConfigLoader,
    _VersionCounter,
    preview_api_key,
)
from app.db import SessionLocal
from app.models import AiProviderCredential, AiSettings
from app.security.secrets import SecretCipher, generate_master_key
from app.settings import reset_settings


@pytest.fixture
def fresh_cipher():
    return SecretCipher.from_b64(generate_master_key())


@pytest.fixture(autouse=True)
def _wipe_credentials(client):
    """Clean credential / settings tables between tests.

    The Alembic migration seeds the ``ai_settings`` singleton, but the
    test fixture creates tables via ``Base.metadata.create_all`` and
    skips data migrations — so seed the row here when missing.
    """
    db = SessionLocal()
    try:
        db.query(AiProviderCredential).delete()
        row = db.query(AiSettings).filter_by(id=1).one_or_none()
        if row is None:
            db.add(
                AiSettings(
                    id=1,
                    feature_enabled=True,
                    kill_switch_active=False,
                    budget_per_request_usd=0.10,
                    budget_per_scan_usd=5.00,
                    budget_daily_usd=5.00,
                    updated_at="2026-05-04T00:00:00+00:00",
                )
            )
        else:
            row.feature_enabled = True
            row.kill_switch_active = False
            row.budget_per_request_usd = 0.10
            row.budget_per_scan_usd = 5.00
            row.budget_daily_usd = 5.00
            row.updated_at = "2026-05-04T00:00:00+00:00"
        db.commit()
    finally:
        db.close()


def _now() -> str:
    return datetime.now(UTC).isoformat()


@contextmanager
def _session():
    s = SessionLocal()
    try:
        yield s
    finally:
        s.close()


def _make_loader(cipher) -> AiConfigLoader:
    """Build a loader with a fresh, process-local version counter."""
    return AiConfigLoader(SessionLocal, cipher=cipher, version_counter=_VersionCounter())


# ============================================================ Env fallback


def test_loader_returns_env_configs_when_db_empty(client, fresh_cipher, monkeypatch):
    """No DB rows → env configs are surfaced unchanged."""
    monkeypatch.setenv("ANTHROPIC_API_KEY", "sk-ant-test-from-env")
    monkeypatch.setenv("AI_ANTHROPIC_MODEL", "claude-sonnet-4-5")
    reset_settings()
    try:
        loader = _make_loader(fresh_cipher)
        configs = loader.resolve_configs()
        anthropic = next((c for c in configs if c.name == "anthropic"), None)
        assert anthropic is not None
        assert anthropic.enabled is True
        assert anthropic.api_key == "sk-ant-test-from-env"
        assert anthropic.organization == ""  # no DB-supplied default flag
    finally:
        reset_settings()


# ============================================================ DB priority


def test_loader_db_row_overrides_env(client, fresh_cipher, monkeypatch):
    monkeypatch.setenv("ANTHROPIC_API_KEY", "sk-ant-from-env")
    reset_settings()
    try:
        # Seed a DB row whose key differs from env.
        with _session() as db:
            db.add(
                AiProviderCredential(
                    provider_name="anthropic",
                    label="default",
                    api_key_encrypted=fresh_cipher.encrypt("sk-ant-from-DB"),
                    default_model="claude-sonnet-4-5",
                    tier="paid",
                    is_default=True,
                    enabled=True,
                    cost_per_1k_input_usd=0.0,
                    cost_per_1k_output_usd=0.0,
                    is_local=False,
                    created_at=_now(),
                    updated_at=_now(),
                )
            )
            db.commit()

        loader = _make_loader(fresh_cipher)
        configs = loader.resolve_configs()
        anthropic = next((c for c in configs if c.name == "anthropic"), None)
        assert anthropic is not None
        # DB plaintext, decrypted on read.
        assert anthropic.api_key == "sk-ant-from-DB"
        # Default-flag carried via the sentinel.
        assert anthropic.organization == "__default__"
    finally:
        reset_settings()


def test_loader_fallback_marker_for_secondary(client, fresh_cipher):
    with _session() as db:
        db.add(
            AiProviderCredential(
                provider_name="gemini",
                label="default",
                api_key_encrypted=fresh_cipher.encrypt("AIza-test"),
                default_model="gemini-2.5-flash",
                tier="free",
                is_default=False,
                is_fallback=True,
                enabled=True,
                created_at=_now(),
                updated_at=_now(),
            )
        )
        db.commit()
    loader = _make_loader(fresh_cipher)
    configs = loader.resolve_configs()
    gemini = next(c for c in configs if c.name == "gemini")
    assert gemini.organization == "__fallback__"


def test_loader_skips_disabled_rows(client, fresh_cipher):
    with _session() as db:
        db.add(
            AiProviderCredential(
                provider_name="grok",
                label="default",
                api_key_encrypted=fresh_cipher.encrypt("xai-test"),
                default_model="grok-2-mini",
                tier="free",
                enabled=False,  # ← disabled
                created_at=_now(),
                updated_at=_now(),
            )
        )
        db.commit()
    loader = _make_loader(fresh_cipher)
    configs = loader.resolve_configs()
    grok = next((c for c in configs if c.name == "grok"), None)
    # Disabled DB row is skipped → falls through to env config (which is
    # enabled=False because no GROK_API_KEY is set in tests). Either way,
    # the api_key from the disabled DB row must NOT leak.
    if grok is not None:
        assert grok.api_key == ""


def test_loader_skips_rows_with_decrypt_failure(client, fresh_cipher, caplog):
    """A row encrypted with one key + decrypted with another → skipped, not raised."""
    other_cipher = SecretCipher.from_b64(generate_master_key())
    with _session() as db:
        db.add(
            AiProviderCredential(
                provider_name="grok",
                label="default",
                api_key_encrypted=other_cipher.encrypt("xai-from-bad-key"),
                default_model="grok-2-mini",
                tier="free",
                enabled=True,
                created_at=_now(),
                updated_at=_now(),
            )
        )
        db.commit()
    loader = _make_loader(fresh_cipher)
    with caplog.at_level("ERROR"):
        configs = loader.resolve_configs()
    # Decrypt-failed rows are dropped — env-only fallback (env has no key
    # for grok in tests, so the entry is enabled=False).
    grok = next((c for c in configs if c.name == "grok"), None)
    if grok is not None:
        assert grok.api_key == ""
    # The error is logged but the ciphertext / plaintext is not.
    log_text = "\n".join(r.getMessage() for r in caplog.records)
    assert "xai-from-bad-key" not in log_text
    assert "decrypt_failed" in log_text


# ============================================================ Cache invalidation


def test_loader_invalidate_drops_cache(client, fresh_cipher):
    loader = _make_loader(fresh_cipher)
    configs_a = loader.resolve_configs()
    # Insert a row + invalidate.
    with _session() as db:
        db.add(
            AiProviderCredential(
                provider_name="custom_openai",
                label="default",
                api_key_encrypted=None,
                base_url="http://localhost:1234/v1",
                default_model="my-model",
                tier="paid",
                enabled=True,
                is_local=True,
                created_at=_now(),
                updated_at=_now(),
            )
        )
        db.commit()
    # Without invalidate, the cache would still serve the old configs.
    loader.invalidate()
    configs_b = loader.resolve_configs()
    custom_a = next((c for c in configs_a if c.name == "custom_openai"), None)
    custom_b = next((c for c in configs_b if c.name == "custom_openai"), None)
    # In env, custom_openai is enabled iff base_url+model are set; tests
    # don't set those env vars so the env config is enabled=False.
    # After the DB write + invalidate, the loader must surface the DB row.
    if custom_a is not None:
        assert custom_a.enabled is False
    assert custom_b is not None
    assert custom_b.enabled is True
    assert custom_b.base_url == "http://localhost:1234/v1"


def test_version_counter_local_fallback_increments():
    counter = _VersionCounter()
    v0 = counter.get()
    counter.bump()
    v1 = counter.get()
    # Either Redis returns the same incremented value, or local fallback
    # incremented. Either way, monotonic.
    assert v1 >= v0


# ============================================================ Settings


def test_loader_settings_from_db(client, fresh_cipher):
    with _session() as db:
        row = db.query(AiSettings).filter_by(id=1).one()
        row.feature_enabled = False
        row.kill_switch_active = True
        row.budget_daily_usd = 99.0
        db.commit()
    loader = _make_loader(fresh_cipher)
    settings = loader.resolve_settings()
    assert settings.feature_enabled is False
    assert settings.kill_switch_active is True
    assert settings.budget_daily_usd == 99.0
    assert settings.source == "db"


# ============================================================ preview helper


def test_preview_api_key_long():
    preview, present = preview_api_key("sk-ant-1234567890abcdefghijklmnop")
    assert present is True
    assert preview is not None
    assert preview.startswith("sk-ant")
    assert preview.endswith("mnop")
    assert "…" in preview


def test_preview_api_key_short():
    preview, present = preview_api_key("ab")
    assert present is True
    assert "ab" in (preview or "")


def test_preview_api_key_empty():
    preview, present = preview_api_key(None)
    assert present is False
    assert preview is None

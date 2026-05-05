"""Tests for ``scripts/migrate_env_to_db.py``.

Phase 4 §4.1 requires the migration script to be:

  * **Idempotent** — running twice doesn't duplicate rows
  * **Non-destructive by default** — existing DB rows are preserved
  * **Encryption-key-aware** — refuses to run without ``AI_CONFIG_ENCRYPTION_KEY``

Tests invoke the script via ``runpy`` so we don't subprocess + lose
the test SQLite engine. Args are passed via ``sys.argv``.
"""

from __future__ import annotations

import runpy
import sys
from pathlib import Path

import pytest
from app.db import SessionLocal
from app.models import AiProviderCredential
from app.security.secrets import generate_master_key, reset_cipher
from app.settings import reset_settings

SCRIPT = Path(__file__).resolve().parent.parent.parent / "scripts" / "migrate_env_to_db.py"


def _run_script(argv: list[str]) -> int:
    """Run the migration script with ``argv``. Return the exit code.

    Catches the ``SystemExit`` the script raises so the caller can
    assert on the code without bringing down the test runner.
    """
    saved_argv = sys.argv
    try:
        sys.argv = ["migrate_env_to_db.py", *argv]
        try:
            runpy.run_path(str(SCRIPT), run_name="__main__")
            return 0
        except SystemExit as exc:
            return int(exc.code or 0)
    finally:
        sys.argv = saved_argv


@pytest.fixture(autouse=True)
def _setup_env(monkeypatch, client):
    """Ensure the test DB has a clean credential table + an encryption key set."""
    monkeypatch.setenv("AI_CONFIG_ENCRYPTION_KEY", generate_master_key())
    # Anthropic is the most realistic fixture — gives the script
    # something to migrate.
    monkeypatch.setenv("ANTHROPIC_API_KEY", "sk-ant-FAKE-MIGRATION-TEST-KEY-XXXXXXXX")
    monkeypatch.setenv("AI_DEFAULT_PROVIDER", "anthropic")
    reset_settings()
    reset_cipher()

    db = SessionLocal()
    try:
        db.query(AiProviderCredential).delete()
        db.commit()
    finally:
        db.close()
    yield
    db = SessionLocal()
    try:
        db.query(AiProviderCredential).delete()
        db.commit()
    finally:
        db.close()
    reset_cipher()
    reset_settings()


def test_dry_run_does_not_write(capsys):
    code = _run_script(["--dry-run"])
    assert code == 0
    db = SessionLocal()
    try:
        rows = db.query(AiProviderCredential).all()
    finally:
        db.close()
    assert len(rows) == 0, "dry-run must never write to the DB"
    out = capsys.readouterr().out
    assert "Dry run" in out


def test_real_run_creates_rows():
    code = _run_script([])
    assert code == 0
    db = SessionLocal()
    try:
        rows = db.query(AiProviderCredential).all()
    finally:
        db.close()
    names = {r.provider_name for r in rows}
    assert "anthropic" in names
    # The migrated row carries the configured default flag.
    anthropic = next(r for r in rows if r.provider_name == "anthropic")
    assert anthropic.is_default is True
    assert anthropic.api_key_encrypted  # encrypted, not plaintext
    assert "sk-ant-" not in anthropic.api_key_encrypted  # ciphertext, not the key


def test_idempotent_second_run(capsys):
    """Running twice doesn't duplicate or destroy."""
    assert _run_script([]) == 0
    db = SessionLocal()
    try:
        first_count = db.query(AiProviderCredential).count()
        first_id = db.query(AiProviderCredential).filter_by(provider_name="anthropic").one().id
    finally:
        db.close()

    capsys.readouterr()  # drain
    assert _run_script([]) == 0

    db = SessionLocal()
    try:
        second_count = db.query(AiProviderCredential).count()
        second_id = db.query(AiProviderCredential).filter_by(provider_name="anthropic").one().id
    finally:
        db.close()
    assert first_count == second_count
    # Same row id — the second run skipped, didn't replace.
    assert first_id == second_id

    out = capsys.readouterr().out
    # Second run reports "skipping" for the existing row.
    assert "skipping" in out.lower() or "skipped" in out.lower()


def test_force_without_consent_aborts():
    """`--force` without the safety belt must exit 2."""
    # First run to seed the row.
    assert _run_script([]) == 0
    # `--force` without `--i-know-what-i-am-doing` aborts.
    code = _run_script(["--force"])
    assert code == 2


def test_force_with_consent_replaces():
    """`--force --i-know-what-i-am-doing` overwrites existing rows."""
    assert _run_script([]) == 0
    # Mutate the row in-place so we can detect the replacement.
    db = SessionLocal()
    try:
        row = db.query(AiProviderCredential).filter_by(provider_name="anthropic").one()
        row.default_model = "wonky-model"
        db.commit()
        original_id = row.id
    finally:
        db.close()

    code = _run_script(["--force", "--i-know-what-i-am-doing"])
    assert code == 0

    db = SessionLocal()
    try:
        row = db.query(AiProviderCredential).filter_by(provider_name="anthropic").one()
    finally:
        db.close()
    # Same row (id preserved) but the model came from env again.
    assert row.id == original_id
    assert row.default_model != "wonky-model"


def test_no_env_keys_is_a_clean_noop(monkeypatch, capsys):
    """If no providers have env credentials at all, the script reports no work and exits 0."""
    monkeypatch.delenv("ANTHROPIC_API_KEY", raising=False)
    monkeypatch.delenv("OPENAI_API_KEY", raising=False)
    monkeypatch.delenv("GEMINI_API_KEY", raising=False)
    monkeypatch.delenv("GROK_API_KEY", raising=False)
    # Ollama is enabled by default base URL — clear it to simulate the
    # cleanest possible "nothing configured" state.
    monkeypatch.setenv("OLLAMA_BASE_URL", "")
    monkeypatch.setenv("VLLM_BASE_URL", "")
    monkeypatch.setenv("AI_CUSTOM_OPENAI_BASE_URL", "")
    monkeypatch.setenv("AI_CUSTOM_OPENAI_MODEL", "")
    reset_settings()
    capsys.readouterr()  # drain prior output

    code = _run_script([])
    assert code == 0
    out = capsys.readouterr().out
    assert "Nothing to migrate" in out


def test_missing_encryption_key_fails(monkeypatch, capsys):
    monkeypatch.delenv("AI_CONFIG_ENCRYPTION_KEY", raising=False)
    reset_cipher()
    code = _run_script([])
    assert code == 1
    err = capsys.readouterr().err
    assert "AI_CONFIG_ENCRYPTION_KEY" in err

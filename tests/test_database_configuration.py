from __future__ import annotations

import os
from types import SimpleNamespace

import pytest
from app.db import _resolve_database_url, database_backend, engine_options
from app.main import _verify_schema_is_current
from sqlalchemy import create_engine


def test_sqlite_engine_options_are_sqlite_only() -> None:
    options = engine_options("sqlite:///./test.db")
    assert options == {"connect_args": {"check_same_thread": False}}
    assert "pool_size" not in options


def test_postgresql_engine_options_use_configured_pool() -> None:
    settings = SimpleNamespace(
        database_pool_size=7,
        database_max_overflow=11,
        database_pool_timeout=17,
        database_pool_recycle=901,
    )
    options = engine_options(
        "postgresql+psycopg://user:secret@localhost/db",
        settings=settings,
    )
    assert options == {
        "pool_pre_ping": True,
        "pool_size": 7,
        "max_overflow": 11,
        "pool_timeout": 17,
        "pool_recycle": 901,
    }
    assert "connect_args" not in options
    assert database_backend("postgresql+psycopg://user:secret@localhost/db") == "postgresql"


def test_database_url_missing_raises_error_without_allow_sqlite(monkeypatch) -> None:
    monkeypatch.delenv("DATABASE_URL", raising=False)
    monkeypatch.setenv("ALLOW_SQLITE", "false")

    # Patch settings singleton
    import app.settings

    monkeypatch.setattr(app.settings, "_settings_instance", SimpleNamespace(database_url="", auth_enabled=False))

    with pytest.raises(RuntimeError, match="fallback to SQLite is not explicitly allowed"):
        _resolve_database_url()


def test_database_url_missing_succeeds_with_allow_sqlite(monkeypatch) -> None:
    monkeypatch.delenv("DATABASE_URL", raising=False)
    monkeypatch.setenv("ALLOW_SQLITE", "true")

    # Patch settings singleton
    import app.settings

    monkeypatch.setattr(app.settings, "_settings_instance", SimpleNamespace(database_url="", auth_enabled=False))

    url = _resolve_database_url()
    assert url.startswith("sqlite:///")


def test_verify_schema_is_current_empty_db(monkeypatch) -> None:
    # An empty database (no tables) should pass verification
    engine = create_engine("sqlite:///:memory:")
    monkeypatch.setattr("app.main.engine", engine)

    # Should not raise any error
    _verify_schema_is_current()


def test_verify_schema_is_current_stale_sqlite(monkeypatch) -> None:
    # Create SQLite engine and add sbom_source table WITHOUT tenant_id column
    engine = create_engine("sqlite:///:memory:")
    with engine.begin() as conn:
        conn.execute(sa_text("CREATE TABLE sbom_source (id INTEGER PRIMARY KEY)"))

    monkeypatch.setattr("app.main.engine", engine)

    # Should raise RuntimeError because tenant_id is missing and it's not empty
    with pytest.raises(RuntimeError, match="Database schema is not up to date"):
        _verify_schema_is_current()


def test_verify_schema_is_current_up_to_date_sqlite(monkeypatch) -> None:
    # Create SQLite engine and add sbom_source table WITH tenant_id column
    engine = create_engine("sqlite:///:memory:")
    with engine.begin() as conn:
        conn.execute(sa_text("CREATE TABLE sbom_source (id INTEGER PRIMARY KEY, tenant_id INTEGER)"))

    monkeypatch.setattr("app.main.engine", engine)

    # Should pass without error
    _verify_schema_is_current()


# Helper to avoid importing text from sqlalchemy in test module scope
def sa_text(query: str):
    from sqlalchemy import text

    return text(query)


def test_database_url_masks_password_in_diagnostics() -> None:
    from sqlalchemy.engine import make_url

    url = make_url("postgresql+psycopg://sbom:secret_pass@localhost:5432/sbom_analyser")
    assert "secret_pass" not in url.render_as_string(hide_password=True)
    assert "***" in url.render_as_string(hide_password=True)


def test_postgres_url_without_password_raises_error(monkeypatch) -> None:
    monkeypatch.setenv("DATABASE_URL", "postgresql+psycopg://sbom@localhost:5432/sbom_analyser")
    with pytest.raises(RuntimeError, match="without password is invalid"):
        _resolve_database_url()


def test_db_check_script_reports_active_python() -> None:
    import subprocess
    import sys
    from pathlib import Path

    root = Path(__file__).resolve().parent.parent
    res = subprocess.run(
        [sys.executable, "scripts/check_database.py"],
        cwd=root,
        capture_output=True,
        text=True,
        env={**os.environ, "ALLOW_SQLITE": "true"},
    )
    assert "python:" in res.stdout
    assert sys.executable in res.stdout


def test_alembic_uses_database_url_from_env() -> None:
    import subprocess
    import sys
    from pathlib import Path

    root = Path(__file__).resolve().parent.parent
    # We test that running alembic uses env URL by passing a closed port on localhost to fail fast
    res = subprocess.run(
        [sys.executable, "-m", "alembic", "current"],
        cwd=root,
        capture_output=True,
        text=True,
        env={**os.environ, "DATABASE_URL": "postgresql+psycopg://sbom:pass@localhost:54321/db"},
    )
    assert "54321" in res.stdout or "54321" in res.stderr


def test_app_does_not_silently_fallback_to_sqlite(monkeypatch) -> None:
    monkeypatch.setenv("DATABASE_URL", "postgresql+psycopg://sbom:pass@localhost:5432/sbom_analyser")
    url = _resolve_database_url()
    assert "sqlite" not in url
    assert "postgresql" in url

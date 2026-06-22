from __future__ import annotations

from types import SimpleNamespace

from app.db import database_backend, engine_options


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

# db.py
"""SQLAlchemy engine and session. Supports SQLite (dev/tests) and PostgreSQL (production)."""

from __future__ import annotations

import os
from pathlib import Path

from sqlalchemy import create_engine, event
from sqlalchemy.orm import declarative_base, sessionmaker


def _default_sqlite_url() -> str:
    _default_db = str(Path(__file__).resolve().parent.parent / "sbom_api.db")
    return f"sqlite:///{_default_db}"


def _resolve_database_url() -> str:
    # Prefer explicit env (tests set this before import) then Settings.
    raw = (os.getenv("DATABASE_URL") or "").strip()
    if raw:
        return raw
    try:
        from .settings import get_settings

        s = get_settings()
        u = (s.database_url or "").strip()
        if u:
            return u
    except Exception:
        pass
    return _default_sqlite_url()


DATABASE_URL = _resolve_database_url()

_connect_args: dict = {}
if DATABASE_URL.startswith("sqlite"):
    _connect_args = {"check_same_thread": False}

engine = create_engine(DATABASE_URL, connect_args=_connect_args)


@event.listens_for(engine, "connect")
def _set_sqlite_pragma(dbapi_connection, connection_record):
    if engine.dialect.name != "sqlite":
        return
    cursor = dbapi_connection.cursor()
    cursor.execute("PRAGMA foreign_keys=ON")
    cursor.close()


SessionLocal = sessionmaker(bind=engine, autoflush=False, autocommit=False)
Base = declarative_base()


def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()

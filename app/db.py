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


# ---------------------------------------------------------------------------
# Transparent soft-delete filter (Option C from docs/soft-delete-audit.md §3.2).
#
# Every SELECT that touches a model inheriting ``SoftDeleteMixin`` gets a
# ``WHERE is_active = TRUE`` predicate injected. Bypass with
# ``execution_options(include_deleted=True)`` — required for restore
# endpoints and admin "show tombstones" surfaces.
#
# Why a Session event listener:
#  * It intercepts both ``select(Model)`` and legacy ``db.query(Model)``
#    paths (both flow through ``do_orm_execute``).
#  * It cascades to relationship loads (``include_aliases=True``), so a
#    parent's lazy-loaded children also see the filter.
#  * It is a single source of truth — adding a new soft-deletable model
#    requires no router changes.
#
# Wired here (rather than in app/main.py) because ``Session`` is built
# from this module's ``sessionmaker``; binding the listener at import
# time guarantees every session — including the one tests build via the
# fixtures — picks up the filter.
# ---------------------------------------------------------------------------

from sqlalchemy.orm import Session as _OrmSession  # noqa: E402
from sqlalchemy.orm import with_loader_criteria  # noqa: E402


@event.listens_for(_OrmSession, "do_orm_execute")
def _filter_soft_deleted(execute_state) -> None:
    if not execute_state.is_select:
        return
    if execute_state.execution_options.get("include_deleted"):
        return

    # Local import so app.db can be imported without a circular hit on
    # app.models_mixins during initial bootstrap.
    from .models_mixins import SoftDeleteMixin

    execute_state.statement = execute_state.statement.options(
        with_loader_criteria(
            SoftDeleteMixin,
            lambda cls: cls.is_active.is_(True),
            include_aliases=True,
        )
    )

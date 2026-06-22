# db.py
"""SQLAlchemy engine and session. Supports SQLite (dev/tests) and PostgreSQL (production)."""

from __future__ import annotations

import os
from pathlib import Path

from sqlalchemy import MetaData, create_engine, event
from sqlalchemy.engine import make_url
from sqlalchemy.orm import declarative_base, sessionmaker

NAMING_CONVENTION = {
    "ix": "ix_%(column_0_label)s",
    "uq": "uq_%(table_name)s_%(column_0_name)s",
    "ck": "ck_%(table_name)s_%(constraint_name)s",
    "fk": "fk_%(table_name)s_%(column_0_name)s_%(referred_table_name)s",
    "pk": "pk_%(table_name)s",
}


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


def database_backend(database_url: str) -> str:
    """Return the SQLAlchemy backend name without exposing URL credentials."""
    return make_url(database_url).get_backend_name()


def engine_options(database_url: str, settings=None) -> dict:
    """Build dialect-specific engine options without opening a connection."""
    backend = database_backend(database_url)
    if backend == "sqlite":
        return {"connect_args": {"check_same_thread": False}}
    if backend == "postgresql":
        if settings is None:
            from .settings import get_settings

            settings = get_settings()
        return {
            "pool_pre_ping": True,
            "pool_size": settings.database_pool_size,
            "max_overflow": settings.database_max_overflow,
            "pool_timeout": settings.database_pool_timeout,
            "pool_recycle": settings.database_pool_recycle,
        }
    return {}


engine = create_engine(DATABASE_URL, **engine_options(DATABASE_URL))


@event.listens_for(engine, "connect")
def _set_sqlite_pragma(dbapi_connection, connection_record):
    if engine.dialect.name != "sqlite":
        return
    cursor = dbapi_connection.cursor()
    cursor.execute("PRAGMA foreign_keys=ON")
    cursor.close()


SessionLocal = sessionmaker(bind=engine, autoflush=False, autocommit=False)
Base = declarative_base(metadata=MetaData(naming_convention=NAMING_CONVENTION))


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
    from .core.context import get_bound_context
    from .models_mixins import SoftDeleteMixin, TenantOwnedMixin

    execute_state.statement = execute_state.statement.options(
        with_loader_criteria(
            SoftDeleteMixin,
            lambda cls: cls.is_active.is_(True),
            include_aliases=True,
        )
    )
    context = get_bound_context()
    if context is not None:
        tenant_id = context.tenant_id
        execute_state.statement = execute_state.statement.options(
            with_loader_criteria(
                TenantOwnedMixin,
                lambda cls: cls.tenant_id == tenant_id,
                include_aliases=True,
            )
        )


@event.listens_for(_OrmSession, "before_flush")
def _enforce_tenant_on_writes(session, _flush_context, _instances) -> None:
    """Stamp new tenant rows and reject cross-tenant ORM mutations."""
    from .core.context import get_bound_context
    from .models_mixins import TenantOwnedMixin

    context = get_bound_context()
    if context is not None:
        tenant_id = context.tenant_id
    else:
        from .settings import get_settings

        if get_settings().auth_enabled:
            tenant_id = None
        else:
            tenant_id = 1

    for instance in session.new:
        if not isinstance(instance, TenantOwnedMixin):
            continue
        current = getattr(instance, "tenant_id", None)
        if current is None:
            if tenant_id is None:
                raise RuntimeError("Tenant context is required for tenant-owned writes")
            instance.tenant_id = tenant_id
        elif tenant_id is not None and current != tenant_id:
            raise RuntimeError("Cross-tenant insert blocked")

    if context is None:
        return
    for instance in session.dirty | session.deleted:
        if isinstance(instance, TenantOwnedMixin) and instance.tenant_id != context.tenant_id:
            raise RuntimeError("Cross-tenant mutation blocked")

# db.py
"""SQLAlchemy engine and session. Supports SQLite (dev/tests) and PostgreSQL (production)."""

from __future__ import annotations

import logging
import os
from pathlib import Path

# Load .env file if present before any config resolution
try:
    from dotenv import load_dotenv

    load_dotenv()
except ImportError:
    pass

from sqlalchemy import MetaData, create_engine, event, inspect
from sqlalchemy.engine import make_url
from sqlalchemy.orm import Session, declarative_base, sessionmaker

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
        try:
            url_parsed = make_url(raw)
            if url_parsed.get_backend_name() == "postgresql" and not url_parsed.password:
                raise RuntimeError("PostgreSQL DATABASE_URL without password is invalid for local development.")
        except Exception as e:
            if isinstance(e, RuntimeError):
                raise e
        return raw
    try:
        from .settings import get_settings

        s = get_settings()
        u = (s.database_url or "").strip()
        if u:
            try:
                url_parsed = make_url(u)
                if url_parsed.get_backend_name() == "postgresql" and not url_parsed.password:
                    raise RuntimeError("PostgreSQL DATABASE_URL without password is invalid for local development.")
            except Exception as e:
                if isinstance(e, RuntimeError):
                    raise e
            return u
    except Exception as exc:  # noqa: BLE001
        logging.getLogger("sbom.db").warning("settings_database_url_unavailable: %s", exc)

    # If DATABASE_URL is missing, we only allow SQLite fallback if ALLOW_SQLITE is explicitly true.
    allow_sqlite = os.getenv("ALLOW_SQLITE", "false").lower() == "true"
    if not allow_sqlite:
        raise RuntimeError(
            "DATABASE_URL is not configured and fallback to SQLite is not explicitly allowed. "
            "Please set DATABASE_URL or set ALLOW_SQLITE=true to use local SQLite development."
        )
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

        # Support both new db_pool_* and legacy database_pool_* settings names for compatibility
        pool_pre_ping = getattr(settings, "db_pool_pre_ping", None)
        if pool_pre_ping is None:
            pool_pre_ping = getattr(settings, "database_pool_pre_ping", True)

        pool_size = getattr(settings, "db_pool_size", None)
        if pool_size is None:
            pool_size = getattr(settings, "database_pool_size", 20)

        max_overflow = getattr(settings, "db_max_overflow", None)
        if max_overflow is None:
            max_overflow = getattr(settings, "database_max_overflow", 20)

        pool_timeout = getattr(settings, "db_pool_timeout", None)
        if pool_timeout is None:
            pool_timeout = getattr(settings, "database_pool_timeout", 30)

        pool_recycle = getattr(settings, "db_pool_recycle", None)
        if pool_recycle is None:
            pool_recycle = getattr(settings, "database_pool_recycle", 1800)

        return {
            "pool_pre_ping": pool_pre_ping,
            "pool_size": pool_size,
            "max_overflow": max_overflow,
            "pool_timeout": pool_timeout,
            "pool_recycle": pool_recycle,
        }
    return {}


# Credentials and token hashes may be bound parameters. Never include parameter
# values in SQLAlchemy engine logs or formatted database exceptions.
engine = create_engine(DATABASE_URL, hide_parameters=True, **engine_options(DATABASE_URL))


@event.listens_for(engine, "connect")
def _set_sqlite_pragma(dbapi_connection, connection_record):
    if engine.dialect.name != "sqlite":
        return
    import uuid
    dbapi_connection.create_function("gen_random_uuid", 0, lambda: uuid.uuid4().hex)
    cursor = dbapi_connection.cursor()
    cursor.execute("PRAGMA foreign_keys=ON")
    cursor.close()


class TenantContextRequired(RuntimeError):
    pass


def _required_tenant_id():
    from .core.context import get_bound_context

    context = get_bound_context()
    if context is None or type(context.tenant_id) is not int or context.tenant_id <= 0:
        raise TenantContextRequired("Tenant context is required for tenant-owned data")
    return context.tenant_id


class TenantSession(Session):
    def _identity_lookup(self, mapper, primary_key_identity, **kwargs):
        from .models_mixins import TenantOwnedMixin

        owned = issubclass(mapper.class_, TenantOwnedMixin)
        tenant_id = _required_tenant_id() if owned else None
        row = super()._identity_lookup(mapper, primary_key_identity, **kwargs)
        if owned and isinstance(row, TenantOwnedMixin) and row.tenant_id != tenant_id:
            return None
        return row

    def _get_impl(self, entity, primary_key_identity, db_load_fn, **kwargs):
        from .models_mixins import TenantOwnedMixin

        mapper = inspect(entity)
        owned = issubclass(mapper.class_, TenantOwnedMixin)
        tenant_id = _required_tenant_id() if owned else None
        row = super()._get_impl(entity, primary_key_identity, db_load_fn, **kwargs)
        # Session.get / Query.get can use an identity-map hit without SQL.
        if owned and row is not None and row.tenant_id != tenant_id:
            return None
        return row

    def bulk_save_objects(self, objects, **kwargs):
        from .models_mixins import TenantOwnedMixin

        objects = list(objects)
        if any(isinstance(row, TenantOwnedMixin) for row in objects):
            raise RuntimeError("Use tenant-scoped ORM operations for tenant-owned bulk writes")
        return super().bulk_save_objects(objects, **kwargs)

    def bulk_insert_mappings(self, mapper, mappings, **kwargs):
        from .models_mixins import TenantOwnedMixin

        if issubclass(inspect(mapper).class_, TenantOwnedMixin):
            raise RuntimeError("Use tenant-scoped ORM operations for tenant-owned bulk writes")
        return super().bulk_insert_mappings(mapper, mappings, **kwargs)

    def bulk_update_mappings(self, mapper, mappings):
        from .models_mixins import TenantOwnedMixin

        if issubclass(inspect(mapper).class_, TenantOwnedMixin):
            raise RuntimeError("Use tenant-scoped ORM operations for tenant-owned bulk writes")
        return super().bulk_update_mappings(mapper, mappings)


SessionLocal = sessionmaker(bind=engine, class_=TenantSession, autoflush=False, autocommit=False)
Base = declarative_base(metadata=MetaData(naming_convention=NAMING_CONVENTION))


def get_db():
    db = SessionLocal()
    try:
        yield db
    except Exception:
        db.rollback()
        raise
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


def _tenant_table_names():
    from .models_mixins import TenantOwnedMixin

    return {mapper.local_table.name for mapper in Base.registry.mappers if issubclass(mapper.class_, TenantOwnedMixin)}


def _tenant_dml_target(target, names):
    from sqlalchemy.sql.selectable import Alias

    base = target
    while isinstance(base, Alias):
        base = base.original
    return getattr(base, "name", None) in names


def _scope_core_select(statement, tenant_id, names, *, stop_on=()):
    from sqlalchemy import Table
    from sqlalchemy.sql import visitors
    from sqlalchemy.sql.selectable import Alias, Join

    def clauses(source, nullable=False):
        if isinstance(source, Join):
            yield from clauses(source.left, nullable or source.full)
            yield from clauses(source.right, nullable or source.isouter or source.full)
        elif isinstance(source, Table) and source.name in names:
            clause = source.c.tenant_id == tenant_id
            yield clause | source.c.tenant_id.is_(None) if nullable else clause
        elif isinstance(source, Alias) and isinstance(source.original, Table) and source.original.name in names:
            clause = source.c.tenant_id == tenant_id
            yield clause | source.c.tenant_id.is_(None) if nullable else clause

    def scope_select(clone):
        predicates = tuple(clause for source in clone.get_final_froms() for clause in clauses(source))
        # Modify only the newly cloned Select. A single traversal memo preserves
        # shared/recursive CTE identity, unlike independently cloning subqueries.
        clone._where_criteria += predicates

    options = tuple(option for node in visitors.iterate(statement) for option in getattr(node, "_with_options", ()))
    return visitors.cloned_traverse(statement, {"stop_on": (*stop_on, *options)}, {"select": scope_select})


@event.listens_for(_OrmSession, "do_orm_execute")
def _enforce_statement_tenant(execute_state):
    from sqlalchemy import Table
    from sqlalchemy.sql import visitors
    from sqlalchemy.sql.elements import TextClause

    statement = execute_state.statement
    names = _tenant_table_names()
    nodes = list(visitors.iterate(statement))
    tables = [node for node in nodes if isinstance(node, Table) and node.name in names]
    # Raw SQL cannot be safely rewritten or verified by the ORM. Migrations
    # use explicit operator connections, outside this application Session.
    # The existing Native bootstrap lock is the only application raw-SQL
    # entry point. Exact matching avoids identifier-encoding/parser bypasses.
    trusted_bootstrap_lock = "SELECT pg_advisory_xact_lock(734621062)"
    if any(isinstance(node, TextClause) and node.text != trusted_bootstrap_lock for node in nodes):
        raise RuntimeError("Raw SQL requires a scoped SQLAlchemy statement or an explicit operator connection")
    if not tables:
        return
    tenant_id = _required_tenant_id()
    if execute_state.is_select:
        execute_state.statement = _scope_core_select(statement, tenant_id, names)
    elif execute_state.is_update or execute_state.is_delete:
        target = statement.table
        if _tenant_dml_target(target, names):
            values = getattr(statement, "_values", {}) or {}
            assignments = list(values.items()) + list(getattr(statement, "_ordered_values", ()) or ())
            for key, value in assignments:
                if getattr(key, "key", key) == "tenant_id" and getattr(value, "value", None) != tenant_id:
                    raise RuntimeError("Cross-tenant owner update blocked")
            scoped = statement.where(target.c.tenant_id == tenant_id)
            execute_state.statement = _scope_core_select(scoped, tenant_id, names, stop_on=(target,))
    elif execute_state.is_insert:
        if _tenant_dml_target(statement.table, names):
            if getattr(statement, "_post_values_clause", None) is not None:
                raise RuntimeError("Tenant-owned upsert requires an explicit scoped service")
            if getattr(statement, "select", None) is not None:
                raise RuntimeError("Tenant-owned INSERT SELECT requires an explicit scoped service")
            values = getattr(statement, "_values", {}) or {}
            for key, value in values.items():
                if getattr(key, "key", key) == "tenant_id" and getattr(value, "value", None) != tenant_id:
                    raise RuntimeError("Cross-tenant insert blocked")
            multi_values = getattr(statement, "_multi_values", ())
            if multi_values:
                for batch in multi_values:
                    for values in batch:
                        if not isinstance(values, dict) or values.get("tenant_id") != tenant_id:
                            raise RuntimeError("Cross-tenant or unscoped multi-row insert blocked")
            else:
                execute_state.statement = statement.values(tenant_id=tenant_id)
            execute_state.statement = _scope_core_select(
                execute_state.statement, tenant_id, names, stop_on=(statement.table,)
            )
    parameters = execute_state.parameters
    mappings = parameters if isinstance(parameters, list) else [parameters]
    for values in mappings:
        if isinstance(values, dict) and "tenant_id" in values and values["tenant_id"] != tenant_id:
            raise RuntimeError("Cross-tenant bulk operation blocked")


@event.listens_for(_OrmSession, "do_orm_execute")
def _filter_soft_deleted(execute_state) -> None:
    if not execute_state.is_select:
        return
    # Local import so app.db can be imported without a circular hit on
    # app.models_mixins during initial bootstrap.
    from .core.context import get_bound_context
    from .models_mixins import SoftDeleteMixin, TenantOwnedMixin

    # Tombstone visibility must never change tenant or resource scope.
    if not execute_state.execution_options.get("include_deleted"):
        execute_state.statement = execute_state.statement.options(
            with_loader_criteria(
                SoftDeleteMixin,
                lambda cls: cls.is_active.is_(True),
                include_aliases=True,
            )
        )
    context = get_bound_context()
    if context is not None and context.tenant_id is not None:
        tenant_id = context.tenant_id
        execute_state.statement = execute_state.statement.options(
            with_loader_criteria(
                TenantOwnedMixin,
                lambda cls: cls.tenant_id == tenant_id,
                include_aliases=True,
            )
        )

    scope = execute_state.session.info.get("dashboard_scope")
    if scope is not None:
        # Core table subqueries avoid recursively applying ORM criteria to
        # themselves.  This one eligible SBOM set is shared by every dashboard
        # metric, including raw run/finding lifetime and trend queries.
        from sqlalchemy import select

        from .models import (
            AnalysisFinding,
            AnalysisRun,
            Product,
            Projects,
            SBOMComponent,
            SBOMSource,
            VexStatement,
            VulnerabilityRemediation,
        )

        sbom_ids = scope.eligible_sbom_ids()
        r = AnalysisRun.__table__.c
        run_ids = select(r.id).where(
            r.tenant_id == scope.tenant_id,
            r.is_active.is_(True),
            r.is_current.is_(True),
            r.sbom_id.in_(sbom_ids),
        )
        criteria = [
            (SBOMSource, SBOMSource.id.in_(sbom_ids)),
            (AnalysisRun, AnalysisRun.sbom_id.in_(sbom_ids) & AnalysisRun.is_current.is_(True)),
            (AnalysisFinding, AnalysisFinding.analysis_run_id.in_(run_ids)),
            (SBOMComponent, SBOMComponent.sbom_id.in_(sbom_ids)),
            (VexStatement, VexStatement.sbom_id.in_(sbom_ids)),
            (Projects, Projects.tenant_id == scope.tenant_id),
            (VulnerabilityRemediation, VulnerabilityRemediation.tenant_id == scope.tenant_id),
        ]
        if scope.project_id is not None:
            criteria.extend(
                [
                    (VulnerabilityRemediation, VulnerabilityRemediation.project_id == scope.project_id),
                ]
            )
            criteria.append((Projects, Projects.id == scope.project_id))
        if scope.product_id is not None:
            criteria.append((Product, (Product.id == scope.product_id) & (Product.tenant_id == scope.tenant_id)))
        else:
            p = Product.__table__.c
            product_ids = select(p.id).where(p.tenant_id == scope.tenant_id)
            if scope.project_id is not None:
                product_ids = product_ids.where(p.project_id == scope.project_id)
            criteria.append((Product, Product.id.in_(product_ids)))
        for model, clause in criteria:
            execute_state.statement = execute_state.statement.options(
                with_loader_criteria(model, clause, include_aliases=True)
            )


@event.listens_for(_OrmSession, "before_flush")
def _enforce_tenant_on_writes(session, _flush_context, _instances) -> None:
    """Stamp new tenant rows and reject cross-tenant ORM mutations."""
    from .core.context import get_bound_context
    from .models_mixins import TenantOwnedMixin

    context = get_bound_context()
    owned = [
        instance for instance in session.new | session.dirty | session.deleted if isinstance(instance, TenantOwnedMixin)
    ]
    if not owned:
        return
    tenant_id = _required_tenant_id()

    for instance in session.new:
        if not isinstance(instance, TenantOwnedMixin):
            continue
        current = getattr(instance, "tenant_id", None)
        if current is None:
            instance.tenant_id = tenant_id
        elif tenant_id is not None and current != tenant_id:
            raise RuntimeError("Cross-tenant insert blocked")

    for instance in session.dirty | session.deleted:
        if isinstance(instance, TenantOwnedMixin):
            previous = inspect(instance).attrs.tenant_id.history.deleted
            if instance.tenant_id != tenant_id or any(value != tenant_id for value in previous):
                raise RuntimeError("Cross-tenant mutation blocked")
            state = inspect(instance)
            if state.persistent and state.attrs.tenant_id.history.has_changes():
                from sqlalchemy import select

                table = state.mapper.local_table
                predicates = [
                    column == value for column, value in zip(table.primary_key.columns, state.identity, strict=True)
                ]
                original_owner = session.scalar(
                    select(table.c.tenant_id).where(*predicates, table.c.tenant_id == tenant_id)
                )
                if original_owner != tenant_id:
                    raise RuntimeError("Cross-tenant owner reassignment blocked")


@event.listens_for(_OrmSession, "do_orm_execute")
def _scope_ai_configuration(execute_state):
    """CRUD sessions can only load their exact AI configuration owner.

    Runtime inheritance uses a separate session and explicit scope predicates;
    it never broadens the tenant data loader criteria above.
    """
    if not execute_state.is_select or "ai_configuration_tenant" not in execute_state.session.info:
        return
    from .models import AiCredentialAuditLog, AiProviderCredential, AiSettings

    tenant_id = execute_state.session.info["ai_configuration_tenant"]
    for model in (AiProviderCredential, AiSettings, AiCredentialAuditLog):
        clause = model.tenant_id.is_(None) if tenant_id is None else model.tenant_id == tenant_id
        execute_state.statement = execute_state.statement.options(
            with_loader_criteria(model, clause, include_aliases=True)
        )


@event.listens_for(_OrmSession, "before_flush")
def _guard_ai_configuration_writes(session, _flush_context, _instances):
    if "ai_configuration_tenant" not in session.info:
        return
    from .models import AiCredentialAuditLog, AiProviderCredential, AiSettings

    owner = session.info["ai_configuration_tenant"]
    for row in session.new:
        if isinstance(row, (AiProviderCredential, AiSettings, AiCredentialAuditLog)):
            if row.tenant_id is not None and row.tenant_id != owner:
                raise RuntimeError("Cross-scope configuration insert blocked")
            row.tenant_id = owner
    for row in session.dirty | session.deleted:
        if isinstance(row, (AiProviderCredential, AiSettings, AiCredentialAuditLog)) and row.tenant_id != owner:
            raise RuntimeError("Cross-scope configuration mutation blocked")

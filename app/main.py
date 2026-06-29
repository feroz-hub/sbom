"""
SBOM Analyzer — FastAPI application entry point.

This module is intentionally slim. After the principles-driven refactor it
contains ONLY:

  * FastAPI app construction
  * CORS + request-logging middleware
  * Startup hook (DB seed / backfill / migrations)
  * Router registration

All routes live in `app/routers/`, all business logic in `app/services/`,
all DB access in `app/repositories/`, and all configuration in
`app/settings.py`.

Design principles applied here:
  - Single Responsibility: this file only wires the app together.
  - Separation of Concerns: routes, services, repositories, settings split.
  - Dependency Inversion: routers depend on service abstractions.
  - Explicit over Implicit: every router is registered by name below.
"""

from __future__ import annotations

import logging
import time
from contextlib import asynccontextmanager
from pathlib import Path

from fastapi import Depends, FastAPI, Request
from fastapi.middleware.cors import CORSMiddleware
from slowapi.errors import RateLimitExceeded
from slowapi.middleware import SlowAPIMiddleware
from sqlalchemy import select, text
from starlette.middleware.gzip import GZipMiddleware

from .logger import get_logger, setup_logging

# Initialise logging FIRST so subsequent imports inherit the config.
setup_logging()
log = get_logger("api")

from datetime import UTC, datetime

from . import error_handlers
from .auth import validate_auth_setup
from .core.security import enforce_request_access
from .db import Base, SessionLocal, engine
from .http_client import close_async_http_client, init_async_http_client
from .middleware import MaxBodySizeMiddleware

# --- Routers --------------------------------------------------------------
from .nvd_mirror.api import router as nvd_mirror_admin_router
from .rate_limit import limiter, rate_limit_exceeded_handler
from .routers import (
    ai_copilot,
    ai_credentials,
    ai_fixes,
    ai_usage,
    analyze_endpoints,
    compare,
    cves,
    dashboard_advanced,
    dashboard_main,
    health,
    lifecycle,
    lifecycle_admin,
    pdf,
    projects,
    remediation,
    runs,
    sbom_upload,
    sbom_validation_sessions,
    sbom_versions,
    sboms_crud,
    schedules,
    tenants,
    vex,
)
from .routers import analysis as analysis_export_router
from .routers import dashboard as dashboard_trend_router
from .routers import sbom as sbom_features_router
from .services.analysis_service import backfill_analytics_tables
from .services.sbom_service import now_iso  # re-exported for tests/back-compat
from .settings import get_settings

# --- App construction ----------------------------------------------------
settings = get_settings()
APP_VERSION = settings.APP_VERSION


def _ensure_text_column(table_name: str, column_name: str) -> None:
    """Idempotent ALTER TABLE … ADD COLUMN for SQLite text columns."""
    if engine.dialect.name != "sqlite":
        return
    with engine.connect() as conn:
        existing = {row[1] for row in conn.execute(text(f"PRAGMA table_info({table_name})"))}
        if column_name in existing:
            return
        conn.execute(text(f"ALTER TABLE {table_name} ADD COLUMN {column_name} TEXT"))
        conn.commit()


def _ensure_column(table_name: str, column_name: str, type_sql: str, default_sql: str | None = None) -> None:
    """Idempotent ALTER TABLE for SQLite columns of an arbitrary type.

    SQLite forbids non-constant defaults in ``ADD COLUMN``; the caller
    must pass a literal (e.g. ``"'validated'"``, ``"0"``) when the
    column is ``NOT NULL``.
    """
    if engine.dialect.name != "sqlite":
        return
    with engine.connect() as conn:
        existing = {row[1] for row in conn.execute(text(f"PRAGMA table_info({table_name})"))}
        if column_name in existing:
            return
        ddl = f"ALTER TABLE {table_name} ADD COLUMN {column_name} {type_sql}"
        if default_sql is not None:
            ddl += f" DEFAULT {default_sql}"
        conn.execute(text(ddl))
        conn.commit()


def _ensure_remediation_audit_table() -> None:
    """Create the remediation audit table for legacy SQLite databases."""
    if engine.dialect.name != "sqlite":
        return
    with engine.begin() as conn:
        tables = {row[0] for row in conn.execute(text("SELECT name FROM sqlite_master WHERE type='table'"))}
        if "vulnerability_remediation_audit" in tables:
            return
        conn.execute(
            text(
                """
                CREATE TABLE vulnerability_remediation_audit (
                    id INTEGER PRIMARY KEY,
                    remediation_id INTEGER NOT NULL REFERENCES vulnerability_remediation(id) ON DELETE CASCADE,
                    project_id INTEGER NOT NULL REFERENCES projects(id) ON DELETE CASCADE,
                    vuln_id VARCHAR NOT NULL,
                    component_name VARCHAR NOT NULL,
                    component_version VARCHAR NOT NULL,
                    old_status VARCHAR,
                    new_status VARCHAR NOT NULL,
                    changed_by VARCHAR(128),
                    changed_at VARCHAR NOT NULL,
                    note TEXT
                )
                """
            )
        )
        conn.execute(
            text(
                "CREATE INDEX ix_vulnerability_remediation_audit_remediation_id "
                "ON vulnerability_remediation_audit (remediation_id)"
            )
        )
        conn.execute(
            text(
                "CREATE INDEX ix_vulnerability_remediation_audit_project_id "
                "ON vulnerability_remediation_audit (project_id)"
            )
        )
        conn.execute(
            text("CREATE INDEX ix_vulnerability_remediation_audit_vuln_id ON vulnerability_remediation_audit (vuln_id)")
        )
        conn.execute(
            text(
                "CREATE INDEX ix_vulnerability_remediation_audit_component_name "
                "ON vulnerability_remediation_audit (component_name)"
            )
        )
        conn.execute(
            text(
                "CREATE INDEX ix_vulnerability_remediation_audit_changed_at "
                "ON vulnerability_remediation_audit (changed_at)"
            )
        )


def _ensure_validation_repair_tables() -> None:
    """Create validation repair tables for legacy SQLite databases."""
    if engine.dialect.name != "sqlite":
        return
    with engine.begin() as conn:
        tables = {row[0] for row in conn.execute(text("SELECT name FROM sqlite_master WHERE type='table'"))}
        if "sbom_validation_sessions" not in tables:
            conn.execute(
                text(
                    """
                    CREATE TABLE sbom_validation_sessions (
                        id VARCHAR(36) PRIMARY KEY,
                        project_id INTEGER REFERENCES projects(id),
                        user_id VARCHAR(128),
                        original_filename VARCHAR(255),
                        sbom_name VARCHAR(255),
                        sbom_type INTEGER REFERENCES sbom_type(id),
                        content_type VARCHAR(255),
                        file_size_bytes INTEGER,
                        sha256 VARCHAR(64),
                        original_size_bytes INTEGER,
                        original_sha256 VARCHAR(64),
                        stored_size_bytes INTEGER,
                        stored_sha256 VARCHAR(64),
                        detected_format VARCHAR(64),
                        detected_version VARCHAR(64),
                        raw_content_text TEXT,
                        raw_content_blob BLOB,
                        raw_storage_path VARCHAR(1024),
                        sanitized_content TEXT,
                        current_content TEXT,
                        repair_content_text TEXT,
                        repair_content_blob BLOB,
                        repair_storage_path VARCHAR(1024),
                        validation_status VARCHAR(32) NOT NULL DEFAULT 'failed',
                        validation_errors_json JSON,
                        stage_results_json JSON,
                        latest_error_report_json JSON,
                        total_lines INTEGER,
                        can_edit BOOLEAN NOT NULL DEFAULT 1,
                        can_ai_fix BOOLEAN NOT NULL DEFAULT 1,
                        security_blocked_reason TEXT,
                        content_sha256 VARCHAR(64),
                        created_at VARCHAR NOT NULL,
                        updated_at VARCHAR NOT NULL,
                        expires_at VARCHAR NOT NULL,
                        imported_sbom_id INTEGER REFERENCES sbom_source(id)
                    )
                    """
                )
            )
        existing_columns = {
            row[1]
            for row in conn.execute(text("PRAGMA table_info(sbom_validation_sessions)"))
        }
        for column_name, column_type in (
            ("content_type", "VARCHAR(255)"),
            ("file_size_bytes", "INTEGER"),
            ("sha256", "VARCHAR(64)"),
            ("original_size_bytes", "INTEGER"),
            ("original_sha256", "VARCHAR(64)"),
            ("stored_size_bytes", "INTEGER"),
            ("stored_sha256", "VARCHAR(64)"),
            ("raw_content_text", "TEXT"),
            ("raw_content_blob", "BLOB"),
            ("raw_storage_path", "VARCHAR(1024)"),
            ("repair_content_text", "TEXT"),
            ("repair_content_blob", "BLOB"),
            ("repair_storage_path", "VARCHAR(1024)"),
            ("validation_errors_json", "JSON"),
            ("stage_results_json", "JSON"),
            ("total_lines", "INTEGER"),
        ):
            if column_name not in existing_columns:
                conn.execute(text(f"ALTER TABLE sbom_validation_sessions ADD COLUMN {column_name} {column_type}"))
        if "sbom_validation_session_events" not in tables:
            conn.execute(
                text(
                    """
                    CREATE TABLE sbom_validation_session_events (
                        id INTEGER PRIMARY KEY,
                        session_id VARCHAR(36) NOT NULL REFERENCES sbom_validation_sessions(id) ON DELETE CASCADE,
                        event_type VARCHAR(64) NOT NULL,
                        actor_user_id VARCHAR(128),
                        timestamp VARCHAR NOT NULL,
                        summary TEXT,
                        before_hash VARCHAR(64),
                        after_hash VARCHAR(64),
                        metadata_json JSON
                    )
                    """
                )
            )
        for ddl in (
            "CREATE INDEX IF NOT EXISTS ix_sbom_validation_sessions_project_id ON sbom_validation_sessions (project_id)",
            "CREATE INDEX IF NOT EXISTS ix_sbom_validation_sessions_user_id ON sbom_validation_sessions (user_id)",
            "CREATE INDEX IF NOT EXISTS ix_sbom_validation_sessions_validation_status ON sbom_validation_sessions (validation_status)",
            "CREATE INDEX IF NOT EXISTS ix_sbom_validation_sessions_content_sha256 ON sbom_validation_sessions (content_sha256)",
            "CREATE INDEX IF NOT EXISTS ix_sbom_validation_sessions_sha256 ON sbom_validation_sessions (sha256)",
            "CREATE INDEX IF NOT EXISTS ix_sbom_validation_sessions_original_sha256 ON sbom_validation_sessions (original_sha256)",
            "CREATE INDEX IF NOT EXISTS ix_sbom_validation_sessions_stored_sha256 ON sbom_validation_sessions (stored_sha256)",
            "CREATE INDEX IF NOT EXISTS ix_sbom_validation_sessions_created_at ON sbom_validation_sessions (created_at)",
            "CREATE INDEX IF NOT EXISTS ix_sbom_validation_sessions_expires_at ON sbom_validation_sessions (expires_at)",
            "CREATE INDEX IF NOT EXISTS ix_sbom_validation_sessions_imported_sbom_id ON sbom_validation_sessions (imported_sbom_id)",
            "CREATE INDEX IF NOT EXISTS ix_sbom_validation_session_events_session_id ON sbom_validation_session_events (session_id)",
            "CREATE INDEX IF NOT EXISTS ix_sbom_validation_session_events_event_type ON sbom_validation_session_events (event_type)",
            "CREATE INDEX IF NOT EXISTS ix_sbom_validation_session_events_actor_user_id ON sbom_validation_session_events (actor_user_id)",
            "CREATE INDEX IF NOT EXISTS ix_sbom_validation_session_events_timestamp ON sbom_validation_session_events (timestamp)",
        ):
            conn.execute(text(ddl))


def _ensure_seed_data() -> None:
    """Prepare legacy SQLite or validate PostgreSQL, then seed reference data."""
    # Enforce schema check before doing any operations
    _verify_schema_is_current()

    if engine.dialect.name == "sqlite":
        Base.metadata.create_all(bind=engine)
    elif engine.dialect.name == "postgresql":
        # Handled by _verify_schema_is_current
        pass
    else:
        raise RuntimeError(f"Unsupported database dialect: {engine.dialect.name}")

    # Lightweight migrations: add columns added in later versions of the schema
    _ensure_text_column("analysis_run", "sbom_name")
    _ensure_text_column("analysis_finding", "cwe")
    _ensure_text_column("analysis_finding", "fixed_versions")
    _ensure_text_column("analysis_finding", "attack_vector")
    _ensure_text_column("analysis_finding", "cvss_version")
    _ensure_text_column("analysis_finding", "aliases")
    _ensure_text_column("run_cache", "source")
    _ensure_text_column("run_cache", "sbom_id")

    # Migration 012 — sbom_source validation columns. Idempotent for
    # SQLite dev DBs that predate the Alembic chain. NOT NULL columns
    # carry literal defaults so existing rows (legacy uploads) get a
    # safe "validated" status.
    _ensure_column("sbom_source", "status", "TEXT", "'validated'")
    _ensure_column("sbom_source", "failed_stage", "TEXT")
    _ensure_column("sbom_source", "validation_errors", "TEXT")
    _ensure_column("sbom_source", "error_count", "INTEGER", "0")
    _ensure_column("sbom_source", "warning_count", "INTEGER", "0")
    _ensure_column("sbom_source", "validated_at", "TEXT")

    # Migration 013 — reclassify legacy rows that predate the validator
    # wiring as 'pending' (validation_at IS NULL is the unambiguous tell).
    # Idempotent: the WHERE clause excludes already-reclassified rows.
    if engine.dialect.name == "sqlite":
        with engine.connect() as conn:
            conn.execute(
                text("UPDATE sbom_source SET status = 'pending' WHERE validated_at IS NULL AND status = 'validated'")
            )
            conn.commit()

    # Migration 014 — soft-delete columns on the eight in-scope tables.
    # ``Base.metadata.create_all`` already added the columns to fresh
    # databases via the SoftDeleteMixin; these calls cover dev DBs that
    # were created before this PR and therefore lack the columns.
    for table in (
        "projects",
        "sbom_source",
        "sbom_analysis_report",
        "sbom_component",
        "analysis_run",
        "analysis_finding",
        "analysis_schedule",
        "ai_fix_batch",
    ):
        _ensure_column(table, "is_active", "BOOLEAN", "1")
        _ensure_column(table, "deactivated_at", "TIMESTAMP")
        _ensure_column(table, "deactivated_by", "VARCHAR(128)")

    # New migrations for SBOM Lifecycle Management Platform features
    _ensure_column("sbom_source", "parent_id", "INTEGER")
    _ensure_column("sbom_source", "change_summary", "TEXT")
    _ensure_column("sbom_source", "completeness_score", "FLOAT", "100.0")
    _ensure_column("sbom_source", "completeness_report", "TEXT")
    _ensure_column("sbom_source", "component_extraction_status", "TEXT")
    _ensure_column("sbom_source", "component_extraction_error", "TEXT")
    _ensure_column("sbom_source", "component_extraction_attempted_at", "TEXT")
    _ensure_column("sbom_source", "component_extraction_completed_at", "TEXT")

    _ensure_column("sbom_component", "license", "TEXT")
    _ensure_column("sbom_component", "hashes", "TEXT")
    _ensure_column("sbom_component", "lifecycle_status", "TEXT")
    _ensure_column("sbom_component", "eos_date", "TEXT")
    _ensure_column("sbom_component", "eol_date", "TEXT")
    _ensure_column("sbom_component", "eof_date", "TEXT")
    _ensure_column("sbom_component", "is_deprecated", "BOOLEAN", "0")
    _ensure_column("sbom_component", "deprecated", "BOOLEAN", "0")
    _ensure_column("sbom_component", "unsupported", "BOOLEAN", "0")
    _ensure_column("sbom_component", "maintenance_status", "TEXT")
    _ensure_column("sbom_component", "latest_version", "TEXT")
    _ensure_column("sbom_component", "ecosystem", "TEXT")
    _ensure_column("sbom_component", "latest_supported_version", "TEXT")
    _ensure_column("sbom_component", "recommended_version", "TEXT")
    _ensure_column("sbom_component", "lifecycle_recommendation", "TEXT")
    _ensure_column("sbom_component", "lifecycle_source", "TEXT")
    _ensure_column("sbom_component", "lifecycle_source_url", "TEXT")
    _ensure_column("sbom_component", "lifecycle_confidence", "TEXT")
    _ensure_column("sbom_component", "lifecycle_checked_at", "TEXT")
    _ensure_column("sbom_component", "lifecycle_evidence_json", "TEXT")
    _ensure_column("sbom_component", "lifecycle_is_stale", "BOOLEAN", "0")
    _ensure_column("sbom_component", "lifecycle_manual_override", "BOOLEAN", "0")
    for column, type_sql, default in (
        ("original_name", "TEXT", None),
        ("normalized_name", "TEXT", None),
        ("original_version", "TEXT", None),
        ("normalized_version", "TEXT", None),
        ("normalized_ecosystem", "TEXT", None),
        ("original_purl", "TEXT", None),
        ("normalized_purl", "TEXT", None),
        ("purl_type", "TEXT", None),
        ("purl_namespace", "TEXT", None),
        ("purl_name", "TEXT", None),
        ("purl_version", "TEXT", None),
        ("purl_qualifiers_json", "TEXT", None),
        ("purl_subpath", "TEXT", None),
        ("normalized_cpes", "TEXT", None),
        ("primary_cpe", "TEXT", None),
        ("cpe_evidence_json", "TEXT", None),
        ("normalized_supplier", "TEXT", None),
        ("normalized_package_key", "TEXT", None),
        ("canonical_identity_confidence", "TEXT", None),
        ("dedupe_canonical_id", "TEXT", None),
        ("dedupe_group_id", "TEXT", None),
        ("dedupe_reason", "TEXT", None),
        ("dedupe_confidence", "TEXT", None),
        ("normalization_notes_json", "TEXT", None),
        ("dedupe_evidence_json", "TEXT", None),
    ):
        _ensure_column("sbom_component", column, type_sql, default)
    _ensure_remediation_audit_table()
    _ensure_validation_repair_tables()
    for column, type_sql, default in (
        ("lookup_key", "TEXT", None),
        ("cpe", "TEXT", None),
        ("unsupported", "BOOLEAN", "0"),
        ("latest_version", "TEXT", None),
        ("is_stale", "BOOLEAN", "0"),
    ):
        _ensure_column("component_lifecycle_cache", column, type_sql, default)

    for column, type_sql in (
        ("source_url", "TEXT"),
        ("discovery_evidence_json", "TEXT"),
        ("last_refresh_status", "TEXT"),
        ("provider_errors_json", "TEXT"),
    ):
        _ensure_column("vex_documents", column, type_sql)

    db = SessionLocal()
    try:
        # PostgreSQL schema DDL belongs exclusively to Alembic. This
        # compatibility index is retained only for legacy SQLite files.
        if engine.dialect.name == "sqlite":
            db.execute(text("CREATE UNIQUE INDEX IF NOT EXISTS uq_sbom_type_typename ON sbom_type(typename)"))

        # Seed the local development identity. Production HCL IAM users are
        # mapped from validated claims and explicit tenant memberships.
        from .models import IAMUser, Tenant, TenantUser

        now = datetime.now(UTC)
        tenant = db.get(Tenant, 1)
        if tenant is None:
            tenant = Tenant(
                id=1,
                name="Default Tenant",
                slug="default",
                external_iam_tenant_id="local-default",
                status="ACTIVE",
                created_at=now,
                updated_at=now,
            )
            db.add(tenant)
        user = db.get(IAMUser, 1)
        if user is None:
            user = IAMUser(
                id=1,
                external_iam_user_id="dev-user",
                email="dev@local",
                display_name="Dev User",
                status="ACTIVE",
                created_at=now,
                updated_at=now,
                last_login_at=now,
            )
            db.add(user)
        elif user.external_iam_user_id == "local-dev-admin":
            user.external_iam_user_id = "dev-user"
            user.email = user.email or "dev@local"
            user.display_name = user.display_name or "Dev User"
        db.flush()
        membership = db.execute(
            select(TenantUser).where(TenantUser.tenant_id == 1, TenantUser.user_id == 1)
        ).scalar_one_or_none()
        if membership is None:
            db.add(
                TenantUser(
                    tenant_id=1,
                    user_id=1,
                    role="TENANT_ADMIN",
                    status="ACTIVE",
                    created_at=now,
                    updated_at=now,
                )
            )
        elif membership.role == "PLATFORM_ADMIN" and not get_settings().auth_enabled:
            membership.role = "TENANT_ADMIN"
        db.commit()

        # Seed default SBOM types
        from .models import SBOMType

        existing = {(row.typename or "").strip().lower() for row in db.execute(select(SBOMType)).scalars().all()}
        seeds = []
        if "cyclonedx" not in existing:
            seeds.append(
                SBOMType(
                    typename="CycloneDX",
                    type_details="CycloneDX format",
                    created_on=now_iso(),
                    created_by="system",
                )
            )
        if "spdx" not in existing:
            seeds.append(
                SBOMType(
                    typename="SPDX",
                    type_details="SPDX format",
                    created_on=now_iso(),
                    created_by="system",
                )
            )
        if seeds:
            db.add_all(seeds)
            db.commit()

        backfill_analytics_tables(db)
        from .services.lifecycle.provider_config_service import LifecycleProviderConfigService

        LifecycleProviderConfigService().bootstrap_defaults(db)
        db.commit()
    finally:
        db.close()


def _verify_schema_is_current() -> None:
    """Verify that the database schema is current and not stale before starting the API."""
    from alembic.config import Config
    from alembic.script import ScriptDirectory
    from sqlalchemy import inspect

    try:
        inspector = inspect(engine)
        table_names = inspector.get_table_names()
    except Exception as exc:
        exc_str = str(exc)
        if (
            "password authentication failed" in exc_str
            or "authentication failed" in exc_str
            or "fe_sendauth" in exc_str
        ):
            import sys

            msg = "PostgreSQL authentication failed for user 'sbom'. Check DATABASE_URL password or reset the PostgreSQL user password."
            print(f"\nERROR: {msg}\n", file=sys.stderr)
            raise RuntimeError(msg) from None
        raise

    # If the database is completely empty, it's either SQLite waiting for create_all or Postgres waiting for migrations
    if not table_names:
        return

    # Check Alembic migrations status if alembic_version table exists
    if "alembic_version" in table_names:
        config = Config(str(Path(__file__).resolve().parent.parent / "alembic.ini"))
        expected_heads = set(ScriptDirectory.from_config(config).get_heads())
        try:
            with engine.connect() as conn:
                actual_heads = {str(row[0]) for row in conn.execute(text("SELECT version_num FROM alembic_version"))}
        except Exception as exc:
            exc_str = str(exc)
            if (
                "password authentication failed" in exc_str
                or "authentication failed" in exc_str
                or "fe_sendauth" in exc_str
            ):
                import sys

                msg = "PostgreSQL authentication failed for user 'sbom'. Check DATABASE_URL password or reset the PostgreSQL user password."
                print(f"\nERROR: {msg}\n", file=sys.stderr)
                raise RuntimeError(msg) from None
            raise RuntimeError(
                "Database schema is missing or unreadable; run 'alembic upgrade head' before starting the API."
            ) from exc
        if actual_heads != expected_heads:
            raise RuntimeError(
                "Database schema is not at Alembic head; run 'alembic upgrade head' before starting the API. "
                f"Expected {sorted(expected_heads)}, found {sorted(actual_heads)}."
            )
    else:
        # If alembic_version is missing but key tables exist, check for required columns
        if "sbom_source" in table_names:
            columns = [col["name"] for col in inspector.get_columns("sbom_source")]
            if "tenant_id" not in columns:
                raise RuntimeError("Database schema is not up to date. Run alembic upgrade head.")


def _update_sbom_names() -> None:
    """Backfill analysis_run.sbom_name from sbom_source for legacy rows."""
    with engine.begin() as conn:
        conn.execute(
            text(
                """
                UPDATE analysis_run
                SET sbom_name = (
                    SELECT sbom_name
                    FROM sbom_source
                    WHERE sbom_source.id = analysis_run.sbom_id
                )
                """
            )
        )


def _reconcile_zombie_ai_fix_batches() -> None:
    """Mark batches that were in-flight when the previous process exited
    as failed.

    The progress store is in-memory by default, so a restart loses every
    live progress envelope. Without this pass, the durable ``ai_fix_batch``
    row stays in (queued|pending|in_progress|paused_budget) forever,
    keeping the run-detail page's banner stuck on a worker that no longer
    exists.

    Threshold: 5 minutes since ``created_at``. Anything younger is
    plausibly a worker that's still booting; anything older has missed
    every realistic deadline (the inline-fallback path completes in
    seconds; even a slow paid batch finishes well inside 5 min).
    """
    from datetime import datetime, timedelta

    now = datetime.now(tz=UTC)
    threshold = (now - timedelta(minutes=5)).isoformat()
    with engine.begin() as conn:
        result = conn.execute(
            text(
                """
                UPDATE ai_fix_batch
                SET status = 'failed',
                    completed_at = :now,
                    last_error = 'interrupted — the server restarted before this batch finished; re-run to retry'
                WHERE status IN ('queued', 'pending', 'in_progress', 'paused_budget')
                  AND created_at < :threshold
                  AND completed_at IS NULL
                """
            ),
            {"now": now.isoformat(), "threshold": threshold},
        )
        if result.rowcount:
            log.info("ai.startup.reconciled_zombie_batches: count=%d", result.rowcount)


@asynccontextmanager
async def lifespan(app: FastAPI):
    # Re-apply logging config AFTER uvicorn has fully initialised. Uvicorn
    # runs `logging.config.dictConfig(LOGGING_CONFIG)` during its own
    # startup which replaces the root logger's handlers — without this
    # re-apply step, our formatter and rotating file handler would be lost
    # for the remainder of the process.
    setup_logging()
    await init_async_http_client()
    log.info("SBOM Analyzer starting up — initialising database …")

    # Securely log database details
    from sqlalchemy.engine import make_url

    try:
        url = make_url(engine.url)
        safe_host = f"{url.host or ''}:{url.port or ''}" if url.port else (url.host or "")
        log.info("Database dialect: %s", engine.dialect.name)
        log.info("Database URL host/db: %s/%s", safe_host, url.database or "")
    except Exception as e:
        log.error("Failed to parse database URL for logging: %s", e)

    _ensure_seed_data()
    _update_sbom_names()
    _reconcile_zombie_ai_fix_batches()
    validate_auth_setup()
    log.info("Startup complete. API ready.")
    yield
    await close_async_http_client()
    log.info("Async HTTP client closed.")


app = FastAPI(title="SBOM & Projects API", version=APP_VERSION, lifespan=lifespan)

app.state.limiter = limiter
app.add_exception_handler(RateLimitExceeded, rate_limit_exceeded_handler)

from fastapi.responses import JSONResponse
from sqlalchemy.exc import TimeoutError as SQLAlchemyTimeoutError


@app.exception_handler(SQLAlchemyTimeoutError)
async def sqlalchemy_timeout_exception_handler(request: Request, exc: SQLAlchemyTimeoutError):
    from .db import engine

    pool = engine.pool
    log.error(
        "Database connection pool checkout timeout occurred! "
        "Pool stats: size=%s, checked_in=%s, checked_out=%s, overflow=%s",
        getattr(pool, "size", lambda: "N/A")()
        if callable(getattr(pool, "size", None))
        else getattr(pool, "size", "N/A"),
        pool.checkedin() if hasattr(pool, "checkedin") else "N/A",
        pool.checkedout() if hasattr(pool, "checkedout") else "N/A",
        getattr(pool, "overflow", lambda: "N/A")()
        if callable(getattr(pool, "overflow", None))
        else getattr(pool, "overflow", "N/A"),
    )
    return JSONResponse(
        status_code=503,
        content={"detail": {"error_code": "DATABASE_BUSY", "message": "Database is busy. Please retry shortly."}},
    )


app.add_middleware(SlowAPIMiddleware)

app.add_middleware(
    CORSMiddleware,
    allow_origins=settings.cors_origins_list,
    allow_credentials=False,
    allow_methods=["*"],
    allow_headers=["*"],
)

app.add_middleware(GZipMiddleware, minimum_size=1000)

# --- Request / response logging middleware ------------------------------
_access_log = get_logger("access")


@app.middleware("http")
async def log_requests(request: Request, call_next):
    """Log every incoming request and its response status + duration."""
    t0 = time.perf_counter()
    _access_log.info(
        "→ %s %s  client=%s",
        request.method,
        request.url.path,
        request.client.host if request.client else "unknown",
    )
    try:
        response = await call_next(request)
    except Exception as exc:
        _access_log.error(
            "✗ %s %s  UNHANDLED %s: %s",
            request.method,
            request.url.path,
            type(exc).__name__,
            exc,
            exc_info=True,
        )
        raise
    duration_ms = int((time.perf_counter() - t0) * 1000)
    # Every completed request is logged at INFO; 4xx/5xx escalate to WARNING
    # so they remain visible even if operators run at WARNING-only in prod.
    level = logging.WARNING if response.status_code >= 400 else logging.INFO
    _access_log.log(
        level,
        "← %s %s  status=%d  %dms",
        request.method,
        request.url.path,
        response.status_code,
        duration_ms,
    )
    context = getattr(request.state, "current_context", None)
    audit_action = None
    if request.url.path == "/api/auth/me":
        audit_action = "auth.login_mapping"
    elif request.headers.get("X-Tenant-ID"):
        audit_action = "tenant.switch"
    elif request.method in {"POST", "PUT", "PATCH", "DELETE"}:
        audit_action = f"api.{request.method.lower()}"
    elif request.method == "GET" and any(value in request.url.path for value in ("/export", "/reports/")):
        audit_action = "export.download"
    if context is not None and audit_action and response.status_code < 400:
        try:
            from .core.context import tenant_scope
            from .models import AuditLog

            with tenant_scope(context), SessionLocal() as audit_db:
                audit_db.add(
                    AuditLog(
                        tenant_id=context.tenant_id,
                        user_id=context.external_user_id,
                        user_ref_id=context.user_id,
                        action=audit_action,
                        target_kind=request.url.path.split("/")[2] if request.url.path.count("/") >= 2 else "api",
                        detail=f"{request.method} {request.url.path}"[:240],
                        entity_type=request.url.path.split("/")[2] if request.url.path.count("/") >= 2 else "api",
                        entity_id=next(
                            (part for part in reversed(request.url.path.split("/")) if part.isdigit()),
                            None,
                        ),
                        ip_address=request.client.host if request.client else None,
                        user_agent=(request.headers.get("user-agent") or "")[:512] or None,
                        created_at=datetime.now(UTC).isoformat(),
                    )
                )
                audit_db.commit()
        except Exception:
            log.exception("security_audit_write_failed")
    return response


# --- Body-size enforcement (BE-001) -------------------------------------
# Added LAST so Starlette's `add_middleware` (insert-at-0) puts this
# OUTERMOST in the stack — oversize requests are rejected with 413
# before any other middleware spends cycles on them.
app.add_middleware(MaxBodySizeMiddleware, max_bytes=settings.MAX_UPLOAD_BYTES)

# --- Global exception handler (BE-002) ----------------------------------
# Converts unhandled exceptions into a canonical, non-leaky 500 envelope
# with a correlation_id linking the response to the server log line.
# HTTPException + RequestValidationError continue to use FastAPI's
# default handlers — we only intercept Exception.
error_handlers.install(app)


# --- Router registration -------------------------------------------------
# Routers already declare their own prefixes where appropriate, so we
# include them here without overriding.
#
# Finding A: every router below carries `dependencies=[Depends(require_auth)]`
# so the bearer-token check runs on every request before the route handler.
# `health.router` is the deliberate exception — it serves the unauthenticated
# `/`, `/health`, `/api/analysis/config`, and `/api/types` endpoints used by
# liveness probes and the FastAPI `/docs` page. When `API_AUTH_MODE=none`
# (the default) the dependency is a cheap no-op, so applying it everywhere
# costs essentially nothing in dev but makes production a one-env-var flip.

_protected = [Depends(enforce_request_access)]

app.include_router(health.router)  # intentionally unprotected
app.include_router(sbom_versions.router, dependencies=_protected)
app.include_router(sboms_crud.router, dependencies=_protected)
# New multipart upload route running the eight-stage validation pipeline.
# Path /api/sboms/upload — see ADR-0007.
app.include_router(sbom_upload.router, dependencies=_protected)
app.include_router(sbom_validation_sessions.router, dependencies=_protected)
app.include_router(sbom_validation_sessions.compat_router, dependencies=_protected)
app.include_router(runs.router, dependencies=_protected)
app.include_router(projects.router, dependencies=_protected)
app.include_router(analyze_endpoints.router, dependencies=_protected)
app.include_router(pdf.router, dependencies=_protected)
app.include_router(dashboard_main.router, dependencies=_protected)
app.include_router(dashboard_advanced.router, dependencies=_protected)
app.include_router(ai_copilot.router, dependencies=_protected)
app.include_router(schedules.router, dependencies=_protected)
app.include_router(cves.router, dependencies=_protected)
app.include_router(compare.router, dependencies=_protected)
app.include_router(ai_usage.router, dependencies=_protected)
app.include_router(ai_fixes.router, dependencies=_protected)
app.include_router(ai_credentials.router, dependencies=_protected)
app.include_router(lifecycle.router, dependencies=_protected)
app.include_router(lifecycle_admin.router, dependencies=_protected)
app.include_router(vex.router, dependencies=_protected)
app.include_router(remediation.router, dependencies=_protected)
app.include_router(tenants.router, dependencies=_protected)


# Feature routers (kept from earlier refactor) — additive paths.
app.include_router(
    analysis_export_router.router,
    prefix="/api/analysis-runs",
    tags=["analysis-export"],
    dependencies=_protected,
)
app.include_router(
    sbom_features_router.router,
    prefix="/api/sboms",
    tags=["sbom-features"],
    dependencies=_protected,
)
app.include_router(
    dashboard_trend_router.router,
    prefix="/dashboard",
    tags=["dashboard-trend"],
    dependencies=_protected,
)

# NVD mirror admin router. Auth via require_auth (binary none/bearer/jwt
# per app.auth). Admin-role split is a TODO (see app/nvd_mirror/api.py).
app.include_router(nvd_mirror_admin_router, dependencies=_protected)

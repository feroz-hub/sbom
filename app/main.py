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

from fastapi import Depends, FastAPI, Request
from fastapi.middleware.cors import CORSMiddleware
from slowapi.errors import RateLimitExceeded
from slowapi.middleware import SlowAPIMiddleware
from sqlalchemy import text
from starlette.middleware.gzip import GZipMiddleware

from .logger import get_logger, setup_logging

# Initialise logging FIRST so subsequent imports inherit the config.
setup_logging()
log = get_logger("api")

from . import error_handlers
from .auth import require_auth, validate_auth_setup
from .db import Base, SessionLocal, engine
from .http_client import close_async_http_client, init_async_http_client
from .middleware import MaxBodySizeMiddleware

# --- Routers --------------------------------------------------------------
from .nvd_mirror.api import router as nvd_mirror_admin_router
from .rate_limit import limiter, rate_limit_exceeded_handler
from .routers import (
    ai_credentials,
    ai_fixes,
    ai_usage,
    analyze_endpoints,
    compare,
    cves,
    dashboard_main,
    health,
    pdf,
    projects,
    runs,
    sbom_upload,
    sboms_crud,
    schedules,
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


def _ensure_seed_data() -> None:
    """Create tables, run lightweight migrations, seed reference data."""
    Base.metadata.create_all(bind=engine)

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
                text(
                    "UPDATE sbom_source SET status = 'pending' "
                    "WHERE validated_at IS NULL AND status = 'validated'"
                )
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

    db = SessionLocal()
    try:
        db.execute(text("CREATE UNIQUE INDEX IF NOT EXISTS uq_sbom_type_typename ON sbom_type(typename)"))

        # Seed default SBOM types
        from sqlalchemy import select

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
    finally:
        db.close()


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
    from datetime import datetime, timedelta, timezone

    now = datetime.now(tz=timezone.utc)
    threshold = (now - timedelta(minutes=5)).isoformat()
    with engine.begin() as conn:
        result = conn.execute(
            text(
                """
                UPDATE ai_fix_batch
                SET status = 'failed',
                    completed_at = :now,
                    last_error = 'reconciled at startup; previous process exited unexpectedly'
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

_protected = [Depends(require_auth)]

app.include_router(health.router)  # intentionally unprotected
app.include_router(sboms_crud.router, dependencies=_protected)
# New multipart upload route running the eight-stage validation pipeline.
# Path /api/sboms/upload — see ADR-0007.
app.include_router(sbom_upload.router, dependencies=_protected)
app.include_router(runs.router, dependencies=_protected)
app.include_router(projects.router, dependencies=_protected)
app.include_router(analyze_endpoints.router, dependencies=_protected)
app.include_router(pdf.router, dependencies=_protected)
app.include_router(dashboard_main.router, dependencies=_protected)
app.include_router(schedules.router, dependencies=_protected)
app.include_router(cves.router, dependencies=_protected)
app.include_router(compare.router, dependencies=_protected)
app.include_router(ai_usage.router, dependencies=_protected)
app.include_router(ai_fixes.router, dependencies=_protected)
app.include_router(ai_credentials.router, dependencies=_protected)

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

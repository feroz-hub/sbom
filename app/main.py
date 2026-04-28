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
from .rate_limit import limiter, rate_limit_exceeded_handler
from .routers import analysis as analysis_export_router

# --- Routers --------------------------------------------------------------
from .nvd_mirror.api import router as nvd_mirror_admin_router
from .routers import (
    analyze_endpoints,
    dashboard_main,
    health,
    pdf,
    projects,
    runs,
    sboms_crud,
)
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
app.include_router(runs.router, dependencies=_protected)
app.include_router(projects.router, dependencies=_protected)
app.include_router(analyze_endpoints.router, dependencies=_protected)
app.include_router(pdf.router, dependencies=_protected)
app.include_router(dashboard_main.router, dependencies=_protected)

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

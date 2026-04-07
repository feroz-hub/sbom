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
from typing import Optional

from fastapi import FastAPI, Request
from fastapi.middleware.cors import CORSMiddleware
from sqlalchemy import text

from .logger import setup_logging, get_logger

# Initialise logging FIRST so subsequent imports inherit the config.
setup_logging()
log = get_logger("api")

from .db import Base, SessionLocal, engine
from .settings import get_settings
from .services.analysis_service import backfill_analytics_tables
from .services.sbom_service import now_iso  # re-exported for tests/back-compat

# --- Routers --------------------------------------------------------------
from .routers import (
    health,
    sboms_crud,
    runs,
    projects,
    analyze_endpoints,
    pdf,
    dashboard_main,
)
from .routers import analysis as analysis_export_router
from .routers import sbom as sbom_features_router
from .routers import dashboard as dashboard_trend_router

# --- App construction ----------------------------------------------------
settings = get_settings()
APP_VERSION = settings.APP_VERSION

app = FastAPI(title="SBOM & Projects API", version=APP_VERSION)

app.add_middleware(
    CORSMiddleware,
    allow_origins=settings.cors_origins_list,
    allow_credentials=False,
    allow_methods=["*"],
    allow_headers=["*"],
)

# --- Request / response logging middleware ------------------------------
_access_log = get_logger("access")


@app.middleware("http")
async def log_requests(request: Request, call_next):
    """Log every incoming request and its response status + duration."""
    t0 = time.perf_counter()
    _access_log.debug(
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
    level = logging.WARNING if response.status_code >= 400 else logging.DEBUG
    _access_log.log(
        level,
        "← %s %s  status=%d  %dms",
        request.method,
        request.url.path,
        response.status_code,
        duration_ms,
    )
    return response


# --- DB schema migrations / seed ----------------------------------------
def _ensure_text_column(table_name: str, column_name: str) -> None:
    """Idempotent ALTER TABLE … ADD COLUMN for SQLite text columns."""
    with engine.connect() as conn:
        existing = {
            row[1]
            for row in conn.execute(text(f"PRAGMA table_info({table_name})"))
        }
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
        db.execute(
            text(
                "CREATE UNIQUE INDEX IF NOT EXISTS uq_sbom_type_typename "
                "ON sbom_type(typename)"
            )
        )

        # Seed default SBOM types
        from sqlalchemy import select
        from .models import SBOMType

        existing = {
            (row.typename or "").strip().lower()
            for row in db.execute(select(SBOMType)).scalars().all()
        }
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


@app.on_event("startup")
def on_startup() -> None:
    log.info("SBOM Analyzer starting up — initialising database …")
    _ensure_seed_data()
    _update_sbom_names()
    log.info("Startup complete. API ready.")


# --- Router registration -------------------------------------------------
# Routers already declare their own prefixes where appropriate, so we
# include them here without overriding.

app.include_router(health.router)
app.include_router(sboms_crud.router)
app.include_router(runs.router)
app.include_router(projects.router)
app.include_router(analyze_endpoints.router)
app.include_router(pdf.router)
app.include_router(dashboard_main.router)

# Feature routers (kept from earlier refactor) — additive paths.
app.include_router(
    analysis_export_router.router,
    prefix="/api/analysis-runs",
    tags=["analysis-export"],
)
app.include_router(
    sbom_features_router.router,
    prefix="/api/sboms",
    tags=["sbom-features"],
)
app.include_router(
    dashboard_trend_router.router,
    prefix="/dashboard",
    tags=["dashboard-trend"],
)

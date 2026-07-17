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
from sqlalchemy import MetaData, Table, func, select, update
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
    kev,
    lifecycle,
    lifecycle_admin,
    pdf,
    products,
    projects,
    remediation,
    reports,
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
from .services.analysis_service import backfill_analytics_tables, reconcile_stale_analysis_runs
from .services.sbom_service import now_iso  # re-exported for tests/back-compat
from .settings import get_settings

# --- App construction ----------------------------------------------------
settings = get_settings()
APP_VERSION = settings.APP_VERSION


def _sync_postgres_sequence(db, table_name: str, column_name: str) -> None:
    """Keep PostgreSQL sequences aligned after startup seeds explicit ids."""
    if engine.dialect.name != "postgresql":
        return
    from .models import IAMUser, Tenant

    allowed_columns = {
        ("tenants", "id"): Tenant.id,
        ("iam_users", "id"): IAMUser.id,
    }
    model_column = allowed_columns.get((table_name, column_name))
    if model_column is None:
        raise RuntimeError("Unsupported PostgreSQL sequence target")

    sequence = db.execute(
        select(func.pg_get_serial_sequence(table_name, column_name)),
    ).scalar()
    if not sequence:
        return
    max_value = int(db.execute(select(func.coalesce(func.max(model_column), 0))).scalar_one() or 0)
    db.execute(
        select(func.setval(func.to_regclass(sequence), max(max_value, 1), max_value > 0)),
    )


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

    db = SessionLocal()
    try:
        # Seed the local development identity. Production HCL IAM users are
        # mapped from validated claims and explicit tenant memberships.
        from .models import IAMUser, SBOMSource, Tenant, TenantUser

        now = datetime.now(UTC)
        db.execute(
            update(SBOMSource)
            .where(SBOMSource.validated_at.is_(None), SBOMSource.status == "validated")
            .values(status="pending")
        )
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
        _sync_postgres_sequence(db, "tenants", "id")
        _sync_postgres_sequence(db, "iam_users", "id")
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
            alembic_version = Table("alembic_version", MetaData(), autoload_with=engine)
            with engine.connect() as conn:
                actual_heads = {str(row[0]) for row in conn.execute(select(alembic_version.c.version_num))}
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
    from .models import AnalysisRun, SBOMSource

    sbom_name = select(SBOMSource.sbom_name).where(SBOMSource.id == AnalysisRun.sbom_id).scalar_subquery()
    with SessionLocal() as db:
        db.execute(
            update(AnalysisRun)
            .where(AnalysisRun.sbom_name.is_(None))
            .values(sbom_name=sbom_name)
        )
        db.commit()


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
    from .models import AiFixBatch

    with SessionLocal() as db:
        result = db.execute(
            update(AiFixBatch)
            .where(
                AiFixBatch.status.in_(("queued", "pending", "in_progress", "paused_budget")),
                AiFixBatch.created_at < threshold,
                AiFixBatch.completed_at.is_(None),
            )
            .values(
                status="failed",
                completed_at=now.isoformat(),
                last_error="interrupted - the server restarted before this batch finished; re-run to retry",
            )
        )
        db.commit()
        if result.rowcount:
            log.info("ai.startup.reconciled_zombie_batches: count=%d", result.rowcount)


def _reconcile_stale_analysis_runs() -> None:
    """Mark old in-process analysis runs interrupted after an API restart."""
    with SessionLocal() as db:
        interrupted = reconcile_stale_analysis_runs(db)
        if interrupted:
            db.commit()
            log.info("analysis.startup.reconciled_stale_runs: count=%d", len(interrupted))
        else:
            db.rollback()


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
    _reconcile_stale_analysis_runs()
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
app.include_router(sbom_validation_sessions.workspace_router, dependencies=_protected)
app.include_router(runs.router, dependencies=_protected)
app.include_router(projects.router, dependencies=_protected)
app.include_router(products.router, dependencies=_protected)
app.include_router(reports.router, dependencies=_protected)
app.include_router(analyze_endpoints.router, dependencies=_protected)
app.include_router(pdf.router, dependencies=_protected)
app.include_router(dashboard_main.router, dependencies=_protected)
app.include_router(dashboard_advanced.router, dependencies=_protected)
app.include_router(ai_copilot.router, dependencies=_protected)
app.include_router(schedules.router, dependencies=_protected)
app.include_router(cves.router, dependencies=_protected)
app.include_router(kev.router, dependencies=_protected)
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

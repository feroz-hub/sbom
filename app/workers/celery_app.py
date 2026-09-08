"""Celery application — independently resolved broker and result backend.

Tasks live in:
  * ``app.nvd_mirror.tasks``           — NVD mirror (mirror_nvd)
  * ``app.workers.scheduled_analysis`` — periodic SBOM rescans
                                          (tick + per-SBOM worker)
  * ``app.workers.kev_sync``           — daily CISA KEV catalog sync

Beat schedule:
  * ``nvd-mirror-hourly`` — fires ``mirror_nvd`` at minute 15 every hour.
  * ``analysis-schedule-tick`` — fires every 15 minutes; reads the
    analysis_schedule table and enqueues per-SBOM analyze tasks for any
    rows whose next_run_at has passed.
  * ``kev-sync-daily`` — refreshes the local ``kev_vulnerabilities`` table
    every 24 hours.

Beat must run as a SINGLE instance (deploy as its own process).
"""

from __future__ import annotations

import asyncio
import logging

from celery import Celery
from celery.schedules import crontab
from celery.signals import worker_process_init, worker_process_shutdown, worker_ready, worker_shutdown

log = logging.getLogger(__name__)


def _broker_url() -> str:
    from app.settings import get_settings

    s = get_settings()
    if s.celery_use_database_broker:
        database_url = (s.database_url or "").strip()
        if not database_url:
            raise RuntimeError(
                "CELERY_USE_DATABASE_BROKER is enabled, but DATABASE_URL is not configured."
            )
        if database_url.startswith("db+"):
            database_url = database_url.removeprefix("db+")
        return f"sqla+{database_url}"

    b = (s.celery_broker_url or "").strip()
    return b or s.redis_url


def _result_backend() -> str:
    """Return a backend URL compatible with the selected broker transport.

    Redis URLs work as both broker and result backend. Kombu's SQLAlchemy
    transport is different: ``sqla+...`` is a broker-only scheme, while
    Celery's database result backend requires ``db+...``. Keep an explicit
    override for other broker/backend combinations.
    """
    from app.settings import get_settings

    s = get_settings()
    configured = (s.celery_result_backend or "").strip()
    if configured:
        return configured

    broker = _broker_url()
    for prefix in ("sqla+", "sqlalchemy+"):
        if broker.startswith(prefix):
            return f"db+{broker.removeprefix(prefix)}"
    return broker


celery_app = Celery(
    "sbom_analyzer",
    broker=_broker_url(),
    backend=_result_backend(),
    include=[
        "app.nvd_mirror.tasks",
        "app.workers.scheduled_analysis",
        "app.workers.cve_refresh",
        "app.workers.ai_fix_tasks",
        "app.workers.source_cache",
        "app.workers.kev_sync",
        "app.workers.report_notifications",
    ],
)

celery_app.conf.update(
    task_serializer="json",
    accept_content=["json"],
    result_serializer="json",
    timezone="UTC",
    enable_utc=True,
    task_track_started=True,
    task_routes={"report_notifications.*": {"queue": "reports"}},
)

celery_app.conf.beat_schedule = {
    "report-notifications-hourly": {"task": "report_notifications.tick", "schedule": crontab(minute=50)},
    "report-notifications-outbox": {"task": "report_notifications.dispatch_pending", "schedule": crontab(minute="*")},
    "report-notifications-retention": {"task": "report_notifications.purge", "schedule": crontab(minute=50, hour=4)},
    "nvd-mirror-hourly": {
        "task": "nvd_mirror.mirror_nvd",
        "schedule": crontab(minute=15),
    },
    "analysis-schedule-tick": {
        "task": "scheduled_analysis.tick",
        # Every 15 minutes — granularity of how soon a "due" schedule
        # actually fires after its next_run_at passes. Tighter = more
        # responsive but more idle DB scans; 15 min is the sweet spot.
        "schedule": crontab(minute="*/15"),
    },
    "kev-sync-daily": {
        # Every 24 hours — CISA's KEV catalog changes at human cadence,
        # and findings enrichment reads from the local table.
        "task": "kev.sync",
        "schedule": crontab(minute=10, hour=3),
    },
    "cve-cache-purge": {
        # Daily — drop rows whose expires_at is more than 24 h in the past.
        "task": "cve_refresh.purge_expired",
        "schedule": crontab(minute=30, hour=3),
    },
    "source-cache-sweep": {
        # Roadmap #2 PR-E — daily housekeeping of source_response_cache.
        # TTL is 4 h by default so expired rows are typically a single
        # day's worth at sweep time; one bounded batch (10k rows)
        # comfortably handles steady state. 03:45 is offset from the
        # cve-cache-purge slot at 03:30 so the two DELETE jobs don't
        # co-fire and amplify lock contention.
        "task": "source_cache.sweep_expired",
        "schedule": crontab(minute=45, hour=3),
    },
}


def _run_http_client_lifecycle(coro) -> None:
    try:
        asyncio.run(coro)
    except Exception:
        log.exception("celery_http_client_lifecycle_failed")
        raise


def _init_worker_http_client(**_: object) -> None:
    from app.http_client import init_async_http_client

    _run_http_client_lifecycle(init_async_http_client())
    log.info("celery_async_http_client_ready")


def _close_worker_http_client(**_: object) -> None:
    from app.http_client import close_async_http_client

    _run_http_client_lifecycle(close_async_http_client())
    log.info("celery_async_http_client_closed")


worker_process_init.connect(_init_worker_http_client, weak=False)
worker_ready.connect(_init_worker_http_client, weak=False)
worker_process_shutdown.connect(_close_worker_http_client, weak=False)
worker_shutdown.connect(_close_worker_http_client, weak=False)

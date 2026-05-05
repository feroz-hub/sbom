"""Celery application — broker/backend from settings (Redis).

Tasks live in:
  * ``app.nvd_mirror.tasks``           — NVD mirror (mirror_nvd)
  * ``app.workers.scheduled_analysis`` — periodic SBOM rescans
                                          (tick + per-SBOM worker)

Beat schedule:
  * ``nvd-mirror-hourly`` — fires ``mirror_nvd`` at minute 15 every hour.
  * ``analysis-schedule-tick`` — fires every 15 minutes; reads the
    analysis_schedule table and enqueues per-SBOM analyze tasks for any
    rows whose next_run_at has passed.

Beat must run as a SINGLE instance (deploy as its own process).
"""

from __future__ import annotations

from celery import Celery
from celery.schedules import crontab


def _broker_url() -> str:
    from app.settings import get_settings

    s = get_settings()
    b = (s.celery_broker_url or "").strip()
    return b or s.redis_url


celery_app = Celery(
    "sbom_analyzer",
    broker=_broker_url(),
    backend=_broker_url(),
    include=[
        "app.nvd_mirror.tasks",
        "app.workers.scheduled_analysis",
        "app.workers.cve_refresh",
        "app.workers.ai_fix_tasks",
    ],
)

celery_app.conf.update(
    task_serializer="json",
    accept_content=["json"],
    result_serializer="json",
    timezone="UTC",
    enable_utc=True,
    task_track_started=True,
)

celery_app.conf.beat_schedule = {
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
    # CVE detail modal cache hygiene
    "cve-refresh-kev": {
        # Every 6 hours — KEV catalog updates infrequently (a few entries
        # a week) so 6h keeps "Actively exploited" badges current without
        # spamming CISA's CDN.
        "task": "cve_refresh.refresh_kev_cache",
        "schedule": crontab(minute=10, hour="*/6"),
    },
    "cve-cache-purge": {
        # Daily — drop rows whose expires_at is more than 24 h in the past.
        "task": "cve_refresh.purge_expired",
        "schedule": crontab(minute=30, hour=3),
    },
}

"""Celery application — broker/backend from settings (Redis).

Tasks live in:
  * ``app.workers.tasks``      — SBOM analysis (run_sbom_analysis)
  * ``app.nvd_mirror.tasks``   — NVD mirror (mirror_nvd)

Beat schedule:
  * ``nvd-mirror-hourly`` — fires ``mirror_nvd`` at minute 15 every hour.
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
    include=["app.workers.tasks", "app.nvd_mirror.tasks"],
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
}

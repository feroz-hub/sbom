"""Celery application — broker/backend from settings (Redis)."""

from __future__ import annotations

from celery import Celery


def _broker_url() -> str:
    from app.settings import get_settings

    s = get_settings()
    b = (s.celery_broker_url or "").strip()
    return b or s.redis_url


celery_app = Celery(
    "sbom_analyzer",
    broker=_broker_url(),
    backend=_broker_url(),
    include=["app.workers.tasks"],
)

celery_app.conf.update(
    task_serializer="json",
    accept_content=["json"],
    result_serializer="json",
    timezone="UTC",
    enable_utc=True,
    task_track_started=True,
)

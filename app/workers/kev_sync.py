"""Scheduled CISA KEV catalog synchronization.

Celery Beat runs this task daily so the local ``kev_vulnerabilities`` table
stays fresh without depending on a user opening a CVE detail page or manually
calling the API endpoint.
"""

from __future__ import annotations

import logging
from typing import Any

from celery import shared_task
from sqlalchemy.orm import Session

log = logging.getLogger(__name__)


@shared_task(name="kev.sync", bind=True, ignore_result=True)
def sync_kev_catalog(
    self,
    *,
    since: str | None = None,
    prune_stale: bool = True,
) -> dict[str, Any]:
    """Download and upsert the CISA KEV feed into the existing database."""
    from app.db import SessionLocal
    from app.services.kev_service import sync_kev
    from app.settings import get_settings

    settings = get_settings()
    effective_since = since if since is not None else (settings.kev_since_date or None)
    db: Session = SessionLocal()
    try:
        result = sync_kev(db, since=effective_since, prune_stale=prune_stale, commit=True)
        log.info(
            "kev_sync_done",
            extra={
                "upserted": result.get("upserted"),
                "total_in_feed": result.get("total_in_feed"),
                "filtered_since": result.get("filtered_since"),
                "duration_seconds": result.get("duration_seconds"),
            },
        )
        return {"ok": True, **result}
    except Exception as exc:
        db.rollback()
        log.exception("kev_sync_failed")
        return {"ok": False, "error": str(exc)}
    finally:
        db.close()


__all__ = ["sync_kev_catalog"]

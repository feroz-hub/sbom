"""
CVE-cache maintenance Celery tasks.

Two jobs:

    refresh_kev_cache  — compatibility wrapper for the dedicated
        ``kev.sync`` task. Beat now schedules ``kev.sync`` directly every
        24 hours.

    purge_expired_cve_cache — fired daily. Deletes ``cve_cache`` rows whose
        ``expires_at`` has passed by more than 24 h. The service layer is
        a TTL-aware reader (it ignores expired rows) so this is bookkeeping
        only — keeps the table from growing unbounded.

Both tasks are best-effort; transient failures log + return rather than
retrying. The service path doesn't depend on either task succeeding.
"""

from __future__ import annotations

import logging
from datetime import UTC, datetime, timedelta

from celery import shared_task
from sqlalchemy import delete
from sqlalchemy.orm import Session

from ..models import CveCache

log = logging.getLogger(__name__)


@shared_task(name="cve_refresh.refresh_kev_cache", bind=True, ignore_result=True)
def refresh_kev_cache(self) -> dict:
    """Compatibility task for callers still using the old task name."""
    from app.workers.kev_sync import sync_kev_catalog

    result = sync_kev_catalog(since=None, prune_stale=True)
    return {"refreshed": bool(result.get("ok")), **result}


@shared_task(name="cve_refresh.purge_expired", bind=True, ignore_result=True)
def purge_expired_cve_cache(self) -> dict:
    """Delete ``cve_cache`` rows expired more than 24 h ago."""
    from app.db import SessionLocal

    cutoff = (datetime.now(UTC) - timedelta(hours=24)).isoformat()
    db: Session = SessionLocal()
    try:
        result = db.execute(delete(CveCache).where(CveCache.expires_at < cutoff))
        db.commit()
        deleted = int(result.rowcount or 0)
        log.info("cve_refresh_purge_done", extra={"deleted": deleted})
        return {"deleted": deleted}
    except Exception:
        db.rollback()
        log.exception("cve_refresh_purge_failed")
        return {"deleted": 0, "error": True}
    finally:
        db.close()

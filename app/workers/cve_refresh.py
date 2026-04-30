"""
CVE-cache maintenance Celery tasks.

Two jobs:

    refresh_kev_cache  — fired by Beat every 6 hours. Forces a refresh of
        the local ``kev_entry`` mirror so KEV-listed status reflects CISA's
        latest catalog without waiting for the next cold modal open.

    purge_expired_cve_cache — fired daily. Deletes ``cve_cache`` rows whose
        ``expires_at`` has passed by more than 24 h. The service layer is
        a TTL-aware reader (it ignores expired rows) so this is bookkeeping
        only — keeps the table from growing unbounded.

Both tasks are best-effort; transient failures log + return rather than
retrying. The service path doesn't depend on either task succeeding.
"""

from __future__ import annotations

import logging
from datetime import datetime, timedelta, timezone

from celery import shared_task
from sqlalchemy import delete
from sqlalchemy.orm import Session

from ..models import CveCache
from ..sources.kev import refresh_if_stale

log = logging.getLogger(__name__)


@shared_task(name="cve_refresh.refresh_kev_cache", bind=True, ignore_result=True)
def refresh_kev_cache(self) -> dict:
    """Force-refresh the KEV mirror. Safe to fail; KEV adapter falls back."""
    from app.db import SessionLocal

    db: Session = SessionLocal()
    try:
        changed = refresh_if_stale(db, force=True)
        log.info("cve_refresh_kev_done", extra={"refreshed": changed})
        return {"refreshed": changed}
    except Exception:
        log.exception("cve_refresh_kev_failed")
        return {"refreshed": False, "error": True}
    finally:
        db.close()


@shared_task(name="cve_refresh.purge_expired", bind=True, ignore_result=True)
def purge_expired_cve_cache(self) -> dict:
    """Delete ``cve_cache`` rows expired more than 24 h ago."""
    from app.db import SessionLocal

    cutoff = (datetime.now(timezone.utc) - timedelta(hours=24)).isoformat()
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

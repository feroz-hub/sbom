"""Periodic source-response-cache housekeeping (roadmap #2, PR-E).

A single Celery beat task that deletes expired rows from
``source_response_cache``. Pure housekeeping — readers already treat
expired rows as a miss (see
``SourceResponseCacheRepository.get`` in ``app.services.source_response_cache``),
so this only reclaims table space; no correctness dependency.

Frequency
---------
Daily at 03:45 UTC (offset from the existing ``cve-cache-purge`` at
03:30 to avoid co-firing DB load). TTL is 4 hours by default — daily
keeps the table compact without paying frequent DELETE overhead.
Empty-cache or disabled-cache deployments → safe no-op.
"""

from __future__ import annotations

import logging
from typing import Any

from celery import shared_task

log = logging.getLogger(__name__)


# Batch size mirrors the cve_cache.purge default. One bounded batch per
# task firing; daily cadence + 4h TTL means steady-state stays well
# below this ceiling in any realistic deployment.
_DEFAULT_BATCH_SIZE: int = 10_000


@shared_task(
    name="source_cache.sweep_expired",
    bind=True,
    ignore_result=True,
)
def sweep_expired(self, *, batch_size: int = _DEFAULT_BATCH_SIZE) -> dict[str, Any]:
    """Delete expired rows from ``source_response_cache``.

    Returns ``{"deleted": int, "batch_size": int}`` for telemetry.
    Storage failures inside the repository are caught + logged there
    and surface here as a 0-deleted result rather than a raised
    exception — beat keeps firing even if a single sweep aborts.
    """
    from app.db import SessionLocal
    from app.services.source_response_cache import (
        SourceResponseCacheRepository,
    )

    session = SessionLocal()
    try:
        repo = SourceResponseCacheRepository(session)
        deleted = repo.delete_expired(batch_size=batch_size)
        log.info(
            "source_cache_sweep_done",
            extra={"deleted": deleted, "batch_size": batch_size},
        )
        return {"deleted": deleted, "batch_size": batch_size}
    except Exception as exc:
        log.warning(
            "source_cache_sweep_failed",
            extra={"error": str(exc)},
        )
        session.rollback()
        return {"deleted": 0, "batch_size": batch_size}
    finally:
        session.close()


__all__ = ["sweep_expired"]

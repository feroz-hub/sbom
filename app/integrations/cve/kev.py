"""
KEV source adapter.

Reads from the local ``kev_entry`` table only — *never* live. The KEV feed
itself is refreshed by a Celery beat task (see ``app.workers.cve_refresh``).
This adapter is async-by-signature to fit the ``CveSource`` Protocol; in
practice the work is a single indexed SELECT, so we don't bother with a
thread-pool offload.
"""

from __future__ import annotations

import logging
import time
from typing import Any, ClassVar

from sqlalchemy import select
from sqlalchemy.orm import Session

from ...models import KevEntry
from .base import FetchOutcome, FetchResult
from .identifiers import IdKind

log = logging.getLogger("sbom.integrations.cve.kev")


class KevSource:
    """Read-only KEV adapter — single SELECT against the cached mirror."""

    name = "kev"
    accepted_kinds: ClassVar[frozenset[IdKind]] = frozenset({IdKind.CVE})

    def __init__(self, db: Session) -> None:
        self._db = db

    async def fetch(self, cve_id: str) -> FetchResult:
        # KEV is keyed by CVE only — the aggregator filters by accepted_kinds
        # so callers should never reach here with a non-CVE id. Defensive
        # guard for direct-call misuse.
        if not cve_id.upper().startswith("CVE-"):
            return FetchResult(source=self.name, outcome=FetchOutcome.NOT_FOUND)
        t0 = time.perf_counter()
        row = self._db.execute(select(KevEntry).where(KevEntry.cve_id == cve_id)).scalars().first()
        latency_ms = int((time.perf_counter() - t0) * 1000)
        if row is None:
            return FetchResult(source=self.name, outcome=FetchOutcome.NOT_FOUND, latency_ms=latency_ms)
        data: dict[str, Any] = {
            "listed": True,
            "due_date": row.due_date,
            "vulnerability_name": row.vulnerability_name,
            "short_description": row.short_description,
        }
        return FetchResult(source=self.name, outcome=FetchOutcome.OK, data=data, latency_ms=latency_ms)

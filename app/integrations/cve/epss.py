"""
EPSS source adapter.

Wraps the existing sync ``app.sources.epss.get_epss_scores`` (which already
handles cache-read + refresh-on-stale) for use in the async aggregator.
We call the sync function directly — for a single CVE the work is a
single indexed lookup plus, at most, one outbound HTTP call (already
batched in the helper). Wrapping it in ``run_in_executor`` would only add
overhead.
"""

from __future__ import annotations

import logging
import time
from typing import Any, ClassVar

from sqlalchemy import select
from sqlalchemy.orm import Session

from ...models import EpssScore
from ...sources.epss import get_epss_scores
from .base import FetchOutcome, FetchResult
from .identifiers import IdKind

log = logging.getLogger("sbom.integrations.cve.epss")


class EpssSource:
    """Read-or-refresh EPSS adapter; reads percentile from the cache row."""

    name = "epss"
    accepted_kinds: ClassVar[frozenset[IdKind]] = frozenset({IdKind.CVE})

    def __init__(self, db: Session) -> None:
        self._db = db

    async def fetch(self, cve_id: str) -> FetchResult:
        # EPSS is keyed by CVE only — the aggregator filters by accepted_kinds
        # so callers should never reach here with a non-CVE id. Defensive
        # guard for direct-call misuse.
        if not cve_id.upper().startswith("CVE-"):
            return FetchResult(source=self.name, outcome=FetchOutcome.NOT_FOUND)
        t0 = time.perf_counter()
        # Side-effect: refreshes the row if stale (existing helper logic).
        scores = get_epss_scores(self._db, [cve_id])
        score = scores.get(cve_id, 0.0)
        # Pull the percentile out of the (possibly just-refreshed) row.
        row = self._db.execute(
            select(EpssScore.percentile).where(EpssScore.cve_id == cve_id)
        ).scalars().first()
        latency_ms = int((time.perf_counter() - t0) * 1000)
        if score == 0.0 and row is None:
            return FetchResult(source=self.name, outcome=FetchOutcome.NOT_FOUND, latency_ms=latency_ms)
        data: dict[str, Any] = {"score": float(score), "percentile": float(row) if row is not None else None}
        return FetchResult(source=self.name, outcome=FetchOutcome.OK, data=data, latency_ms=latency_ms)

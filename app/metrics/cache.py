"""In-process TTL cache keyed on a cheap invalidation tuple.

The lifetime tile already uses this pattern; this module generalises it so
``findings.daily_distinct_active`` and ``findings.net_change`` can reuse it.

Spec §6 caps any metric driving headline copy at 1h TTL — stale numbers are
themselves an inconsistency.
"""

from __future__ import annotations

import threading
import time
from typing import Any, Callable, TypeVar

from sqlalchemy import func, select
from sqlalchemy.orm import Session

from ..models import AnalysisRun, SBOMSource

T = TypeVar("T")

_cache: dict[tuple, tuple[float, Any]] = {}
_cache_lock = threading.Lock()
_MAX_ENTRIES = 256  # bounded so a runaway test session doesn't grow forever


def invalidation_key(db: Session) -> tuple[int, int, int]:
    """Cheap O(1) invalidation tuple — any new run / SBOM bumps it.

    ``(max(analysis_run.id), count(analysis_run), count(sbom_source))``.
    Kept identical to the existing lifetime cache key so the two pools
    converge if we ever consolidate.
    """
    max_run_id = db.execute(select(func.max(AnalysisRun.id))).scalar() or 0
    run_count = db.execute(select(func.count(AnalysisRun.id))).scalar() or 0
    sbom_count = db.execute(select(func.count(SBOMSource.id))).scalar() or 0
    return (int(max_run_id), int(run_count), int(sbom_count))


def memoize_with_ttl(
    *,
    name: str,
    ttl_seconds: float,
    db: Session,
    key_extra: tuple = (),
    compute: Callable[[], T],
) -> T:
    """Look up ``(name, invalidation_key, *key_extra)`` in the cache.

    On miss, calls ``compute()`` and stores the result. Bounded to
    ``_MAX_ENTRIES``; oldest entry evicted on overflow.
    """
    inv = invalidation_key(db)
    key = (name, inv, *key_extra)
    now = time.time()
    with _cache_lock:
        cached = _cache.get(key)
        if cached is not None and (now - cached[0]) < ttl_seconds:
            return cached[1]
    value = compute()
    with _cache_lock:
        _cache[key] = (now, value)
        if len(_cache) > _MAX_ENTRIES:
            oldest = min(_cache, key=lambda k: _cache[k][0])
            _cache.pop(oldest, None)
    return value


def reset_cache() -> None:
    """Test seam — clear the cache. Production never calls this."""
    with _cache_lock:
        _cache.clear()


__all__ = ["invalidation_key", "memoize_with_ttl", "reset_cache"]

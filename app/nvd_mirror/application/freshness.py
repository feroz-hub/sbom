"""Pure freshness computation — no I/O, no ports."""

from __future__ import annotations

from datetime import datetime

from ..domain.models import FreshnessVerdict, NvdSettingsSnapshot


def compute_freshness(snapshot: NvdSettingsSnapshot, now: datetime) -> FreshnessVerdict:
    """Decide whether the mirror's data is fresh enough to trust.

    Returns ``is_fresh=False`` when:
      * The mirror has never run successfully (``last_successful_sync_at`` is ``None``).
      * The most recent success is older than ``min_freshness_hours``.
    """
    last = snapshot.last_successful_sync_at
    if last is None:
        return FreshnessVerdict(is_fresh=False, age_hours=None, last_successful_sync_at=None)

    age_seconds = (now - last).total_seconds()
    age_hours = age_seconds / 3600.0
    is_fresh = age_hours <= snapshot.min_freshness_hours
    return FreshnessVerdict(
        is_fresh=is_fresh,
        age_hours=age_hours,
        last_successful_sync_at=last,
    )

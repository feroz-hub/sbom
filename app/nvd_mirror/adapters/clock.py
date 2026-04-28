"""System clock adapter — wraps ``datetime.now(tz=UTC)``.

Tests inject a ``FixedClock(now)`` that satisfies ``ClockPort``.
"""

from __future__ import annotations

from datetime import datetime, timezone


class SystemClockAdapter:
    """ClockPort impl returning the live UTC time."""

    def now(self) -> datetime:
        return datetime.now(tz=timezone.utc)

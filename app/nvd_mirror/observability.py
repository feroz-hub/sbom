"""In-process counters for the NVD mirror.

The repo doesn't carry a metrics library, so we implement a tiny named-counter
registry that lives in the process memory and serialises to JSON for the
``/health`` endpoint. It's a stand-in — when an actual metrics module is
introduced, swap the calls one-for-one.

Counter names follow ``nvd.<area>.<event>`` (dot-separated, lowercase).
Threadsafe: ``threading.Lock`` guards every read/write so concurrent fan-out
from the analyzer's multi-source orchestrator can't lose increments.

Standard names emitted by this codebase:

  * ``nvd.windows.success``      — bootstrap/incremental windows fully written
  * ``nvd.windows.failure``      — windows that aborted with an error
  * ``nvd.cves.upserted``        — total CveRow upserts attempted
  * ``nvd.live_fallbacks``       — facade fell through to the live API
  * ``nvd.api.429_count``        — NVD HTTP adapter saw a 429 status
"""

from __future__ import annotations

import logging
import threading
from collections import Counter as _Counter

log = logging.getLogger(__name__)


class Counters:
    """Threadsafe named-counter registry."""

    def __init__(self) -> None:
        self._counts: _Counter[str] = _Counter()
        self._lock = threading.Lock()

    def increment(self, name: str, value: int = 1) -> None:
        if value <= 0:
            return
        with self._lock:
            self._counts[name] += value

    def snapshot(self) -> dict[str, int]:
        with self._lock:
            return dict(self._counts)

    def reset(self) -> None:
        """Reset all counters to zero. Intended for tests."""
        with self._lock:
            self._counts.clear()


# Process-global singleton. Imported by the use cases, adapters, and the
# /health router.
mirror_counters: Counters = Counters()


def increment(name: str, value: int = 1) -> None:
    """Module-level shorthand: ``observability.increment("nvd.api.429_count")``."""
    mirror_counters.increment(name, value)


__all__ = ["Counters", "mirror_counters", "increment"]

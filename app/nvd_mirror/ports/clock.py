"""Clock port — exists so use cases can be tested with a fixed time."""

from __future__ import annotations

from datetime import datetime
from typing import Protocol


class ClockPort(Protocol):
    """Returns the current tz-aware UTC datetime."""

    def now(self) -> datetime: ...

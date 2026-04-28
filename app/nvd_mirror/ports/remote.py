"""Remote port — abstraction over the live NVD API or any future feed source."""

from __future__ import annotations

from collections.abc import AsyncIterator
from typing import Protocol

from ..domain.models import CveBatch, MirrorWindow


class NvdRemotePort(Protocol):
    """Yields one ``CveBatch`` per HTTP page for a given lastModified window.

    Implementations MUST:
      * Accept windows up to 119 days; reject wider ones.
      * Honour rate limits.
      * Retry transient 429/503 with backoff.
      * Be safe to call multiple times concurrently against different
        windows (no shared mutable state).
    """

    def fetch_window(
        self, window: MirrorWindow, *, page_size: int
    ) -> AsyncIterator[CveBatch]: ...

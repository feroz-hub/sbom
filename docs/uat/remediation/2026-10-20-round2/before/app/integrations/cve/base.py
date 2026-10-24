"""
Common types for the CVE detail enrichment sources.

Every source returns a :class:`FetchResult` whether it succeeded, soft-failed
(timeout / 5xx / malformed JSON), or was short-circuited by an open circuit
breaker. The aggregator inspects ``outcome`` to decide whether to merge the
payload and whether to flag the final result as ``is_partial``.
"""

from __future__ import annotations

import logging
import time
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, ClassVar, Protocol

from .identifiers import IdKind

log = logging.getLogger("sbom.integrations.cve")


class FetchOutcome(str, Enum):
    """Why a source returned what it did."""

    OK = "ok"  # data present
    NOT_FOUND = "not_found"  # upstream returned 404 / empty for this CVE
    ERROR = "error"  # transient: timeout, 5xx, bad JSON. Will be retried later.
    CIRCUIT_OPEN = "circuit_open"  # short-circuited; do not count against partial flag uniquely
    DISABLED = "disabled"  # source not enabled in settings


@dataclass(frozen=True)
class FetchResult:
    """The output of a single source fetch for a single CVE."""

    source: str
    outcome: FetchOutcome
    data: dict[str, Any] = field(default_factory=dict)
    error: str | None = None
    latency_ms: int = 0


class CveSource(Protocol):
    """Source-client surface — each upstream implements this.

    ``accepted_kinds`` declares which :class:`IdKind` values this source can
    natively look up. The aggregator filters by this set before fan-out, so
    NVD never receives a GHSA, KEV/EPSS never receive a non-CVE, and OSV
    receives anything it understands.
    """

    name: str
    accepted_kinds: ClassVar[frozenset[IdKind]]

    async def fetch(self, cve_id: str) -> FetchResult:  # pragma: no cover - protocol
        ...


class CircuitBreakerOpen(Exception):
    """Raised internally when a circuit breaker rejects a call."""


@dataclass
class CircuitBreaker:
    """
    Tiny per-source circuit breaker.

    Opens after ``threshold`` consecutive failures. Stays open for
    ``reset_seconds``, then half-opens — the next call probes the upstream;
    success closes the breaker, failure re-opens it.

    Not thread-safe. The aggregator runs each source as one coroutine, so the
    only contention is the ``asyncio.gather`` that fans them out — which still
    serialises updates per breaker instance.
    """

    threshold: int = 5
    reset_seconds: float = 60.0
    consecutive_failures: int = 0
    opened_at: float | None = None

    def allow(self) -> bool:
        """Return True if a call should proceed; False if the breaker is open."""
        if self.opened_at is None:
            return True
        if (time.monotonic() - self.opened_at) >= self.reset_seconds:
            # Half-open: allow one probe.
            return True
        return False

    def record_success(self) -> None:
        self.consecutive_failures = 0
        self.opened_at = None

    def record_failure(self) -> None:
        self.consecutive_failures += 1
        if self.consecutive_failures >= self.threshold and self.opened_at is None:
            self.opened_at = time.monotonic()
            log.warning("Circuit breaker opened after %d failures", self.consecutive_failures)

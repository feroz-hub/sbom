"""
CVE detail enrichment sources.

Each source is a separate class implementing :class:`base.CveSource`. The
aggregator merges their results into a single ``CveDetail`` payload via
deterministic, documented merge rules.

No shared mutable state across modules. All HTTP via the shared async
``httpx.AsyncClient`` from ``app.http_client`` with explicit per-call
timeouts, retries (tenacity), and a circuit breaker per source.
"""

from .base import (
    CircuitBreaker,
    CircuitBreakerOpen,
    CveSource,
    FetchOutcome,
    FetchResult,
)

__all__ = [
    "CircuitBreaker",
    "CircuitBreakerOpen",
    "CveSource",
    "FetchOutcome",
    "FetchResult",
]

"""Per-provider concurrency + token-bucket rate limiter and circuit breaker.

Why a hand-rolled token bucket instead of ``aiolimiter``: the codebase has
zero existing async-rate-limit dependency and adding one for a single use
inflates the surface for no gain. The implementation here is small, tested,
and deliberately minimal.

The breaker mirrors the one in :mod:`app.integrations.cve.base` — same
semantics (closed → open after N consecutive failures → half-open after
cooldown → closed on first success).
"""

from __future__ import annotations

import asyncio
import time
from dataclasses import dataclass

from .providers.base import CircuitBreakerOpenError

# ---------------------------------------------------------------------------
# Token-bucket rate limiter
# ---------------------------------------------------------------------------


class RateLimiter:
    """Simple async token bucket.

    ``rate`` tokens added per ``per`` seconds, capped at ``rate`` (no burst
    saving). ``acquire()`` blocks until a token is available. One token =
    one HTTP request.

    Designed to be cheap when the bucket is full (the common case) and to
    serialise correctly under high concurrency.
    """

    def __init__(self, rate: float, per: float = 1.0) -> None:
        if rate <= 0:
            raise ValueError("rate must be > 0")
        if per <= 0:
            raise ValueError("per must be > 0")
        self._rate = float(rate)
        self._per = float(per)
        self._tokens = float(rate)
        self._lock = asyncio.Lock()
        self._last = time.monotonic()

    @property
    def rate(self) -> float:
        return self._rate

    @property
    def per(self) -> float:
        return self._per

    async def acquire(self) -> None:
        while True:
            async with self._lock:
                now = time.monotonic()
                elapsed = now - self._last
                self._last = now
                # Replenish, capped at the bucket size.
                self._tokens = min(self._rate, self._tokens + elapsed * (self._rate / self._per))
                if self._tokens >= 1.0:
                    self._tokens -= 1.0
                    return
                # Compute exact wait for one token.
                deficit = 1.0 - self._tokens
                wait = deficit * (self._per / self._rate)
            # Sleep outside the lock so other waiters can update the clock.
            await asyncio.sleep(wait)


# ---------------------------------------------------------------------------
# Circuit breaker
# ---------------------------------------------------------------------------


@dataclass
class _BreakerState:
    consecutive_failures: int = 0
    opened_at: float | None = None
    # Visible for tests / observability.
    total_failures: int = 0
    total_successes: int = 0


class CircuitBreaker:
    """Lightweight breaker.

    States:
      * **closed** — requests flow.
      * **open** — every ``allow()`` call raises until ``reset_seconds``
        elapse.
      * **half-open** — first request after cool-down is allowed; on success
        the breaker closes, on failure it re-opens.

    Threshold and reset window come from caller configuration so each
    provider can have its own (cloud providers fail fast and recover fast;
    local providers may need longer windows).
    """

    def __init__(
        self,
        *,
        threshold: int = 5,
        reset_seconds: float = 60.0,
        clock: callable = time.monotonic,
    ) -> None:
        if threshold < 1:
            raise ValueError("threshold must be >= 1")
        if reset_seconds <= 0:
            raise ValueError("reset_seconds must be > 0")
        self._threshold = threshold
        self._reset = float(reset_seconds)
        self._clock = clock
        self._state = _BreakerState()

    @property
    def is_open(self) -> bool:
        if self._state.opened_at is None:
            return False
        return (self._clock() - self._state.opened_at) < self._reset

    def state(self) -> dict[str, object]:
        return {
            "is_open": self.is_open,
            "consecutive_failures": self._state.consecutive_failures,
            "total_failures": self._state.total_failures,
            "total_successes": self._state.total_successes,
            "opened_at": self._state.opened_at,
        }

    def allow(self) -> None:
        """Raise if the breaker is currently open. Called before each request."""
        if self.is_open:
            raise CircuitBreakerOpenError("circuit breaker is open")
        # Half-open: opened_at is set but cool-down has elapsed → allow one through.
        # We don't reset here; success/failure of the in-flight request decides.

    def record_success(self) -> None:
        self._state.consecutive_failures = 0
        self._state.opened_at = None
        self._state.total_successes += 1

    def record_failure(self) -> None:
        self._state.consecutive_failures += 1
        self._state.total_failures += 1
        if self._state.consecutive_failures >= self._threshold:
            self._state.opened_at = self._clock()

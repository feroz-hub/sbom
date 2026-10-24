"""Token bucket + circuit breaker unit tests."""

from __future__ import annotations

import asyncio
import time

import pytest
from app.ai.limiter import CircuitBreaker, RateLimiter
from app.ai.providers.base import CircuitBreakerOpenError

# ============================================================ RateLimiter


def test_rate_limiter_validates_args():
    with pytest.raises(ValueError):
        RateLimiter(rate=0)
    with pytest.raises(ValueError):
        RateLimiter(rate=1, per=0)


@pytest.mark.asyncio
async def test_rate_limiter_serialises_burst_above_capacity():
    # 4 tokens per 0.4s (= 10 req/s effective). A 6-call burst should take
    # at least 0.2s for the last 2 tokens.
    limiter = RateLimiter(rate=4, per=0.4)
    t0 = time.monotonic()
    for _ in range(6):
        await limiter.acquire()
    elapsed = time.monotonic() - t0
    assert elapsed >= 0.18, f"expected >= 0.18s, got {elapsed:.3f}s"


@pytest.mark.asyncio
async def test_rate_limiter_does_not_block_when_under_capacity():
    limiter = RateLimiter(rate=100, per=1.0)
    t0 = time.monotonic()
    for _ in range(10):
        await limiter.acquire()
    assert time.monotonic() - t0 < 0.05


@pytest.mark.asyncio
async def test_rate_limiter_concurrent_acquires_serialise():
    limiter = RateLimiter(rate=2, per=0.2)
    results = []

    async def one():
        await limiter.acquire()
        results.append(time.monotonic())

    t0 = time.monotonic()
    await asyncio.gather(*[one() for _ in range(4)])
    # 2 immediate + 2 waiting ~0.1s each
    assert max(results) - t0 >= 0.08


# ============================================================ CircuitBreaker


def test_breaker_validates_args():
    with pytest.raises(ValueError):
        CircuitBreaker(threshold=0)
    with pytest.raises(ValueError):
        CircuitBreaker(threshold=1, reset_seconds=0)


def test_breaker_closed_initially():
    cb = CircuitBreaker(threshold=3, reset_seconds=10)
    cb.allow()  # no raise
    assert not cb.is_open


def test_breaker_opens_after_threshold():
    cb = CircuitBreaker(threshold=3, reset_seconds=10)
    cb.record_failure()
    cb.record_failure()
    cb.allow()  # still closed (2 < 3)
    cb.record_failure()
    assert cb.is_open
    with pytest.raises(CircuitBreakerOpenError):
        cb.allow()


def test_breaker_reopens_after_cooldown():
    now = [0.0]
    cb = CircuitBreaker(threshold=2, reset_seconds=5, clock=lambda: now[0])
    cb.record_failure()
    cb.record_failure()
    assert cb.is_open
    # Advance past cool-down — breaker should be in half-open / closed state.
    now[0] = 6.0
    assert not cb.is_open
    cb.allow()  # passes


def test_breaker_success_resets_consecutive_count():
    cb = CircuitBreaker(threshold=3, reset_seconds=10)
    cb.record_failure()
    cb.record_failure()
    cb.record_success()
    cb.record_failure()
    cb.record_failure()
    # 2 consecutive failures after the success — still under threshold.
    assert not cb.is_open
    state = cb.state()
    assert state["consecutive_failures"] == 2
    assert state["total_failures"] == 4
    assert state["total_successes"] == 1

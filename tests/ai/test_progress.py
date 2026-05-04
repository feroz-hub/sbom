"""Progress store tests — exercises the in-memory backend.

The Redis backend is verified by the protocol it implements (same shape
contract as the in-memory version); a real-Redis integration test lives
behind an env-gated marker that is skipped by default.
"""

from __future__ import annotations

import os

import pytest
from app.ai.progress import (
    BatchProgress,
    InMemoryProgressStore,
    initial_progress,
    progress_events,
)


def test_initial_progress_shape():
    p = initial_progress(42, total=100)
    assert p.run_id == 42
    assert p.status == "pending"
    assert p.total == 100
    assert p.remaining == 100
    assert p.from_cache == 0
    assert p.cancel_requested is False


def test_in_memory_round_trip():
    store = InMemoryProgressStore()
    p = initial_progress(1, total=5)
    store.write(p)
    got = store.read(1)
    assert got is not None
    assert got.total == 5
    assert got.run_id == 1


def test_in_memory_cancel_flag():
    store = InMemoryProgressStore()
    assert store.is_cancel_requested(7) is False
    store.request_cancel(7)
    assert store.is_cancel_requested(7) is True
    store.clear(7)
    assert store.is_cancel_requested(7) is False


def test_in_memory_clear_drops_progress():
    store = InMemoryProgressStore()
    store.write(initial_progress(99, total=1))
    assert store.read(99) is not None
    store.clear(99)
    assert store.read(99) is None


def test_progress_events_yields_changes_then_terminates():
    """progress_events polls until status is terminal."""
    store = InMemoryProgressStore()
    p = initial_progress(3, total=2)
    p.status = "in_progress"
    store.write(p)

    snaps = []
    # Use a tiny poll interval and quick deadline; mutate progress between yields.
    gen = progress_events(store, 3, poll_interval_seconds=0.01, max_seconds=2.0)
    snaps.append(next(gen))
    p.generated = 1
    p.remaining = 1
    store.write(p)
    snaps.append(next(gen))
    p.status = "complete"
    p.remaining = 0
    p.generated = 2
    store.write(p)
    # After this the generator yields the final snapshot then returns.
    snaps.append(next(gen))
    with pytest.raises(StopIteration):
        next(gen)
    assert snaps[0].status == "in_progress"
    assert snaps[-1].status == "complete"


@pytest.mark.skipif(
    not os.getenv("AI_TEST_REDIS_URL"),
    reason="Redis integration test — set AI_TEST_REDIS_URL=redis://... to run",
)
def test_redis_round_trip_when_available():  # pragma: no cover — gated
    import redis  # noqa: F401 — importing only when env-gate flips
    from app.ai.progress import RedisProgressStore

    client = redis.Redis.from_url(os.environ["AI_TEST_REDIS_URL"])
    store = RedisProgressStore(client)
    p = BatchProgress(run_id=1234, status="pending", total=3, remaining=3)
    store.write(p)
    got = store.read(1234)
    assert got is not None and got.run_id == 1234
    store.clear(1234)

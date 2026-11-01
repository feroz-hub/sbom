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


@pytest.fixture(params=["memory", "redis"])
def cancel_store(request):
    if request.param == "memory":
        return InMemoryProgressStore()
    if not os.getenv("AI_TEST_REDIS_URL"):
        pytest.skip("Set AI_TEST_REDIS_URL for the real Redis cancellation regression")
    import redis
    from app.ai.progress import RedisProgressStore

    return RedisProgressStore(redis.Redis.from_url(os.environ["AI_TEST_REDIS_URL"]))


def test_run_cancel_stops_existing_batches_but_allows_retry(cancel_store):
    import uuid

    run_id = uuid.uuid4().int % 1_000_000_000
    try:
        for batch_id in ("queued-before-cancel", "running-before-cancel"):
            cancel_store.write(initial_progress(run_id, total=3, batch_id=batch_id))
        cancel_store.request_cancel(run_id)
        assert cancel_store.is_cancel_requested(run_id, "queued-before-cancel")
        assert cancel_store.is_cancel_requested(run_id, "running-before-cancel")
        cancel_store.write(initial_progress(run_id, total=3, batch_id="retry-after-cancel"))
        assert not cancel_store.is_cancel_requested(run_id, "retry-after-cancel")
    finally:
        cancel_store.clear(run_id)


def test_idle_legacy_cancel_does_not_poison_a_future_batch(cancel_store):
    import uuid

    run_id = uuid.uuid4().int % 1_000_000_000
    try:
        cancel_store.request_cancel(run_id)
        assert cancel_store.is_cancel_requested(run_id)
        assert cancel_store.is_cancel_requested(run_id, "unregistered-in-flight")
        cancel_store.write(initial_progress(run_id, total=0, status="cancelled"))
        cancel_store.write(initial_progress(run_id, total=75, batch_id="new-batch"))
        assert not cancel_store.is_cancel_requested(run_id, "new-batch")
        assert cancel_store.read(run_id).batch_id == "new-batch"
    finally:
        cancel_store.clear(run_id)


def test_cancel_generation_survives_writes_and_repeated_cancel(cancel_store):
    import uuid

    run_id = uuid.uuid4().int % 1_000_000_000
    try:
        old = initial_progress(run_id, total=2, batch_id="old", status="in_progress")
        cancel_store.write(old)
        cancel_store.request_cancel(run_id)
        cancel_store.write(old)  # An in-flight completion cannot reset cancellation.
        assert cancel_store.is_cancel_requested(run_id, "old")
        retry = initial_progress(run_id, total=2, batch_id="retry")
        cancel_store.write(retry)
        assert not cancel_store.is_cancel_requested(run_id, "retry")
        cancel_store.request_cancel(run_id)
        assert cancel_store.is_cancel_requested(run_id, "old")
        assert cancel_store.is_cancel_requested(run_id, "retry")
    finally:
        cancel_store.clear(run_id)


@pytest.fixture
def redis_fault_store():
    if not os.getenv("AI_TEST_REDIS_URL"):
        pytest.skip("Set AI_TEST_REDIS_URL for Redis fault injection")
    import uuid

    import redis
    from app.ai.progress import RedisProgressStore

    client = redis.Redis.from_url(os.environ["AI_TEST_REDIS_URL"])
    store = RedisProgressStore(client)
    run_id = uuid.uuid4().int % 1_000_000_000
    yield store, client, run_id
    store.clear(run_id)
    client.delete(store._batch_progress_key(run_id, "partial"), store._batch_epoch_key(run_id, "partial"))


def test_redis_rejects_invalid_index_before_publishing(redis_fault_store):
    from app.ai.progress import ProgressStoreUnavailableError

    store, client, run_id = redis_fault_store
    client.set(store._run_batches_index(run_id), "injected-wrong-type")
    try:
        with pytest.raises(ProgressStoreUnavailableError):
            store.write(initial_progress(run_id, total=2, batch_id="partial"))
        assert store.read_batch(run_id, "partial") is None
        assert client.get(store._batch_epoch_key(run_id, "partial")) is None
    finally:
        client.delete(store._run_batches_index(run_id))


@pytest.mark.parametrize("fault", ["partial-legacy-write", "lost-publication-reply"])
def test_redis_publication_fault_stays_cancellable_after_recovery(redis_fault_store, fault):
    from app.ai.progress import ProgressStoreUnavailableError, RedisProgressStore

    store, client, run_id = redis_fault_store
    snapshot = initial_progress(run_id, total=2, batch_id="partial", status="queued")

    class Fault:
        def eval(self, *args):
            if fault == "partial-legacy-write":
                # Reproduce a SET-success/index-failure publication from the
                # pre-upgrade implementation. No epoch or index was written.
                client.set(store._batch_progress_key(run_id, "partial"), snapshot.model_dump_json())
            else:
                client.eval(*args)  # Server committed; client lost the reply.
            raise ConnectionError("synthetic publication failure")

    with pytest.raises(ProgressStoreUnavailableError):
        RedisProgressStore(Fault()).write(snapshot)
    store.request_cancel(run_id)
    assert store.is_cancel_requested(run_id, "partial")  # Does not need the index.
    store.write(snapshot)  # Recovery repairs registration without losing cancel.
    assert store.list_for_run(run_id)[0].batch_id == "partial"
    assert store.read(run_id).batch_id == "partial"
    assert store.is_cancel_requested(run_id, "partial")
    store.write(initial_progress(run_id, total=2, batch_id="retry"))
    assert not store.is_cancel_requested(run_id, "retry")
    assert store.read(run_id).batch_id == "retry"


def test_redis_cancel_read_failure_does_not_start_more_paid_work():
    from app.ai.progress import RedisProgressStore

    class Unavailable:
        def mget(self, *args):
            raise ConnectionError("synthetic read failure")

    assert RedisProgressStore(Unavailable()).is_cancel_requested(1, "active")

"""Progress + cancel state for batch AI-fix runs.

Two backends share one interface:

  * :class:`RedisProgressStore` — production. JSON-encoded value at
    ``ai:fix:progress:{run_id}`` with a 24h TTL (so cancelled / abandoned
    runs don't leak forever). Cancel flag lives at
    ``ai:fix:cancel:{run_id}`` — separate key so it can be set without
    racing the progress writer.
  * :class:`InMemoryProgressStore` — tests + Redis-down fallback.
    Process-local; thread-safe.

The factory :func:`get_progress_store` returns the Redis store when a
Redis client can be constructed, falling back to memory otherwise. This
keeps unit tests Redis-free without forcing the production code to know
which backend it's talking to.
"""

from __future__ import annotations

import logging
import threading
from collections.abc import Iterator
from typing import Any, Literal, Protocol

from pydantic import BaseModel, ConfigDict

log = logging.getLogger("sbom.ai.progress")


# ---------------------------------------------------------------------------
# Shape
# ---------------------------------------------------------------------------


ProgressStatus = Literal[
    "pending",        # accepted, not started
    "in_progress",
    "paused_budget",  # halted at the per-scan or per-day cap
    "complete",
    "failed",
    "cancelled",
]


class BatchProgress(BaseModel):
    """Snapshot of a batch run's state. Frontend reads this verbatim."""

    model_config = ConfigDict(extra="forbid")

    run_id: int
    status: ProgressStatus
    total: int = 0
    from_cache: int = 0
    generated: int = 0
    failed: int = 0
    remaining: int = 0
    cost_so_far_usd: float = 0.0
    estimated_remaining_seconds: int | None = None
    estimated_remaining_cost_usd: float | None = None
    started_at: str | None = None
    finished_at: str | None = None
    last_error: str | None = None
    cancel_requested: bool = False
    provider_used: str | None = None
    model_used: str | None = None


# ---------------------------------------------------------------------------
# Protocol
# ---------------------------------------------------------------------------


class ProgressStore(Protocol):
    def write(self, progress: BatchProgress) -> None: ...
    def read(self, run_id: int) -> BatchProgress | None: ...
    def request_cancel(self, run_id: int) -> None: ...
    def is_cancel_requested(self, run_id: int) -> bool: ...
    def clear(self, run_id: int) -> None: ...


# ---------------------------------------------------------------------------
# In-memory backend (test + fallback)
# ---------------------------------------------------------------------------


class InMemoryProgressStore:
    """Process-local store. Single instance shared via :func:`get_progress_store`."""

    def __init__(self) -> None:
        self._lock = threading.Lock()
        self._progress: dict[int, str] = {}
        self._cancel: set[int] = set()

    def write(self, progress: BatchProgress) -> None:
        with self._lock:
            self._progress[progress.run_id] = progress.model_dump_json()

    def read(self, run_id: int) -> BatchProgress | None:
        with self._lock:
            raw = self._progress.get(run_id)
        if raw is None:
            return None
        try:
            return BatchProgress.model_validate_json(raw)
        except Exception:  # noqa: BLE001
            return None

    def request_cancel(self, run_id: int) -> None:
        with self._lock:
            self._cancel.add(run_id)

    def is_cancel_requested(self, run_id: int) -> bool:
        with self._lock:
            return run_id in self._cancel

    def clear(self, run_id: int) -> None:
        with self._lock:
            self._progress.pop(run_id, None)
            self._cancel.discard(run_id)


# ---------------------------------------------------------------------------
# Redis backend
# ---------------------------------------------------------------------------


class RedisProgressStore:
    """Redis-backed store.

    Keys:
      * ``ai:fix:progress:{run_id}``     JSON-encoded :class:`BatchProgress`
      * ``ai:fix:cancel:{run_id}``       ``"1"`` when cancel requested

    TTL: 24h on both keys (rolled forward on write). Stale entries clean
    themselves up — operators don't have to.
    """

    _PROGRESS_TTL_SECONDS = 24 * 3600

    def __init__(self, client: Any) -> None:
        self._client = client

    @staticmethod
    def _progress_key(run_id: int) -> str:
        return f"ai:fix:progress:{run_id}"

    @staticmethod
    def _cancel_key(run_id: int) -> str:
        return f"ai:fix:cancel:{run_id}"

    def write(self, progress: BatchProgress) -> None:
        try:
            self._client.set(
                self._progress_key(progress.run_id),
                progress.model_dump_json(),
                ex=self._PROGRESS_TTL_SECONDS,
            )
        except Exception as exc:  # noqa: BLE001
            log.warning("ai.progress.redis_write_failed: run=%s err=%s", progress.run_id, exc)

    def read(self, run_id: int) -> BatchProgress | None:
        try:
            raw = self._client.get(self._progress_key(run_id))
        except Exception as exc:  # noqa: BLE001
            log.warning("ai.progress.redis_read_failed: run=%s err=%s", run_id, exc)
            return None
        if raw is None:
            return None
        if isinstance(raw, bytes):
            raw = raw.decode("utf-8", errors="replace")
        try:
            return BatchProgress.model_validate_json(raw)
        except Exception:  # noqa: BLE001
            return None

    def request_cancel(self, run_id: int) -> None:
        try:
            self._client.set(self._cancel_key(run_id), "1", ex=self._PROGRESS_TTL_SECONDS)
        except Exception as exc:  # noqa: BLE001
            log.warning("ai.progress.redis_cancel_failed: run=%s err=%s", run_id, exc)

    def is_cancel_requested(self, run_id: int) -> bool:
        try:
            return bool(self._client.get(self._cancel_key(run_id)))
        except Exception:  # noqa: BLE001
            return False

    def clear(self, run_id: int) -> None:
        try:
            self._client.delete(self._progress_key(run_id), self._cancel_key(run_id))
        except Exception:  # noqa: BLE001
            pass


# ---------------------------------------------------------------------------
# Factory
# ---------------------------------------------------------------------------


_lock = threading.Lock()
_store: ProgressStore | None = None


def get_progress_store() -> ProgressStore:
    """Return the singleton store.

    Tries Redis first; falls back to the in-memory store if the connection
    can't be established. The fallback is process-local — fine for dev /
    tests, but in production you want Redis (the SSE endpoint and the
    Celery worker live in different processes).
    """
    global _store
    with _lock:
        if _store is not None:
            return _store
        _store = _build_store()
        return _store


def _build_store() -> ProgressStore:
    try:
        import redis

        from ..settings import get_settings

        url = get_settings().redis_url
        client = redis.Redis.from_url(url, socket_timeout=2.0, socket_connect_timeout=1.5)
        # Probe — fails fast when Redis is down.
        client.ping()
        log.info("ai.progress.using_redis: url=%s", url)
        return RedisProgressStore(client)
    except Exception as exc:  # noqa: BLE001
        log.info("ai.progress.using_memory_fallback: %s", exc)
        return InMemoryProgressStore()


def reset_progress_store() -> None:
    """Drop the cached singleton (test helper)."""
    global _store
    with _lock:
        _store = None


# ---------------------------------------------------------------------------
# Helpers used by the pipeline + SSE generator
# ---------------------------------------------------------------------------


def initial_progress(run_id: int, total: int) -> BatchProgress:
    return BatchProgress(
        run_id=run_id,
        status="pending",
        total=total,
        remaining=total,
    )


def progress_events(
    store: ProgressStore,
    run_id: int,
    *,
    poll_interval_seconds: float = 2.0,
    max_seconds: float = 600.0,
) -> Iterator[BatchProgress]:
    """Synchronous generator used by the SSE endpoint via ``run_in_executor``.

    Yields the latest :class:`BatchProgress` until the status reaches a
    terminal state. Polling is fine here — the alternative (Redis pub/sub)
    is more infrastructure for the same UX. 2s × ~ minutes is well under
    Redis QPS limits for any realistic deployment.
    """
    import time as _time

    deadline = _time.monotonic() + max_seconds
    last_payload: str | None = None
    while _time.monotonic() < deadline:
        snap = store.read(run_id)
        if snap is None:
            _time.sleep(poll_interval_seconds)
            continue
        payload = snap.model_dump_json()
        if payload != last_payload:
            yield snap
            last_payload = payload
        if snap.status in {"complete", "failed", "cancelled"}:
            return
        _time.sleep(poll_interval_seconds)


__all__ = [
    "BatchProgress",
    "InMemoryProgressStore",
    "ProgressStatus",
    "ProgressStore",
    "RedisProgressStore",
    "get_progress_store",
    "initial_progress",
    "progress_events",
    "reset_progress_store",
]


# Test helper used in unit tests instead of needing a real Redis instance.
def _set_store(store: ProgressStore) -> None:
    global _store
    with _lock:
        _store = store

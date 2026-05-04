"""Progress + cancel state for batch AI-fix runs.

Two backends share one interface:

  * :class:`RedisProgressStore` — production. JSON-encoded value at
    ``ai:fix:progress:{run_id}:{batch_id}`` (24h TTL). The legacy
    no-batch-id key ``ai:fix:progress:{run_id}`` is still accepted on
    write/read so the deprecated single-batch endpoints keep working.
    Cancel flag lives at ``ai:fix:cancel:{run_id}:{batch_id}`` — separate
    key so it can be set without racing the progress writer.
  * :class:`InMemoryProgressStore` — tests + Redis-down fallback.
    Process-local; thread-safe.

The factory :func:`get_progress_store` returns the Redis store when a
Redis client can be constructed, falling back to memory otherwise. This
keeps unit tests Redis-free without forcing the production code to know
which backend it's talking to.

Multi-batch support
-------------------
Each :class:`BatchProgress` carries a ``batch_id`` (UUID hex string).
The store keys keep batches isolated so two parallel batches on the
same run don't clobber each other's progress.

Backward compatibility: when ``batch_id is None`` (legacy single-batch
callers — including the old test suite), writes go to the run-id-only
key. ``read(run_id)`` returns the legacy entry if present, otherwise
the most-recently-written batch entry. New code paths use
:meth:`read_batch` and :meth:`latest_for_run` explicitly.
"""

from __future__ import annotations

import logging
import threading
import time
from collections.abc import Iterator
from typing import Any, Literal, Protocol

from pydantic import BaseModel, ConfigDict

log = logging.getLogger("sbom.ai.progress")


# ---------------------------------------------------------------------------
# Shape
# ---------------------------------------------------------------------------


ProgressStatus = Literal[
    "pending",        # accepted, not started
    "queued",         # accepted, waiting for worker pickup
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
    batch_id: str | None = None
    scope_label: str | None = None
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
    def read_batch(self, run_id: int, batch_id: str) -> BatchProgress | None: ...
    def latest_for_run(self, run_id: int) -> BatchProgress | None: ...
    def list_for_run(self, run_id: int) -> list[BatchProgress]: ...
    def request_cancel(self, run_id: int, batch_id: str | None = None) -> None: ...
    def is_cancel_requested(self, run_id: int, batch_id: str | None = None) -> bool: ...
    def clear(self, run_id: int, batch_id: str | None = None) -> None: ...


# ---------------------------------------------------------------------------
# In-memory backend (test + fallback)
# ---------------------------------------------------------------------------


class InMemoryProgressStore:
    """Process-local store. Single instance shared via :func:`get_progress_store`."""

    def __init__(self) -> None:
        self._lock = threading.Lock()
        # Legacy single-batch entries (backward compat with run-id-only callers).
        self._legacy_progress: dict[int, str] = {}
        self._legacy_cancel: set[int] = set()
        # Multi-batch entries.
        self._batch_progress: dict[tuple[int, str], str] = {}
        self._batch_cancel: set[tuple[int, str]] = set()
        # Per-run ordered list of (created_perf_seconds, batch_id),
        # most-recent last. Lets ``latest_for_run`` resolve in O(1).
        self._run_batches: dict[int, list[tuple[float, str]]] = {}

    def write(self, progress: BatchProgress) -> None:
        with self._lock:
            if progress.batch_id is None:
                self._legacy_progress[progress.run_id] = progress.model_dump_json()
                return
            key = (progress.run_id, progress.batch_id)
            if key not in self._batch_progress:
                self._run_batches.setdefault(progress.run_id, []).append(
                    (time.monotonic(), progress.batch_id)
                )
            self._batch_progress[key] = progress.model_dump_json()

    def read(self, run_id: int) -> BatchProgress | None:
        with self._lock:
            raw = self._legacy_progress.get(run_id)
        if raw is None:
            # Backward-compat: when no legacy entry exists but at least
            # one batch is tracked for this run, return the latest one.
            return self.latest_for_run(run_id)
        return _decode(raw)

    def read_batch(self, run_id: int, batch_id: str) -> BatchProgress | None:
        with self._lock:
            raw = self._batch_progress.get((run_id, batch_id))
        return _decode(raw) if raw else None

    def latest_for_run(self, run_id: int) -> BatchProgress | None:
        with self._lock:
            entries = self._run_batches.get(run_id, [])
            if not entries:
                return None
            _, latest_id = entries[-1]
            raw = self._batch_progress.get((run_id, latest_id))
        return _decode(raw) if raw else None

    def list_for_run(self, run_id: int) -> list[BatchProgress]:
        with self._lock:
            entries = list(self._run_batches.get(run_id, []))
            raws = [
                self._batch_progress.get((run_id, bid))
                for _, bid in entries
            ]
        out: list[BatchProgress] = []
        for raw in raws:
            decoded = _decode(raw) if raw else None
            if decoded is not None:
                out.append(decoded)
        return out

    def request_cancel(self, run_id: int, batch_id: str | None = None) -> None:
        with self._lock:
            if batch_id is None:
                self._legacy_cancel.add(run_id)
            else:
                self._batch_cancel.add((run_id, batch_id))

    def is_cancel_requested(self, run_id: int, batch_id: str | None = None) -> bool:
        with self._lock:
            if batch_id is None:
                # Legacy callers see legacy flag OR any batch-level flag.
                if run_id in self._legacy_cancel:
                    return True
                return any(rid == run_id for rid, _ in self._batch_cancel)
            # Batch-level callers: explicit batch flag OR legacy flag
            # (the latter covers "cancel everything for this run").
            return (run_id, batch_id) in self._batch_cancel or run_id in self._legacy_cancel

    def clear(self, run_id: int, batch_id: str | None = None) -> None:
        with self._lock:
            if batch_id is None:
                # Clear EVERYTHING for the run — legacy + all batches.
                self._legacy_progress.pop(run_id, None)
                self._legacy_cancel.discard(run_id)
                for rid, bid in list(self._batch_progress.keys()):
                    if rid == run_id:
                        self._batch_progress.pop((rid, bid), None)
                self._batch_cancel = {
                    (rid, bid) for rid, bid in self._batch_cancel if rid != run_id
                }
                self._run_batches.pop(run_id, None)
                return
            self._batch_progress.pop((run_id, batch_id), None)
            self._batch_cancel.discard((run_id, batch_id))
            entries = self._run_batches.get(run_id, [])
            self._run_batches[run_id] = [e for e in entries if e[1] != batch_id]


def _decode(raw: str | None) -> BatchProgress | None:
    if raw is None:
        return None
    try:
        return BatchProgress.model_validate_json(raw)
    except Exception:  # noqa: BLE001
        return None


# ---------------------------------------------------------------------------
# Redis backend
# ---------------------------------------------------------------------------


class RedisProgressStore:
    """Redis-backed store.

    Keys:
      * ``ai:fix:progress:{run_id}``                  legacy single-batch
      * ``ai:fix:progress:{run_id}:{batch_id}``       per-batch progress
      * ``ai:fix:cancel:{run_id}``                    legacy cancel flag
      * ``ai:fix:cancel:{run_id}:{batch_id}``         per-batch cancel
      * ``ai:fix:run_batches:{run_id}``               sorted-set index
            (member=batch_id, score=created-time epoch ms) for fast
            "list all batches for this run" lookups

    TTL: 24h on every key (rolled forward on write). Stale entries clean
    themselves up — operators don't have to.
    """

    _PROGRESS_TTL_SECONDS = 24 * 3600

    def __init__(self, client: Any) -> None:
        self._client = client

    # Key helpers ------------------------------------------------------

    @staticmethod
    def _legacy_progress_key(run_id: int) -> str:
        return f"ai:fix:progress:{run_id}"

    @staticmethod
    def _batch_progress_key(run_id: int, batch_id: str) -> str:
        return f"ai:fix:progress:{run_id}:{batch_id}"

    @staticmethod
    def _legacy_cancel_key(run_id: int) -> str:
        return f"ai:fix:cancel:{run_id}"

    @staticmethod
    def _batch_cancel_key(run_id: int, batch_id: str) -> str:
        return f"ai:fix:cancel:{run_id}:{batch_id}"

    @staticmethod
    def _run_batches_index(run_id: int) -> str:
        return f"ai:fix:run_batches:{run_id}"

    # Writes -----------------------------------------------------------

    def write(self, progress: BatchProgress) -> None:
        try:
            payload = progress.model_dump_json()
            if progress.batch_id is None:
                self._client.set(
                    self._legacy_progress_key(progress.run_id),
                    payload,
                    ex=self._PROGRESS_TTL_SECONDS,
                )
                return
            self._client.set(
                self._batch_progress_key(progress.run_id, progress.batch_id),
                payload,
                ex=self._PROGRESS_TTL_SECONDS,
            )
            # Index this batch under its run for fast "latest" lookups.
            score = time.time()
            self._client.zadd(
                self._run_batches_index(progress.run_id),
                {progress.batch_id: score},
            )
            self._client.expire(
                self._run_batches_index(progress.run_id),
                self._PROGRESS_TTL_SECONDS,
            )
        except Exception as exc:  # noqa: BLE001
            log.warning(
                "ai.progress.redis_write_failed: run=%s batch=%s err=%s",
                progress.run_id,
                progress.batch_id,
                exc,
            )

    # Reads ------------------------------------------------------------

    def read(self, run_id: int) -> BatchProgress | None:
        raw = self._safe_get(self._legacy_progress_key(run_id))
        if raw is not None:
            return _decode(raw)
        return self.latest_for_run(run_id)

    def read_batch(self, run_id: int, batch_id: str) -> BatchProgress | None:
        raw = self._safe_get(self._batch_progress_key(run_id, batch_id))
        return _decode(raw)

    def latest_for_run(self, run_id: int) -> BatchProgress | None:
        try:
            members = self._client.zrevrange(self._run_batches_index(run_id), 0, 0)
        except Exception as exc:  # noqa: BLE001
            log.warning("ai.progress.redis_index_failed: run=%s err=%s", run_id, exc)
            return None
        if not members:
            return None
        bid = members[0]
        if isinstance(bid, bytes):
            bid = bid.decode("utf-8", errors="replace")
        return self.read_batch(run_id, bid)

    def list_for_run(self, run_id: int) -> list[BatchProgress]:
        try:
            # Ascending by score (= chronological).
            members = self._client.zrange(self._run_batches_index(run_id), 0, -1)
        except Exception as exc:  # noqa: BLE001
            log.warning("ai.progress.redis_list_failed: run=%s err=%s", run_id, exc)
            return []
        out: list[BatchProgress] = []
        for m in members:
            bid = m.decode("utf-8", errors="replace") if isinstance(m, bytes) else m
            snap = self.read_batch(run_id, bid)
            if snap is not None:
                out.append(snap)
        return out

    # Cancel -----------------------------------------------------------

    def request_cancel(self, run_id: int, batch_id: str | None = None) -> None:
        key = (
            self._legacy_cancel_key(run_id)
            if batch_id is None
            else self._batch_cancel_key(run_id, batch_id)
        )
        try:
            self._client.set(key, "1", ex=self._PROGRESS_TTL_SECONDS)
        except Exception as exc:  # noqa: BLE001
            log.warning(
                "ai.progress.redis_cancel_failed: run=%s batch=%s err=%s",
                run_id,
                batch_id,
                exc,
            )

    def is_cancel_requested(self, run_id: int, batch_id: str | None = None) -> bool:
        # Legacy flag is a "cancel everything for this run" lever; honour
        # it for both legacy and per-batch callers.
        try:
            if self._client.get(self._legacy_cancel_key(run_id)):
                return True
            if batch_id is not None and self._client.get(
                self._batch_cancel_key(run_id, batch_id)
            ):
                return True
            return False
        except Exception:  # noqa: BLE001
            return False

    # Clear ------------------------------------------------------------

    def clear(self, run_id: int, batch_id: str | None = None) -> None:
        try:
            if batch_id is None:
                # Legacy clear: drop every key for this run.
                pattern_keys = [
                    self._legacy_progress_key(run_id),
                    self._legacy_cancel_key(run_id),
                ]
                # Drop all batch entries via the index.
                members = self._safe_zrange_all(run_id)
                for bid in members:
                    pattern_keys.append(self._batch_progress_key(run_id, bid))
                    pattern_keys.append(self._batch_cancel_key(run_id, bid))
                pattern_keys.append(self._run_batches_index(run_id))
                self._client.delete(*pattern_keys)
                return
            # Per-batch clear.
            self._client.delete(
                self._batch_progress_key(run_id, batch_id),
                self._batch_cancel_key(run_id, batch_id),
            )
            try:
                self._client.zrem(self._run_batches_index(run_id), batch_id)
            except Exception:  # noqa: BLE001
                pass
        except Exception:  # noqa: BLE001
            pass

    # Internals --------------------------------------------------------

    def _safe_get(self, key: str) -> str | None:
        try:
            raw = self._client.get(key)
        except Exception as exc:  # noqa: BLE001
            log.warning("ai.progress.redis_read_failed: key=%s err=%s", key, exc)
            return None
        if raw is None:
            return None
        if isinstance(raw, bytes):
            return raw.decode("utf-8", errors="replace")
        return raw

    def _safe_zrange_all(self, run_id: int) -> list[str]:
        try:
            members = self._client.zrange(self._run_batches_index(run_id), 0, -1)
        except Exception:  # noqa: BLE001
            return []
        out: list[str] = []
        for m in members:
            out.append(m.decode("utf-8", errors="replace") if isinstance(m, bytes) else m)
        return out


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


def initial_progress(
    run_id: int,
    total: int,
    *,
    batch_id: str | None = None,
    scope_label: str | None = None,
    status: ProgressStatus = "pending",
) -> BatchProgress:
    return BatchProgress(
        run_id=run_id,
        batch_id=batch_id,
        scope_label=scope_label,
        status=status,
        total=total,
        remaining=total,
    )


def progress_events(
    store: ProgressStore,
    run_id: int,
    *,
    batch_id: str | None = None,
    poll_interval_seconds: float = 2.0,
    max_seconds: float = 600.0,
) -> Iterator[BatchProgress]:
    """Synchronous generator used by the SSE endpoint via ``run_in_executor``.

    Yields the latest :class:`BatchProgress` until the status reaches a
    terminal state. When ``batch_id`` is provided, scopes to one batch;
    otherwise streams the latest batch's progress (legacy behaviour).
    Polling is fine here — the alternative (Redis pub/sub) is more
    infrastructure for the same UX. 2s × ~minutes is well under Redis QPS
    limits for any realistic deployment.
    """
    import time as _time

    deadline = _time.monotonic() + max_seconds
    last_payload: str | None = None
    while _time.monotonic() < deadline:
        if batch_id is not None:
            snap = store.read_batch(run_id, batch_id)
        else:
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

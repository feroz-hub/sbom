"""Generation lock to prevent duplicate LLM calls under concurrent batches.

When two parallel batches both miss the AI-fix cache for the same
``(vuln_id, component_name, component_version)`` finding, the naive
flow has them both call the LLM and both write to the cache — paying
twice for the same work. This module wraps generation in an
async-context-manager-style lock keyed on the cache key so only one
batch makes the LLM call; the second waits, then re-checks the cache
and gets the result the first batch wrote.

Two implementations share one interface:

  * :class:`RedisCacheLock` — production. Uses ``redis.lock()``
    primitive; the lock is held for at most ``ttl_seconds`` (defaults
    to 30s, matching the LLM call wall-clock budget). If the holder
    crashes mid-call the lock auto-expires. The blocking acquire is
    dispatched via ``run_in_executor`` so it does NOT stall the
    event loop.
  * :class:`InMemoryCacheLock` — tests + Redis-down fallback. Uses
    one :class:`asyncio.Lock` per cache key. Coroutine-friendly within
    a single event loop. Cross-process correctness is NOT guaranteed
    (multi-worker production should always have Redis available;
    documented in the runbook).

Lock contract::

    async with cache_lock.acquire(cache_key) as acquired:
        if not acquired:
            # timed out — bail with a retryable error
            ...
        # re-check the cache; the holder may have written it
        # if still a miss, call the LLM and write
        ...

``acquire`` always yields a bool indicating whether the lock was
actually held. Callers that need strict mutual exclusion should bail
when ``acquired is False``; callers that prefer "best effort" can
proceed anyway (at the cost of a possible duplicate call).
"""

from __future__ import annotations

import asyncio
import logging
import threading
from collections.abc import AsyncIterator
from contextlib import asynccontextmanager
from typing import Any, Protocol

log = logging.getLogger("sbom.ai.cache_lock")


_DEFAULT_TTL_SECONDS = 30


class CacheLock(Protocol):
    """Lock manager for AI-fix generation."""

    def acquire(
        self,
        cache_key: str,
        *,
        ttl_seconds: int = _DEFAULT_TTL_SECONDS,
    ) -> "AsyncContextManager[bool]":  # pragma: no cover — protocol
        ...


# Forward-ref alias for the protocol return type so the protocol can
# be expressed without quoting on Python 3.10+.
class AsyncContextManager(Protocol):  # pragma: no cover — typing only
    async def __aenter__(self) -> bool: ...
    async def __aexit__(self, *_: Any) -> None: ...


# ---------------------------------------------------------------------------
# In-memory backend (tests + Redis-down fallback)
# ---------------------------------------------------------------------------


class InMemoryCacheLock:
    """Process-local lock registry.

    Use case: unit tests + dev environments without Redis. Multi-worker
    production deployments should always have Redis available — this
    fallback offers no cross-process protection and a duplicate
    generation under contention is possible. The runbook documents
    this caveat.

    Implementation: one :class:`asyncio.Lock` per cache key. Lazily
    created. ``setdefault`` is atomic in CPython (GIL) so registry
    insertion is safe under cooperative concurrency.
    """

    def __init__(self) -> None:
        self._locks: dict[str, asyncio.Lock] = {}

    @asynccontextmanager
    async def acquire(
        self,
        cache_key: str,
        *,
        ttl_seconds: int = _DEFAULT_TTL_SECONDS,
    ) -> AsyncIterator[bool]:
        lock = self._locks.setdefault(cache_key, asyncio.Lock())
        acquired = False
        try:
            await asyncio.wait_for(lock.acquire(), timeout=ttl_seconds)
            acquired = True
        except asyncio.TimeoutError:
            log.warning(
                "ai.cache_lock.timeout: key=%s ttl=%ss — proceeding best-effort",
                cache_key,
                ttl_seconds,
            )
            acquired = False
        try:
            yield acquired
        finally:
            if acquired:
                try:
                    lock.release()
                except RuntimeError:
                    # Released twice somehow — safe to ignore.
                    pass


# ---------------------------------------------------------------------------
# Redis backend
# ---------------------------------------------------------------------------


class RedisCacheLock:
    """Redis-backed lock for cross-process correctness.

    Uses the redis-py ``Redis.lock()`` primitive (Redlock-lite — a SETNX
    with TTL, plus a value token to prevent foreign release). Sufficient
    for our "prevent two workers from calling the LLM for the same
    cache key" use case; we don't need full Redlock fence-tokens because
    the worst case (lost lock, two callers proceed) costs us a single
    duplicate LLM call, not data corruption.

    The redis-py lock is synchronous; we dispatch acquire/release via
    :func:`asyncio.get_event_loop().run_in_executor` so the event loop
    keeps spinning while we wait for the lock.
    """

    _KEY_PREFIX = "ai_fix_gen:"

    def __init__(self, client: Any) -> None:
        self._client = client

    @asynccontextmanager
    async def acquire(
        self,
        cache_key: str,
        *,
        ttl_seconds: int = _DEFAULT_TTL_SECONDS,
    ) -> AsyncIterator[bool]:
        loop = asyncio.get_event_loop()
        lock = self._client.lock(
            self._KEY_PREFIX + cache_key,
            timeout=ttl_seconds,
            blocking_timeout=ttl_seconds,
        )
        acquired = False
        try:
            # ``lock.acquire(blocking=True)`` blocks the caller's thread
            # for up to ``blocking_timeout`` seconds. Run it in the
            # default thread pool so we don't stall the event loop.
            acquired = await loop.run_in_executor(None, lock.acquire)
        except Exception as exc:  # noqa: BLE001
            log.warning("ai.cache_lock.acquire_failed: key=%s err=%s", cache_key, exc)
            acquired = False
        try:
            yield acquired
        finally:
            if acquired:
                try:
                    await loop.run_in_executor(None, lock.release)
                except Exception as exc:  # noqa: BLE001
                    log.debug("ai.cache_lock.release_failed: key=%s err=%s", cache_key, exc)


# ---------------------------------------------------------------------------
# Factory
# ---------------------------------------------------------------------------


_lock = threading.Lock()
_cache_lock_singleton: CacheLock | None = None


def get_cache_lock() -> CacheLock:
    """Return the process-wide singleton.

    Tries Redis first; falls back to the in-memory lock when Redis is
    unreachable. Mirrors the progress-store factory.
    """
    global _cache_lock_singleton
    with _lock:
        if _cache_lock_singleton is not None:
            return _cache_lock_singleton
        _cache_lock_singleton = _build_lock()
        return _cache_lock_singleton


def _build_lock() -> CacheLock:
    try:
        import redis

        from ..settings import get_settings

        url = get_settings().redis_url
        client = redis.Redis.from_url(url, socket_timeout=2.0, socket_connect_timeout=1.5)
        client.ping()
        log.info("ai.cache_lock.using_redis: url=%s", url)
        return RedisCacheLock(client)
    except Exception as exc:  # noqa: BLE001
        log.info("ai.cache_lock.using_memory_fallback: %s", exc)
        return InMemoryCacheLock()


def reset_cache_lock() -> None:
    """Drop the cached singleton (test helper)."""
    global _cache_lock_singleton
    with _lock:
        _cache_lock_singleton = None


def _set_cache_lock(lock: CacheLock) -> None:
    """Inject a specific instance for tests."""
    global _cache_lock_singleton
    with _lock:
        _cache_lock_singleton = lock


__all__ = [
    "CacheLock",
    "InMemoryCacheLock",
    "RedisCacheLock",
    "get_cache_lock",
    "reset_cache_lock",
]

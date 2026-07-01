"""
Shared httpx.AsyncClient(s) for outbound HTTP (connection pooling, keep-alive).

An ``httpx.AsyncClient`` binds its connection pool to the event loop that first
drives it, so a single process-global client breaks the moment it is reused
from a different loop. That is exactly what happens under Celery: every task
spins up its own ``asyncio.run(...)`` loop, and a client created on the FastAPI
lifespan loop (or on a throwaway worker-init loop) is either missing or bound to
a dead loop — surfacing as::

    RuntimeError: Async HTTP client not initialised (app lifespan not run?)
    RuntimeError: Event loop is closed
    RuntimeError: <...> is bound to a different event loop

The fix: cache **one client per event loop** and always hand back the client
bound to whichever loop the caller is running on.

  * FastAPI — one long-lived server loop. ``init_async_http_client`` warms the
    client on startup and ``close_async_http_client`` disposes it on shutdown.
  * Celery  — each task runs its coroutine via ``run_task_async(...)``, which
    drives it on a fresh loop and closes that loop's client before the loop is
    torn down. All findings/requests inside one task share that single client
    (no per-request/per-finding client churn).
"""

from __future__ import annotations

import asyncio
import os
import ssl
from collections.abc import Awaitable
from typing import TypeVar

import certifi
import httpx

_T = TypeVar("_T")

# One shared client per event loop. httpx binds its pool to the creating loop,
# so a client must never be shared across loops. Keyed by the loop object;
# entries whose loop has been closed are pruned lazily (see _prune_dead_loops).
_clients: dict[asyncio.AbstractEventLoop, httpx.AsyncClient] = {}
_tls_context: ssl.SSLContext | None = None


def tls_ssl_context() -> ssl.SSLContext:
    """Mozilla CA bundle via certifi (avoids missing system certs in slim images)."""
    global _tls_context
    if _tls_context is None:
        _tls_context = ssl.create_default_context(cafile=certifi.where())
    return _tls_context


def _new_client() -> httpx.AsyncClient:
    max_conn = int(os.getenv("HTTPX_MAX_CONNECTIONS") or "100")
    max_keepalive = int(os.getenv("HTTPX_MAX_KEEPALIVE") or "20")
    timeout_s = float(os.getenv("HTTPX_TIMEOUT_SECONDS") or "60")
    return httpx.AsyncClient(
        timeout=httpx.Timeout(timeout_s),
        limits=httpx.Limits(
            max_keepalive_connections=max_keepalive,
            max_connections=max_conn,
        ),
        verify=tls_ssl_context(),
        # http2=True requires optional `h2` package — opt in via HTTPX_HTTP2=1
        http2=os.getenv("HTTPX_HTTP2", "").lower() in {"1", "true", "yes"},
    )


def _prune_dead_loops() -> None:
    """Drop cache entries whose event loop is already closed (bounds the dict)."""
    for loop in [lp for lp in _clients if lp.is_closed()]:
        _clients.pop(loop, None)


def get_async_http_client() -> httpx.AsyncClient:
    """Return the shared ``httpx.AsyncClient`` bound to the *current* event loop.

    Lazily creates and caches one client per event loop. Safe to call from any
    async context — FastAPI request handlers and Celery tasks driven by
    ``asyncio.run`` each transparently get a client bound to their own loop, so
    the connection pool is never reused across a closed or foreign loop.

    Raises ``RuntimeError`` only when there is no running event loop at all
    (i.e. called from plain sync code), preserving the previous contract that
    callers such as ``app.analysis`` fall back on.
    """
    loop = asyncio.get_running_loop()
    client = _clients.get(loop)
    if client is not None and not client.is_closed:
        return client
    _prune_dead_loops()
    client = _new_client()
    _clients[loop] = client
    return client


async def init_async_http_client() -> None:
    """Warm the shared client for the current event loop (FastAPI lifespan)."""
    get_async_http_client()


async def close_async_http_client() -> None:
    """Close and drop the shared client bound to the current event loop.

    Used by the FastAPI shutdown hook and by ``run_task_async`` per Celery task.
    A no-op if the current loop never created a client.
    """
    loop = asyncio.get_running_loop()
    client = _clients.pop(loop, None)
    if client is not None:
        await client.aclose()
    _prune_dead_loops()


def run_task_async(coro: Awaitable[_T]) -> _T:
    """Run ``coro`` to completion on a fresh loop for a synchronous Celery task.

    Drop-in replacement for ``asyncio.run(coro)`` in Celery tasks: it disposes
    this loop's shared HTTP client in a ``finally`` before the loop is torn down,
    so there are no leaked connections and no "Event loop is closed" errors from
    a client outliving its loop. All outbound calls made while ``coro`` runs
    share that one loop-local client.
    """

    async def _runner() -> _T:
        try:
            return await coro
        finally:
            await close_async_http_client()

    return asyncio.run(_runner())

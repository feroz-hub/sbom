"""
Shared httpx.AsyncClient for outbound HTTP (connection pooling, keep-alive).

Initialised on app startup via FastAPI lifespan; closed on shutdown.
"""

from __future__ import annotations

import os
import ssl

import certifi
import httpx

_async_client: httpx.AsyncClient | None = None
_tls_context: ssl.SSLContext | None = None


def tls_ssl_context() -> ssl.SSLContext:
    """Mozilla CA bundle via certifi (avoids missing system certs in slim images)."""
    global _tls_context
    if _tls_context is None:
        _tls_context = ssl.create_default_context(cafile=certifi.where())
    return _tls_context


def get_async_http_client() -> httpx.AsyncClient:
    if _async_client is None:
        raise RuntimeError("Async HTTP client not initialised (app lifespan not run?)")
    return _async_client


async def init_async_http_client() -> None:
    global _async_client
    if _async_client is not None:
        return
    max_conn = int(os.getenv("HTTPX_MAX_CONNECTIONS") or "100")
    max_keepalive = int(os.getenv("HTTPX_MAX_KEEPALIVE") or "20")
    timeout_s = float(os.getenv("HTTPX_TIMEOUT_SECONDS") or "60")
    _async_client = httpx.AsyncClient(
        timeout=httpx.Timeout(timeout_s),
        limits=httpx.Limits(
            max_keepalive_connections=max_keepalive,
            max_connections=max_conn,
        ),
        verify=tls_ssl_context(),
        # http2=True requires optional `h2` package — opt in via HTTPX_HTTP2=1
        http2=os.getenv("HTTPX_HTTP2", "").lower() in {"1", "true", "yes"},
    )


async def close_async_http_client() -> None:
    global _async_client
    if _async_client is not None:
        await _async_client.aclose()
        _async_client = None

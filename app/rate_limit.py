"""
API rate limiting (slowapi) — per client IP / forwarded IP + bearer token hash.

Disabled when API_RATE_LIMIT_ENABLED is false (e.g. tests).
"""

from __future__ import annotations

import hashlib
import os

from fastapi import Request
from slowapi import Limiter, _rate_limit_exceeded_handler
from slowapi.util import get_remote_address

rate_limit_exceeded_handler = _rate_limit_exceeded_handler


def _rate_limit_enabled() -> bool:
    v = (os.getenv("API_RATE_LIMIT_ENABLED") or "true").strip().lower()
    return v not in {"0", "false", "no", "off"}


def _default_limit() -> str:
    return (os.getenv("API_RATE_LIMIT_DEFAULT") or "300/minute").strip() or "300/minute"


def _analyze_limit() -> str:
    return (os.getenv("API_RATE_LIMIT_ANALYZE") or "15/minute").strip() or "15/minute"


def rate_limit_key(request: Request) -> str:
    """
    Key by first X-Forwarded-For hop (if present), else client host,
    plus a stable hash of the bearer token when Authorization is set
    so distinct authenticated clients do not share one bucket on NAT.
    """
    forwarded = request.headers.get("x-forwarded-for")
    if forwarded:
        host = forwarded.split(",")[0].strip() or get_remote_address(request)
    else:
        host = get_remote_address(request)
    auth = request.headers.get("authorization") or ""
    if auth.lower().startswith("bearer "):
        token = auth[7:].strip()
        if token:
            th = hashlib.sha256(token.encode("utf-8")).hexdigest()[:16]
            return f"{host}|t:{th}"
    return host


limiter = Limiter(
    key_func=rate_limit_key,
    default_limits=[_default_limit()],
    enabled=_rate_limit_enabled(),
)


# Stricter limit for analysis / SSE endpoints (env API_RATE_LIMIT_ANALYZE).
analyze_route_limit = limiter.limit(_analyze_limit())

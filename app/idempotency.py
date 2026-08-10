"""
Idempotency-Key support for expensive POST / analyze operations.

Same key + scope within TTL returns the cached JSON response (sync endpoints)
or replays a terminal SSE complete event (stream).

Uses a per-key asyncio lock so concurrent duplicate requests serialize and
share one result.
"""

from __future__ import annotations

import asyncio
import hashlib
import json
import os
import time
from typing import Any

from .schemas import AnalysisRunOut

TTL_SECONDS = int(os.getenv("API_IDEMPOTENCY_TTL_SECONDS") or "86400")  # 24h


def _enabled() -> bool:
    v = (os.getenv("API_IDEMPOTENCY_ENABLED") or "true").strip().lower()
    return v not in {"0", "false", "no", "off"}


def _hash_scope(scope: str, idempotency_key: str) -> str:
    raw = f"{scope}\n{idempotency_key}".encode()
    return hashlib.sha256(raw).hexdigest()


def normalize_idempotency_key(header: str | None) -> str | None:
    if not header:
        return None
    s = header.strip()
    if not s or len(s) > 256:
        return None
    return s


# completed[h] -> (expires_at_unix, json_dict)
_completed: dict[str, tuple[float, dict]] = {}
_locks: dict[str, asyncio.Lock] = {}


def _get_lock(h: str) -> asyncio.Lock:
    if h not in _locks:
        _locks[h] = asyncio.Lock()
    return _locks[h]


def _prune(now: float) -> None:
    dead = [k for k, (exp, _) in _completed.items() if exp <= now]
    for k in dead:
        del _completed[k]


def _body_copy(body: dict) -> dict:
    return json.loads(json.dumps(body))


async def run_idempotent(
    scope: str,
    idempotency_key: str,
    runner,
) -> dict:
    """
    Run async ``runner`` once per unique idempotency key; return cached
    response for duplicates within TTL.
    """
    if not _enabled():
        return await runner()

    h = _hash_scope(scope, idempotency_key)
    now = time.time()
    _prune(now)
    if h in _completed:
        exp, body = _completed[h]
        if exp > now:
            return _body_copy(body)

    lock = _get_lock(h)
    async with lock:
        now = time.time()
        if h in _completed:
            exp, body = _completed[h]
            if exp > now:
                return _body_copy(body)
        result = await runner()
        _completed[h] = (now + TTL_SECONDS, _body_copy(result))
        return result


def analysis_run_to_dict(run: Any) -> dict:
    """Serialize ORM AnalysisRun to the same shape as AnalysisRunOut."""
    return AnalysisRunOut.model_validate(run).model_dump()


async def get_cached(scope: str, idempotency_key: str) -> dict | None:
    if not _enabled():
        return None
    h = _hash_scope(scope, idempotency_key)
    now = time.time()
    _prune(now)
    if h in _completed:
        exp, body = _completed[h]
        if exp > now:
            return _body_copy(body)
    return None


def put_cached(scope: str, idempotency_key: str, body: dict) -> None:
    if not _enabled():
        return
    h = _hash_scope(scope, idempotency_key)
    _completed[h] = (time.time() + TTL_SECONDS, _body_copy(body))

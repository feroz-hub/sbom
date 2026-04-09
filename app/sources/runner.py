"""
Concurrent source fan-out helper.

A single coroutine that takes a list of pre-instantiated ``VulnSource``
adapters and runs their ``query()`` calls in parallel via
``asyncio.gather``. Per-source progress events are surfaced through an
optional ``asyncio.Queue`` so callers that need streaming progress
(e.g. the SSE handler in ``app/routers/sboms_crud.py``) can drain events
as soon as each source resolves.

This is the convergence point that Phase 3 promises: both the SSE
streaming endpoint and (eventually) the production
``POST /api/sboms/{id}/analyze`` path will go through here, instead of
each having its own inline fan-out loop.

Design notes:
  * The runner takes already-constructed adapter instances rather than
    ``(name, kwargs)`` pairs because credential plumbing belongs in the
    call site, not here. Callers do
    ``[NvdSource(api_key=...), OsvSource(), GhsaSource(token=...)]``.
  * The optional ``progress_queue`` is a plain ``asyncio.Queue``. Each
    adapter emits ``running`` → ``complete`` / ``error`` events. The
    runner emits a final ``done`` sentinel so consumers know to stop.
  * Errors from individual adapters do **not** cancel the whole gather:
    each ``_run_one`` catches its own exception and logs it onto the
    queue + the aggregated ``errors`` list. This preserves the existing
    best-effort multi-source semantics.
"""

from __future__ import annotations

import asyncio
import time
from typing import Any, List, Optional, Sequence, Tuple

from .base import VulnSource


# ---- Progress event constants ---------------------------------------
EVENT_RUNNING = "running"
EVENT_COMPLETE = "complete"
EVENT_ERROR = "error"
EVENT_DONE = "done"


async def run_sources_concurrently(
    sources: Sequence[VulnSource],
    components: List[dict],
    settings: Any,
    progress_queue: Optional[asyncio.Queue] = None,
) -> Tuple[List[dict], List[dict], List[dict]]:
    """
    Run every adapter's ``query()`` in parallel and aggregate the results.

    Returns:
        ``(all_findings, all_errors, all_warnings)``

    If ``progress_queue`` is supplied, the runner pushes one ``running``
    event per source as it starts, one ``complete`` (or ``error``) event
    as it finishes, and a final ``done`` sentinel after all sources have
    settled. Each event is a dict with at least ``{"kind": ..., "source": ...}``.

    Adapter exceptions are caught and converted into ``error`` events +
    an entry in ``all_errors`` — they do not cancel the gather.
    """
    if not sources:
        if progress_queue is not None:
            await progress_queue.put({"kind": EVENT_DONE})
        return [], [], []

    all_findings: List[dict] = []
    all_errors: List[dict] = []
    all_warnings: List[dict] = []

    async def _run_one(source: VulnSource) -> None:
        src_start = time.perf_counter()
        if progress_queue is not None:
            await progress_queue.put({"kind": EVENT_RUNNING, "source": source.name})
        try:
            result = await source.query(components, settings)
            elapsed_ms = int((time.perf_counter() - src_start) * 1000)
            findings = list(result.get("findings", []))
            errors = list(result.get("errors", []))
            warnings = list(result.get("warnings", []))
            all_findings.extend(findings)
            all_errors.extend(errors)
            all_warnings.extend(warnings)
            if progress_queue is not None:
                await progress_queue.put({
                    "kind": EVENT_COMPLETE,
                    "source": source.name,
                    "findings": len(findings),
                    "errors": len(errors),
                    "source_ms": elapsed_ms,
                })
        except Exception as exc:
            elapsed_ms = int((time.perf_counter() - src_start) * 1000)
            err_msg = str(exc)
            all_errors.append({"source": source.name, "error": err_msg})
            if progress_queue is not None:
                await progress_queue.put({
                    "kind": EVENT_ERROR,
                    "source": source.name,
                    "error": err_msg,
                    "source_ms": elapsed_ms,
                })

    try:
        await asyncio.gather(
            *(_run_one(src) for src in sources),
            return_exceptions=False,
        )
    finally:
        if progress_queue is not None:
            await progress_queue.put({"kind": EVENT_DONE})

    return all_findings, all_errors, all_warnings

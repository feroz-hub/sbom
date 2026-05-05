"""Celery task for batch AI fix generation.

Thin wrapper around :class:`~app.ai.batch.AiFixBatchPipeline`. The task
itself is sync (Celery's preferred world); it spins up an asyncio loop,
drives the pipeline to completion, and stores the summary in the
existing progress key — readers (REST poll, SSE) don't change.

Why ``asyncio.run`` instead of an async-Celery shim: the codebase uses
sync Celery throughout (``cve_refresh``, ``scheduled_analysis``). Adding
an async-Celery dependency for one task would balloon the scope. The
pipeline does the actual concurrency work; Celery is just the dispatcher.
"""

from __future__ import annotations

import asyncio
import logging

from celery import shared_task

from ..ai.batch import AiFixBatchPipeline
from ..ai.cost import BudgetCaps, BudgetGuard
from ..ai.progress import BatchProgress, get_progress_store
from ..settings import get_settings

log = logging.getLogger("sbom.ai.tasks")


@shared_task(name="ai_fix.generate_run_fixes", bind=True, ignore_result=True)
def generate_run_fixes(
    self,
    run_id: int,
    *,
    provider_name: str | None = None,
    force_refresh: bool = False,
    budget_usd: float | None = None,
    finding_ids: list[int] | None = None,
    batch_id: str | None = None,
    scope_label: str | None = None,
) -> dict:
    """Generate AI fix bundles for findings in a run.

    Idempotent at the cache layer — re-running this is essentially free
    if the previous run completed. ``force_refresh=True`` bypasses the
    cache for one pass.

    ``budget_usd`` overrides the per-scan cap from Settings (lets an
    admin bump it for an unusually large scan from the UI).

    Scope-aware (Phase 4 multi-batch): ``finding_ids`` narrows the set
    to a specific subset (else all findings in the run). ``batch_id`` /
    ``scope_label`` distinguish concurrent batches on the same run in
    progress writes and the durable ``ai_fix_batch`` row.
    """
    from ..db import SessionLocal

    log.info(
        "ai.task.generate_run_fixes.start: run=%s batch=%s provider=%s force=%s budget=%s scope=%s findings=%s",
        run_id,
        batch_id,
        provider_name,
        force_refresh,
        budget_usd,
        scope_label,
        len(finding_ids) if finding_ids is not None else "all",
    )

    s = get_settings()
    if s.ai_fixes_kill_switch:
        store = get_progress_store()
        prog = BatchProgress(
            run_id=run_id,
            batch_id=batch_id,
            scope_label=scope_label,
            status="failed",
            last_error="AI fixes kill switch is enabled",
        )
        store.write(prog)
        return prog.model_dump(mode="json")

    caps = BudgetCaps(
        per_request_usd=float(s.ai_budget_per_request_usd) if s.ai_budget_per_request_usd is not None else None,
        per_scan_usd=float(budget_usd) if budget_usd is not None else (
            float(s.ai_budget_per_scan_usd) if s.ai_budget_per_scan_usd is not None else None
        ),
        per_day_org_usd=float(s.ai_budget_per_day_org_usd) if s.ai_budget_per_day_org_usd is not None else None,
    )

    db = SessionLocal()
    try:
        pipeline = AiFixBatchPipeline(
            db,
            budget=BudgetGuard(caps, db_session_factory=SessionLocal),
        )
        summary = asyncio.run(
            pipeline.run(
                run_id,
                provider_name=provider_name,
                force_refresh=force_refresh,
                finding_ids=finding_ids,
                batch_id=batch_id,
                scope_label=scope_label,
            )
        )
    except Exception as exc:  # noqa: BLE001
        log.exception("ai.task.generate_run_fixes.failed: run=%s batch=%s err=%s", run_id, batch_id, exc)
        store = get_progress_store()
        prog = BatchProgress(
            run_id=run_id,
            batch_id=batch_id,
            scope_label=scope_label,
            status="failed",
            last_error=str(exc)[:240],
        )
        store.write(prog)
        return prog.model_dump(mode="json")
    finally:
        db.close()

    log.info(
        "ai.task.generate_run_fixes.done: run=%s status=%s generated=%s from_cache=%s failed=%s cost=%.4f",
        run_id,
        summary.progress.status,
        summary.progress.generated,
        summary.progress.from_cache,
        summary.progress.failed,
        summary.progress.cost_so_far_usd,
    )
    return summary.progress.model_dump(mode="json")

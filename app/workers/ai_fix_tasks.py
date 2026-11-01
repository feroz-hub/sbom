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
from fastapi import HTTPException
from sqlalchemy import select

from ..ai.batch import AiFixBatchPipeline
from ..ai.batches import update_batch_from_progress
from ..ai.progress import BatchProgress, ProgressStoreUnavailableError, get_progress_store
from ..ai.rollout import evaluate_access
from ..ai.runtime_config import build_budget_guard
from ..core.context import minimal_background_context, tenant_scope
from ..models import AnalysisRun
from ..services.job_authorization import authorize_job_actor

log = logging.getLogger("sbom.ai.tasks")


async def _run_pipeline_with_http_client(pipeline: AiFixBatchPipeline, **kwargs) -> object:
    from ..http_client import close_async_http_client, init_async_http_client

    # The Celery task owns this asyncio.run() loop. Build and close the
    # shared AsyncClient inside the same loop so httpx connections are not
    # left bound to a loop that Celery has already torn down.
    await close_async_http_client()
    await init_async_http_client()
    try:
        return await pipeline.run(**kwargs)
    finally:
        await close_async_http_client()


@shared_task(name="ai_fix.generate_run_fixes", bind=True, ignore_result=True)
def generate_run_fixes(
    self,
    run_id: int,
    *,
    tenant_id: int | None = None,
    actor_user_id: int | None = None,
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

    if tenant_id is None:
        prog = BatchProgress(
            run_id=run_id,
            batch_id=batch_id,
            scope_label=scope_label,
            status="failed",
            last_error="AI batch is missing its tenant context",
        )
        return prog.model_dump(mode="json")

    with tenant_scope(minimal_background_context(tenant_id)):
        db = SessionLocal()
        ownership_confirmed = False
        try:
            # Revalidate the requesting actor before run/finding access or provider calls.
            context = authorize_job_actor(db, actor_user_id=actor_user_id,
                                          tenant_id=tenant_id, permission="analysis:run")
            if db.scalar(select(AnalysisRun.id).where(
                AnalysisRun.id == run_id, AnalysisRun.tenant_id == context.tenant_id
            )) is None:
                raise HTTPException(404, "Analysis run not found")
            ownership_confirmed = True
            with tenant_scope(context):
                access = evaluate_access(rollout_key=f"run:{run_id}")
                if not access.allowed:
                    prog = BatchProgress(run_id=run_id, batch_id=batch_id, scope_label=scope_label,
                                         status="failed", last_error=access.message)
                    get_progress_store().write(prog)
                    return prog.model_dump(mode="json")
                pipeline = AiFixBatchPipeline(
                    db,
                    budget=build_budget_guard(per_scan_override_usd=budget_usd),
                )
                summary = asyncio.run(
                    _run_pipeline_with_http_client(
                        pipeline,
                        run_id=run_id,
                        provider_name=provider_name,
                        force_refresh=force_refresh,
                        finding_ids=finding_ids,
                        batch_id=batch_id,
                        scope_label=scope_label,
                    )
                )
        except Exception as exc:  # noqa: BLE001
            log.exception("ai.task.generate_run_fixes.failed: run=%s batch=%s err=%s", run_id, batch_id, exc)
            prog = BatchProgress(
                run_id=run_id,
                batch_id=batch_id,
                scope_label=scope_label,
                status="failed",
                last_error="Background job authorization denied" if isinstance(exc, HTTPException) else "AI batch execution failed",
            )
            if (
                isinstance(exc, ProgressStoreUnavailableError) and exc.progress is not None
                and exc.progress.run_id == run_id and exc.progress.batch_id == batch_id
            ):
                # Preserve completed/billed outcomes if publication fails after
                # a finding finishes; failing Redis must not reset cost to zero.
                prog = exc.progress.model_copy(update={"status": "failed", "last_error": "AI progress publication failed"})
            # Rejected/foreign jobs must not overwrite another run's progress key.
            if ownership_confirmed:
                if batch_id is not None:
                    update_batch_from_progress(db, batch_id=batch_id, progress=prog)
                try:
                    get_progress_store().write(prog)
                except ProgressStoreUnavailableError:
                    log.warning("ai.task.failure_progress_unavailable: run=%s batch=%s", run_id, batch_id)
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

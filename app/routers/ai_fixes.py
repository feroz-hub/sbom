"""AI fix generation REST surface.

Routes:

  POST   /api/v1/runs/{run_id}/ai-fixes
            Trigger batch generation. Returns immediately with the initial
            progress envelope; the actual work runs in a Celery task. If
            Celery isn't reachable (e.g. dev without a worker), falls back
            to running the pipeline inline so the dev experience is intact.

  GET    /api/v1/runs/{run_id}/ai-fixes/progress
            Snapshot for polling clients.

  GET    /api/v1/runs/{run_id}/ai-fixes/stream
            Server-Sent Events stream — emits a new event whenever the
            progress payload changes; closes when the run reaches a
            terminal state.

  POST   /api/v1/runs/{run_id}/ai-fixes/cancel
            Cooperative cancel. The pipeline checks the cancel flag at
            each semaphore boundary; in-flight calls run to completion.

  GET    /api/v1/runs/{run_id}/ai-fixes
            List cached fix bundles for a run (the data the table view
            renders).

  GET    /api/v1/findings/{finding_id}/ai-fix
            Single-finding fetch for the CVE detail modal. Generates on
            demand if the cache is cold.

  POST   /api/v1/findings/{finding_id}/ai-fix:regenerate
            Force a refresh on one finding (the modal's "Regenerate" button).
"""

from __future__ import annotations

import json
import logging

from fastapi import APIRouter, Depends, HTTPException
from fastapi.responses import StreamingResponse
from pydantic import BaseModel, Field
from sqlalchemy import select
from sqlalchemy.orm import Session

from ..ai import cache as cache_mod
from ..ai.batch import AiFixBatchPipeline
from ..ai.estimator import estimate_batch_duration
from ..ai.fix_generator import AiFixGenerator
from ..ai.grounding import build_grounding_context
from ..ai.progress import (
    BatchProgress,
    get_progress_store,
    initial_progress,
    progress_events,
)
from ..ai.registry import get_registry
from ..ai.rollout import evaluate_access
from ..ai.schemas import AiFixError, AiFixResult
from ..db import get_db
from ..models import AiFixCache, AnalysisFinding, AnalysisRun

log = logging.getLogger("sbom.routers.ai_fixes")

router = APIRouter(prefix="/api/v1", tags=["ai-fixes"])


# ---------------------------------------------------------------------------
# Request / response shapes
# ---------------------------------------------------------------------------


class TriggerBatchRequest(BaseModel):
    provider_name: str | None = Field(default=None, description="Override the default provider for this run.")
    force_refresh: bool = Field(default=False, description="Bypass cache, re-generate every finding.")
    budget_usd: float | None = Field(
        default=None,
        ge=0.0,
        description="Override per-scan budget for this run only.",
    )


class TriggerBatchResponse(BaseModel):
    progress: BatchProgress
    enqueued: bool = Field(..., description="True when the Celery task accepted the job; False = ran inline.")


class FindingFixListItem(BaseModel):
    cache_key: str
    vuln_id: str
    component_name: str
    component_version: str
    provider_used: str
    model_used: str
    total_cost_usd: float
    generated_at: str
    expires_at: str


class FindingFixListResponse(BaseModel):
    run_id: int
    items: list[FindingFixListItem]
    total: int


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


_ROLLOUT_ERROR_CODE: dict[str, str] = {
    "kill_switch": "AI_FIXES_KILL_SWITCH",
    "not_enabled": "AI_FIXES_DISABLED",
    "canary_excluded": "AI_FIXES_CANARY_EXCLUDED",
}


def _require_ai_enabled(rollout_key: str | None = None) -> None:
    """Apply the full rollout gate (kill switch → master flag → canary).

    ``rollout_key`` is the stable identifier the canary hash buckets on —
    typically the run id for batch endpoints, or the finding id for the
    single-finding endpoints. Passing ``None`` bypasses canary sampling
    (admin tools that don't have a stable user / scope).
    """
    access = evaluate_access(rollout_key=rollout_key)
    if access.allowed:
        return
    raise HTTPException(
        status_code=access.http_status,
        detail={
            "error_code": _ROLLOUT_ERROR_CODE.get(access.reason, "AI_FIXES_DISABLED"),
            "message": access.message,
        },
    )


def _ensure_run_exists(db: Session, run_id: int) -> AnalysisRun:
    run = db.execute(select(AnalysisRun).where(AnalysisRun.id == run_id)).scalar_one_or_none()
    if run is None:
        raise HTTPException(status_code=404, detail=f"Analysis run {run_id} not found.")
    return run


# ---------------------------------------------------------------------------
# Batch endpoints
# ---------------------------------------------------------------------------


@router.post("/runs/{run_id}/ai-fixes", response_model=TriggerBatchResponse)
async def trigger_run_fixes(
    run_id: int,
    body: TriggerBatchRequest | None = None,
    db: Session = Depends(get_db),
) -> TriggerBatchResponse:
    """Kick off batch generation for an entire run.

    Returns immediately with the initial progress envelope. Clients should
    poll ``/progress`` or subscribe to ``/stream`` for updates.
    """
    _require_ai_enabled(rollout_key=f"run:{run_id}")
    _ensure_run_exists(db, run_id)
    payload = body or TriggerBatchRequest()

    total = db.execute(
        select(AnalysisFinding).where(AnalysisFinding.analysis_run_id == run_id)
    ).all()
    progress = initial_progress(run_id, total=len(total))
    store = get_progress_store()
    store.write(progress)

    enqueued = False
    try:
        from ..workers.ai_fix_tasks import generate_run_fixes

        generate_run_fixes.apply_async(
            kwargs={
                "run_id": run_id,
                "provider_name": payload.provider_name,
                "force_refresh": payload.force_refresh,
                "budget_usd": payload.budget_usd,
            }
        )
        enqueued = True
    except Exception as exc:  # noqa: BLE001
        # Celery broker unreachable / worker not running. Fall back to an
        # inline run so dev still works. Production deployments hit the
        # Celery path; this branch is a developer-experience escape hatch.
        log.info("ai.trigger.celery_unavailable_fallback_inline: run=%s err=%s", run_id, exc)
        await _run_inline(
            db,
            run_id=run_id,
            provider_name=payload.provider_name,
            force_refresh=payload.force_refresh,
        )
        progress = store.read(run_id) or progress

    return TriggerBatchResponse(progress=progress, enqueued=enqueued)


async def _run_inline(
    db: Session,
    *,
    run_id: int,
    provider_name: str | None,
    force_refresh: bool,
) -> None:
    pipeline = AiFixBatchPipeline(db)
    await pipeline.run(run_id, provider_name=provider_name, force_refresh=force_refresh)


class BatchDurationEstimateResponse(BaseModel):
    """Phase 1 §1.5 — frontend warning trip-wire payload."""

    run_id: int
    findings_total: int
    findings_to_generate: int
    cached_count: int
    provider: str
    tier: str
    is_local: bool
    concurrency: int
    requests_per_minute: float
    estimated_seconds: int
    estimated_cost_usd: float
    bottleneck: str
    warning_recommended: bool


@router.get("/runs/{run_id}/ai-fixes/estimate", response_model=BatchDurationEstimateResponse)
def estimate_run_duration(run_id: int, db: Session = Depends(get_db)) -> BatchDurationEstimateResponse:
    """Estimate batch wall-clock + cost before the user clicks Generate.

    Free-tier providers (Gemini Flash @ 15 RPM, Grok @ 60 RPM) make
    large batches *slow* — the UI uses this to show a "this will take
    ~12 minutes; switch to paid?" modal when ``warning_recommended``
    flips true.

    Uses the *current* default provider's settings; switching providers
    in Settings is reflected on the next call.
    """
    _ensure_run_exists(db, run_id)

    findings = list(
        db.execute(select(AnalysisFinding).where(AnalysisFinding.analysis_run_id == run_id)).scalars()
    )
    total = len(findings)

    # Cache hits: same partition logic the pipeline uses, but read-only.
    cached = 0
    for f in findings:
        try:
            ctx = build_grounding_context(f, db=db)
        except Exception:
            continue
        key = cache_mod.make_cache_key(
            vuln_id=ctx.cve_id,
            component_name=ctx.component.name,
            component_version=ctx.component.version,
        )
        if cache_mod.read_cache(db, cache_key=key) is not None:
            cached += 1

    registry = get_registry(db)
    try:
        provider = registry.get_default()
    except Exception:
        # Estimator should still respond when no provider configured.
        return BatchDurationEstimateResponse(
            run_id=run_id,
            findings_total=total,
            findings_to_generate=max(total - cached, 0),
            cached_count=cached,
            provider="unknown",
            tier="paid",
            is_local=False,
            concurrency=0,
            requests_per_minute=0.0,
            estimated_seconds=0,
            estimated_cost_usd=0.0,
            bottleneck="cache",
            warning_recommended=False,
        )

    tier = getattr(provider, "tier", None) or "paid"
    estimate = estimate_batch_duration(
        findings_total=total,
        cached_count=cached,
        provider_name=provider.name,
        tier=tier,
        max_concurrent=getattr(provider, "max_concurrent", 8),
        rate_per_minute=None,
        is_local=getattr(provider, "is_local", False),
    )
    return BatchDurationEstimateResponse(
        run_id=run_id,
        findings_total=estimate.findings_total,
        findings_to_generate=estimate.findings_to_generate,
        cached_count=estimate.cached_count,
        provider=provider.name,
        tier=tier,
        is_local=getattr(provider, "is_local", False),
        concurrency=estimate.concurrency,
        requests_per_minute=estimate.requests_per_minute,
        estimated_seconds=estimate.estimated_seconds,
        estimated_cost_usd=estimate.estimated_cost_usd,
        bottleneck=estimate.bottleneck,
        warning_recommended=estimate.warning_recommended,
    )


@router.get("/runs/{run_id}/ai-fixes/progress", response_model=BatchProgress)
def get_progress(run_id: int, db: Session = Depends(get_db)) -> BatchProgress:
    _ensure_run_exists(db, run_id)
    snap = get_progress_store().read(run_id)
    if snap is None:
        # No batch has ever been triggered for this run.
        return initial_progress(run_id, total=0)
    return snap


@router.post("/runs/{run_id}/ai-fixes/cancel", status_code=202)
def cancel_run_fixes(run_id: int, db: Session = Depends(get_db)) -> dict:
    _ensure_run_exists(db, run_id)
    get_progress_store().request_cancel(run_id)
    return {"run_id": run_id, "cancel_requested": True}


@router.get("/runs/{run_id}/ai-fixes/stream")
def stream_progress(run_id: int, db: Session = Depends(get_db)) -> StreamingResponse:
    _ensure_run_exists(db, run_id)

    store = get_progress_store()

    def _gen():
        # Synchronous generator yielding SSE-formatted events. FastAPI runs
        # this in a thread (StreamingResponse handles that), so we don't
        # need an async loop here.
        yield ":ok\n\n"  # initial ping
        for snap in progress_events(store, run_id):
            payload = json.dumps(snap.model_dump(mode="json"))
            yield f"event: progress\ndata: {payload}\n\n"
        yield "event: end\ndata: {}\n\n"

    return StreamingResponse(_gen(), media_type="text/event-stream")


@router.get("/runs/{run_id}/ai-fixes", response_model=FindingFixListResponse)
def list_run_fixes(run_id: int, db: Session = Depends(get_db)) -> FindingFixListResponse:
    """List cached AI fix bundles produced for a run.

    Joins ``ai_fix_cache`` against the run's findings via the cache key;
    keeps the response compact (the table view doesn't need full bundles —
    those land via the per-finding endpoint when the user clicks a row).
    """
    _ensure_run_exists(db, run_id)
    findings = list(
        db.execute(select(AnalysisFinding).where(AnalysisFinding.analysis_run_id == run_id)).scalars()
    )
    keys: list[str] = []
    key_to_finding: dict[str, AnalysisFinding] = {}
    for f in findings:
        try:
            ctx = build_grounding_context(f, db=db)
        except Exception:
            continue
        key = cache_mod.make_cache_key(
            vuln_id=ctx.cve_id,
            component_name=ctx.component.name,
            component_version=ctx.component.version,
        )
        keys.append(key)
        key_to_finding[key] = f
    if not keys:
        return FindingFixListResponse(run_id=run_id, items=[], total=0)
    rows = list(
        db.execute(select(AiFixCache).where(AiFixCache.cache_key.in_(keys))).scalars()
    )
    items = [
        FindingFixListItem(
            cache_key=r.cache_key,
            vuln_id=r.vuln_id,
            component_name=r.component_name,
            component_version=r.component_version,
            provider_used=r.provider_used,
            model_used=r.model_used,
            total_cost_usd=float(r.total_cost_usd or 0.0),
            generated_at=r.generated_at,
            expires_at=r.expires_at,
        )
        for r in rows
    ]
    return FindingFixListResponse(run_id=run_id, items=items, total=len(items))


# ---------------------------------------------------------------------------
# Single-finding endpoints (CVE detail modal)
# ---------------------------------------------------------------------------


class FindingFixResponse(BaseModel):
    """Returned by the single-finding endpoints.

    Either ``result`` or ``error`` is set. Frontend reads ``error`` first;
    success path reads ``result``.
    """

    result: AiFixResult | None = None
    error: AiFixError | None = None


def _load_finding(db: Session, finding_id: int) -> AnalysisFinding:
    f = db.execute(select(AnalysisFinding).where(AnalysisFinding.id == finding_id)).scalar_one_or_none()
    if f is None:
        raise HTTPException(status_code=404, detail=f"Finding {finding_id} not found.")
    return f


@router.get("/findings/{finding_id}/ai-fix", response_model=FindingFixResponse)
async def get_finding_fix(
    finding_id: int,
    provider_name: str | None = None,
    db: Session = Depends(get_db),
) -> FindingFixResponse:
    """Fetch (or generate) the AI fix bundle for a single finding."""
    _require_ai_enabled(rollout_key=f"finding:{finding_id}")
    finding = _load_finding(db, finding_id)
    gen = AiFixGenerator(db)
    outcome = await gen.generate_for_finding(finding, provider_name=provider_name)
    return _envelope(outcome)


@router.post("/findings/{finding_id}/ai-fix:regenerate", response_model=FindingFixResponse)
async def regenerate_finding_fix(
    finding_id: int,
    provider_name: str | None = None,
    db: Session = Depends(get_db),
) -> FindingFixResponse:
    """Force-refresh — bypass the cache for this finding."""
    _require_ai_enabled(rollout_key=f"finding:{finding_id}")
    finding = _load_finding(db, finding_id)
    gen = AiFixGenerator(db)
    outcome = await gen.generate_for_finding(
        finding, provider_name=provider_name, force_refresh=True
    )
    return _envelope(outcome)


def _envelope(outcome: AiFixResult | AiFixError) -> FindingFixResponse:
    if isinstance(outcome, AiFixResult):
        return FindingFixResponse(result=outcome)
    return FindingFixResponse(error=outcome)

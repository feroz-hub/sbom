"""AI fix generation REST surface.

Routes (multi-batch — current):

  POST   /api/v1/runs/{run_id}/ai-fixes
            Create a batch, optionally scoped via the ``scope`` body.
            Returns the batch id + initial progress envelope.

  POST   /api/v1/runs/{run_id}/ai-fixes/estimate
            Pre-flight cost + duration estimate for a *scoped* batch.
            Body carries the same ``scope`` shape; response includes
            the resolved finding count, cache hit count, and ETA.

  GET    /api/v1/runs/{run_id}/ai-fixes/batches
            List every batch (active + historical) for this run.

  GET    /api/v1/runs/{run_id}/ai-fixes/batches/{batch_id}
            One batch's durable record + live progress envelope.

  GET    /api/v1/runs/{run_id}/ai-fixes/batches/{batch_id}/stream
            SSE stream of progress for one batch.

  POST   /api/v1/runs/{run_id}/ai-fixes/batches/{batch_id}/cancel
            Cooperative cancel for one batch. Other active batches on
            the same run keep running.

  GET    /api/v1/runs/{run_id}/ai-fixes
            List cached fix bundles for a run (the data the table view
            renders). Unchanged.

  GET    /api/v1/findings/{finding_id}/ai-fix
            Single-finding fetch for the CVE detail modal. Unchanged.

  POST   /api/v1/findings/{finding_id}/ai-fix:regenerate
            Force a refresh on one finding. Unchanged.

Deprecated aliases (kept for 30 days post-rollout):

  GET    /api/v1/runs/{run_id}/ai-fixes/estimate
            GET-style estimate for ALL findings in the run. Equivalent
            to POST /estimate with ``scope=None``.

  GET    /api/v1/runs/{run_id}/ai-fixes/progress
            Returns the most-recent batch's progress.

  GET    /api/v1/runs/{run_id}/ai-fixes/stream
            Streams the most-recent batch's progress.

  POST   /api/v1/runs/{run_id}/ai-fixes/cancel
            Cancels every active batch on the run.
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
from ..ai.batches import (
    MAX_ACTIVE_BATCHES_PER_RUN,
    count_active_batches,
    create_batch,
    get_batch,
    list_batches_for_run,
    new_batch_id,
)
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
from ..ai.scope import (
    AiFixGenerationScope,
    count_cached_for_finding_ids,
    resolve_scope_findings,
)
from ..db import get_db
from ..models import AiFixBatch, AiFixCache, AnalysisFinding, AnalysisRun

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
    scope: AiFixGenerationScope | None = Field(
        default=None,
        description=(
            "Scope spec — restricts the batch to a subset of findings. "
            "When None or empty, processes every finding in the run "
            "(legacy behaviour)."
        ),
    )


class TriggerBatchResponse(BaseModel):
    progress: BatchProgress
    batch_id: str
    enqueued: bool = Field(..., description="True when the Celery task accepted the job; False = ran inline.")
    total: int = Field(..., description="Number of findings in scope after resolution.")
    cached_count: int = Field(..., description="How many of those findings already have cached fixes.")
    scope_label: str | None = Field(default=None, description="Human-readable scope label, if any.")


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


class BatchListItem(BaseModel):
    batch_id: str
    run_id: int
    status: str
    scope_label: str | None
    provider_name: str
    total: int
    cached_count: int
    generated_count: int
    failed_count: int
    cost_usd: float
    started_at: str | None
    completed_at: str | None
    created_at: str
    last_error: str | None


class BatchListResponse(BaseModel):
    run_id: int
    items: list[BatchListItem]
    total: int


class BatchDetailResponse(BaseModel):
    batch: BatchListItem
    progress: BatchProgress | None


class EstimateRequest(BaseModel):
    scope: AiFixGenerationScope | None = None


class EstimateResponse(BaseModel):
    """Pre-flight estimate used by the CTA card.

    Always reflects the *current* scope: filters / selection drive the
    finding set, the cache count is computed in a single SQL join, and
    the per-call latency / cost projections come from the same
    estimator the legacy GET endpoint uses.
    """

    run_id: int
    scope_label: str | None
    total_findings_in_scope: int
    cached_count: int
    llm_call_count: int
    estimated_cost_usd: float
    estimated_seconds: int
    provider_name: str
    provider_tier: str
    is_local: bool
    rate_per_minute: float
    bottleneck: str
    warning_recommended: bool
    active_batches_using_provider: int
    blocked: bool
    blocked_reason: str | None


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


def _row_to_list_item(row: AiFixBatch) -> BatchListItem:
    return BatchListItem(
        batch_id=row.id,
        run_id=row.run_id,
        status=row.status,
        scope_label=row.scope_label,
        provider_name=row.provider_name,
        total=int(row.total or 0),
        cached_count=int(row.cached_count or 0),
        generated_count=int(row.generated_count or 0),
        failed_count=int(row.failed_count or 0),
        cost_usd=float(row.cost_usd or 0.0),
        started_at=row.started_at,
        completed_at=row.completed_at,
        created_at=row.created_at,
        last_error=row.last_error,
    )


# ---------------------------------------------------------------------------
# Batch trigger endpoint (multi-batch + scope-aware)
# ---------------------------------------------------------------------------


@router.post("/runs/{run_id}/ai-fixes", response_model=TriggerBatchResponse)
async def trigger_run_fixes(
    run_id: int,
    body: TriggerBatchRequest | None = None,
    db: Session = Depends(get_db),
) -> TriggerBatchResponse:
    """Kick off a batch generation, optionally scoped.

    Returns the new ``batch_id`` plus the initial progress envelope.
    Clients should subscribe to the per-batch SSE stream
    (``/batches/{batch_id}/stream``) for updates; the legacy
    run-scoped stream is still available but only sees the most recent
    batch.
    """
    _require_ai_enabled(rollout_key=f"run:{run_id}")
    _ensure_run_exists(db, run_id)
    payload = body or TriggerBatchRequest()
    scope = payload.scope

    # Concurrency cap: at most N active batches per run. The router is
    # the single enforcement point — the worker doesn't know about
    # other batches.
    active = count_active_batches(db, run_id=run_id)
    if active >= MAX_ACTIVE_BATCHES_PER_RUN:
        raise HTTPException(
            status_code=409,
            detail={
                "error_code": "TOO_MANY_ACTIVE_BATCHES",
                "message": (
                    f"This run has {active} active batches. Wait for one to "
                    "complete before starting another."
                ),
                "active_count": active,
                "max_concurrent": MAX_ACTIVE_BATCHES_PER_RUN,
                "retryable": True,
            },
        )

    # Resolve the scope — security: always intersected with run_id.
    findings = resolve_scope_findings(db, run_id=run_id, scope=scope)
    finding_ids = [f.id for f in findings]
    if not findings:
        raise HTTPException(
            status_code=400,
            detail={
                "error_code": "EMPTY_SCOPE",
                "message": "No findings match the supplied scope.",
            },
        )

    cached_count = count_cached_for_finding_ids(db, finding_ids=finding_ids)

    # Determine provider for the durable row. The pipeline may swap
    # providers if the named one is unavailable, but we record the
    # client's intent here.
    provider_name = payload.provider_name
    resolved_provider_name = provider_name or _default_provider_name(db)

    bid = new_batch_id()
    create_batch(
        db,
        run_id=run_id,
        finding_ids=finding_ids,
        provider_name=resolved_provider_name,
        scope=scope,
        cached_count=cached_count,
        batch_id=bid,
    )

    progress = initial_progress(
        run_id,
        total=len(findings),
        batch_id=bid,
        scope_label=(scope.label if scope and scope.label else None),
        status="queued",
    )
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
                "finding_ids": finding_ids,
                "batch_id": bid,
                "scope_label": progress.scope_label,
            }
        )
        enqueued = True
    except Exception as exc:  # noqa: BLE001
        # Celery broker unreachable / worker not running. Fall back to
        # an inline run so dev still works. Production deployments hit
        # the Celery path; this branch is a developer-experience escape.
        log.info("ai.trigger.celery_unavailable_fallback_inline: run=%s batch=%s err=%s", run_id, bid, exc)
        await _run_inline(
            db,
            run_id=run_id,
            provider_name=payload.provider_name,
            force_refresh=payload.force_refresh,
            finding_ids=finding_ids,
            batch_id=bid,
            scope_label=progress.scope_label,
        )
        progress = store.read_batch(run_id, bid) or progress

    return TriggerBatchResponse(
        progress=progress,
        batch_id=bid,
        enqueued=enqueued,
        total=len(findings),
        cached_count=cached_count,
        scope_label=progress.scope_label,
    )


def _default_provider_name(db: Session) -> str:
    try:
        return get_registry(db).get_default().name
    except Exception:  # noqa: BLE001
        return "unknown"


async def _run_inline(
    db: Session,
    *,
    run_id: int,
    provider_name: str | None,
    force_refresh: bool,
    finding_ids: list[int],
    batch_id: str,
    scope_label: str | None,
) -> None:
    pipeline = AiFixBatchPipeline(db)
    await pipeline.run(
        run_id,
        provider_name=provider_name,
        force_refresh=force_refresh,
        finding_ids=finding_ids,
        batch_id=batch_id,
        scope_label=scope_label,
    )


# ---------------------------------------------------------------------------
# Estimate endpoints
# ---------------------------------------------------------------------------


class BatchDurationEstimateResponse(BaseModel):
    """Legacy GET-estimate shape.

    Kept identical to the pre-Phase-4 contract so existing frontend
    consumers don't break during the rollout window.
    """

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


@router.get(
    "/runs/{run_id}/ai-fixes/estimate",
    response_model=BatchDurationEstimateResponse,
    deprecated=True,
)
def estimate_run_duration_legacy(
    run_id: int,
    db: Session = Depends(get_db),
) -> BatchDurationEstimateResponse:
    """Legacy GET estimate — equivalent to POST /estimate with ``scope=None``.

    Kept for 30 days post Phase-4 rollout. Frontend should migrate to
    the POST variant which supports filter / selection scoping.
    """
    return _legacy_estimate(db, run_id=run_id)


@router.post(
    "/runs/{run_id}/ai-fixes/estimate",
    response_model=EstimateResponse,
)
def estimate_run_duration(
    run_id: int,
    body: EstimateRequest | None = None,
    db: Session = Depends(get_db),
) -> EstimateResponse:
    """Scope-aware pre-flight estimate.

    Resolves the scope to a finding-id list, counts cached entries via
    a single SQL join, then runs the existing duration estimator.
    Returns the same shape regardless of scope (empty / filter /
    selection); the caller uses ``total_findings_in_scope`` and
    ``llm_call_count`` to render the CTA copy.
    """
    _ensure_run_exists(db, run_id)
    scope = body.scope if body else None

    findings = resolve_scope_findings(db, run_id=run_id, scope=scope)
    finding_ids = [f.id for f in findings]
    cached = count_cached_for_finding_ids(db, finding_ids=finding_ids)

    label = scope.label if scope and scope.label else None

    registry = get_registry(db)
    try:
        provider = registry.get_default()
    except Exception:
        return EstimateResponse(
            run_id=run_id,
            scope_label=label,
            total_findings_in_scope=len(findings),
            cached_count=cached,
            llm_call_count=max(len(findings) - cached, 0),
            estimated_cost_usd=0.0,
            estimated_seconds=0,
            provider_name="unknown",
            provider_tier="paid",
            is_local=False,
            rate_per_minute=0.0,
            bottleneck="cache",
            warning_recommended=False,
            active_batches_using_provider=0,
            blocked=True,
            blocked_reason="No AI provider configured.",
        )

    tier = getattr(provider, "tier", None) or "paid"
    estimate = estimate_batch_duration(
        findings_total=len(findings),
        cached_count=cached,
        provider_name=provider.name,
        tier=tier,
        max_concurrent=getattr(provider, "max_concurrent", 8),
        rate_per_minute=None,
        is_local=getattr(provider, "is_local", False),
    )

    # Honest ETA: if other batches are active on the same provider, the
    # rate-limit budget is shared. The frontend uses this to render
    # "sharing capacity with N active batch(es)" copy.
    active_batches_same_provider = (
        db.execute(
            select(AiFixBatch).where(
                AiFixBatch.provider_name == provider.name,
                AiFixBatch.status.in_(("queued", "pending", "in_progress")),
            )
        )
        .scalars()
        .all()
    )

    return EstimateResponse(
        run_id=run_id,
        scope_label=label,
        total_findings_in_scope=estimate.findings_total,
        cached_count=estimate.cached_count,
        llm_call_count=estimate.findings_to_generate,
        estimated_cost_usd=estimate.estimated_cost_usd,
        estimated_seconds=estimate.estimated_seconds,
        provider_name=provider.name,
        provider_tier=tier,
        is_local=getattr(provider, "is_local", False),
        rate_per_minute=estimate.requests_per_minute,
        bottleneck=estimate.bottleneck,
        warning_recommended=estimate.warning_recommended,
        active_batches_using_provider=len(active_batches_same_provider),
        blocked=False,
        blocked_reason=None,
    )


def _legacy_estimate(db: Session, *, run_id: int) -> BatchDurationEstimateResponse:
    """Legacy estimate computation. Iterates findings; slower than the
    POST variant but preserves the exact pre-Phase-4 numbers for any
    consumer still on the GET endpoint."""
    _ensure_run_exists(db, run_id)
    findings = list(
        db.execute(select(AnalysisFinding).where(AnalysisFinding.analysis_run_id == run_id)).scalars()
    )
    total = len(findings)

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


# ---------------------------------------------------------------------------
# Per-batch endpoints
# ---------------------------------------------------------------------------


@router.get(
    "/runs/{run_id}/ai-fixes/batches",
    response_model=BatchListResponse,
)
def list_run_batches(run_id: int, db: Session = Depends(get_db)) -> BatchListResponse:
    """List every batch (active + historical) for a run, newest-first."""
    _ensure_run_exists(db, run_id)
    rows = list_batches_for_run(db, run_id=run_id)
    return BatchListResponse(
        run_id=run_id,
        items=[_row_to_list_item(r) for r in rows],
        total=len(rows),
    )


@router.get(
    "/runs/{run_id}/ai-fixes/batches/{batch_id}",
    response_model=BatchDetailResponse,
)
def get_run_batch(
    run_id: int,
    batch_id: str,
    db: Session = Depends(get_db),
) -> BatchDetailResponse:
    _ensure_run_exists(db, run_id)
    row = get_batch(db, run_id=run_id, batch_id=batch_id)
    if row is None:
        raise HTTPException(status_code=404, detail=f"Batch {batch_id} not found for run {run_id}.")
    progress = get_progress_store().read_batch(run_id, batch_id)
    return BatchDetailResponse(batch=_row_to_list_item(row), progress=progress)


@router.get("/runs/{run_id}/ai-fixes/batches/{batch_id}/stream")
def stream_batch_progress(
    run_id: int,
    batch_id: str,
    db: Session = Depends(get_db),
) -> StreamingResponse:
    _ensure_run_exists(db, run_id)
    row = get_batch(db, run_id=run_id, batch_id=batch_id)
    if row is None:
        raise HTTPException(status_code=404, detail=f"Batch {batch_id} not found for run {run_id}.")
    return _sse_response(run_id, batch_id=batch_id)


@router.post(
    "/runs/{run_id}/ai-fixes/batches/{batch_id}/cancel",
    status_code=202,
)
def cancel_run_batch(
    run_id: int,
    batch_id: str,
    db: Session = Depends(get_db),
) -> dict:
    _ensure_run_exists(db, run_id)
    row = get_batch(db, run_id=run_id, batch_id=batch_id)
    if row is None:
        raise HTTPException(status_code=404, detail=f"Batch {batch_id} not found for run {run_id}.")
    get_progress_store().request_cancel(run_id, batch_id)
    return {"run_id": run_id, "batch_id": batch_id, "cancel_requested": True}


# ---------------------------------------------------------------------------
# Deprecated single-batch endpoints (30-day backward-compat window)
# ---------------------------------------------------------------------------


@router.get(
    "/runs/{run_id}/ai-fixes/progress",
    response_model=BatchProgress,
    deprecated=True,
)
def get_progress(run_id: int, db: Session = Depends(get_db)) -> BatchProgress:
    """Return the most-recent batch's progress (legacy compat).

    Frontends migrating to the multi-batch surface should call
    ``/batches/{batch_id}`` instead.
    """
    _ensure_run_exists(db, run_id)
    store = get_progress_store()
    snap = store.read(run_id)
    if snap is not None:
        return snap
    snap = store.latest_for_run(run_id)
    if snap is not None:
        return snap
    return initial_progress(run_id, total=0)


@router.post(
    "/runs/{run_id}/ai-fixes/cancel",
    status_code=202,
    deprecated=True,
)
def cancel_run_fixes_legacy(run_id: int, db: Session = Depends(get_db)) -> dict:
    """Cancel every active batch on the run (legacy compat).

    The legacy cancel flag is honoured by every batch's pipeline loop;
    in practice this halts the in-flight semaphore work for all
    concurrent batches.
    """
    _ensure_run_exists(db, run_id)
    get_progress_store().request_cancel(run_id)
    return {"run_id": run_id, "cancel_requested": True}


@router.get(
    "/runs/{run_id}/ai-fixes/stream",
    deprecated=True,
)
def stream_progress_legacy(run_id: int, db: Session = Depends(get_db)) -> StreamingResponse:
    """Stream the most-recent batch's progress (legacy compat).

    Multi-batch frontends should subscribe to
    ``/batches/{batch_id}/stream`` instead — the legacy stream is
    indeterminate when multiple batches run on one run.
    """
    _ensure_run_exists(db, run_id)
    return _sse_response(run_id, batch_id=None)


def _sse_response(run_id: int, *, batch_id: str | None) -> StreamingResponse:
    store = get_progress_store()

    def _gen():
        # Synchronous generator yielding SSE-formatted events. FastAPI runs
        # this in a thread (StreamingResponse handles that), so we don't
        # need an async loop here.
        yield ":ok\n\n"  # initial ping
        for snap in progress_events(store, run_id, batch_id=batch_id):
            payload = json.dumps(snap.model_dump(mode="json"))
            yield f"event: progress\ndata: {payload}\n\n"
        yield "event: end\ndata: {}\n\n"

    return StreamingResponse(_gen(), media_type="text/event-stream")


# ---------------------------------------------------------------------------
# Cached-fix listing (unchanged from Phase 3)
# ---------------------------------------------------------------------------


@router.get("/runs/{run_id}/ai-fixes", response_model=FindingFixListResponse)
def list_run_fixes(run_id: int, db: Session = Depends(get_db)) -> FindingFixListResponse:
    """List cached AI fix bundles produced for a run."""
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
# Single-finding endpoints (CVE detail modal) — unchanged
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


# Compatibility re-exports (unused-here helpers retained for
# downstream tests that import them from this module).
__all__ = [
    "BatchDurationEstimateResponse",
    "BatchListResponse",
    "EstimateRequest",
    "EstimateResponse",
    "FindingFixListResponse",
    "FindingFixResponse",
    "TriggerBatchRequest",
    "TriggerBatchResponse",
    "router",
]



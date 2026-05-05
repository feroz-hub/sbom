"""Async batch pipeline for run-level AI fix generation.

Phase 3 §3.1-3.6 distilled into one class. The pipeline is pure async
(no Celery, no FastAPI imports) so it's testable in isolation. The
Celery task and the REST router both call into it.

Scope-aware (Phase 4 multi-batch): a single run may have multiple
concurrent batches in flight, each with its own resolved finding set
and ``batch_id``. Progress writes carry the ``batch_id`` so two batches
on the same run don't clobber each other's snapshots.

Concurrency:

  * Cache hits are returned immediately, no semaphore.
  * Misses fan out under ``asyncio.Semaphore(provider.max_concurrent)``.
  * The orchestrator's per-finding work already includes its own provider
    rate-limiter; the semaphore here just bounds simultaneous in-flight
    LLM calls so we don't blow past the provider's tier limit.
  * Cross-batch dedup happens inside :class:`AiFixGenerator` via
    :class:`~app.ai.cache_lock.CacheLock`. When two batches scope-overlap
    on the same finding, the lock guarantees exactly one LLM call.

Cancellation:

  * Cooperative — the cancel flag is checked before each semaphore
    acquisition. In-flight calls run to completion (we don't kill HTTP
    mid-flight); subsequent findings are skipped.
  * Per-batch: ``store.is_cancel_requested(run_id, batch_id)`` checks
    the batch-scoped flag first, then the legacy run-level flag (which
    cancels every batch on the run).
"""

from __future__ import annotations

import asyncio
import logging
import time
from collections.abc import Sequence
from datetime import UTC, datetime

from sqlalchemy import select
from sqlalchemy.orm import Session

from ..models import AnalysisFinding
from . import cache as cache_mod
from .batches import update_batch_from_progress
from .cost import BudgetGuard
from .fix_generator import AiFixGenerator
from .grounding import build_grounding_context
from .observability import update_cache_hit_ratio
from .progress import BatchProgress, ProgressStore, get_progress_store, initial_progress
from .providers.base import ProviderUnavailableError
from .registry import ProviderRegistry, get_registry
from .schemas import AiFixError, AiFixResult

log = logging.getLogger("sbom.ai.batch")


def _now_iso() -> str:
    return datetime.now(UTC).isoformat()


# ---------------------------------------------------------------------------
# Result envelope
# ---------------------------------------------------------------------------


class BatchSummary:
    """Lightweight aggregate of a batch run.

    Not a Pydantic model — the heavy lifting is in :class:`BatchProgress`,
    which is what the API surfaces. Tests use this to inspect outcomes.
    """

    __slots__ = ("results", "errors", "progress")

    def __init__(
        self,
        *,
        results: list[AiFixResult],
        errors: list[AiFixError],
        progress: BatchProgress,
    ) -> None:
        self.results = results
        self.errors = errors
        self.progress = progress


# ---------------------------------------------------------------------------
# Pipeline
# ---------------------------------------------------------------------------


class AiFixBatchPipeline:
    """Run-level orchestration."""

    def __init__(
        self,
        db: Session,
        *,
        registry: ProviderRegistry | None = None,
        store: ProgressStore | None = None,
        budget: BudgetGuard | None = None,
    ) -> None:
        self._db = db
        self._registry = registry or get_registry(db)
        self._store = store or get_progress_store()
        self._budget = budget
        # Generator is constructed per-call so it can pick up the runtime
        # budget guard the caller may have customised (e.g. with a per-scan
        # cap).

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    async def run(
        self,
        run_id: int,
        *,
        provider_name: str | None = None,
        force_refresh: bool = False,
        finding_ids: list[int] | None = None,
        batch_id: str | None = None,
        scope_label: str | None = None,
    ) -> BatchSummary:
        """Generate AI fixes for findings in ``run_id``.

        Idempotent: a second invocation hits the cache for everything the
        first one wrote, so the throughput is bound by DB reads, not LLM
        latency. Cost is essentially zero on the second run.

        ``finding_ids``: when provided, restricts the batch to these
        findings (intersected with ``run_id`` for safety). When ``None``,
        processes every finding in the run (legacy behaviour).

        ``batch_id`` / ``scope_label``: when provided, propagated into
        progress writes so the SSE stream can be scoped to a single
        batch. ``None`` is the legacy single-batch mode.
        """
        findings = self._load_findings(run_id, finding_ids=finding_ids)
        progress = initial_progress(
            run_id,
            total=len(findings),
            batch_id=batch_id,
            scope_label=scope_label,
        )
        progress.started_at = _now_iso()
        self._store.write(progress)
        self._sync_batch_row(progress, batch_id)

        if not findings:
            progress.status = "complete"
            progress.finished_at = _now_iso()
            self._store.write(progress)
            self._sync_batch_row(progress, batch_id)
            return BatchSummary(results=[], errors=[], progress=progress)

        try:
            provider = (
                self._registry.get(provider_name) if provider_name else self._registry.get_default()
            )
        except ProviderUnavailableError as exc:
            progress.status = "failed"
            progress.last_error = str(exc)
            progress.finished_at = _now_iso()
            self._store.write(progress)
            self._sync_batch_row(progress, batch_id)
            return BatchSummary(results=[], errors=[], progress=progress)

        progress.provider_used = provider.name
        progress.model_used = provider.default_model
        progress.status = "in_progress"
        self._store.write(progress)

        results: list[AiFixResult] = []
        errors: list[AiFixError] = []

        # Phase 1: bulk cache check.
        miss_findings, hit_results = self._partition_cache_hits(findings, force_refresh=force_refresh)
        for hit in hit_results:
            results.append(hit)
            progress.from_cache += 1
            progress.remaining -= 1

        # Refresh progress so the UI sees the cache-hit fast path complete.
        self._update_eta(progress)
        self._store.write(progress)

        if not miss_findings:
            progress.status = "complete"
            progress.finished_at = _now_iso()
            self._store.write(progress)
            self._sync_batch_row(progress, batch_id)
            return BatchSummary(results=results, errors=errors, progress=progress)

        # Phase 2: bounded-concurrency miss path.
        gen = AiFixGenerator(self._db, registry=self._registry, budget=self._budget) if self._budget else AiFixGenerator(self._db, registry=self._registry)
        max_concurrent = max(1, int(getattr(provider, "max_concurrent", 1)))
        semaphore = asyncio.Semaphore(max_concurrent)
        start_perf = time.perf_counter()

        async def _one(finding: AnalysisFinding) -> AiFixResult | AiFixError | None:
            if self._store.is_cancel_requested(run_id, batch_id):
                return None
            async with semaphore:
                if self._store.is_cancel_requested(run_id, batch_id):
                    return None
                return await gen.generate_for_finding(
                    finding,
                    provider_name=provider.name,
                    force_refresh=force_refresh,
                    scan_id=run_id,
                )

        tasks = [asyncio.create_task(_one(f)) for f in miss_findings]
        # We process completions in arrival order so progress writes interleave.
        budget_halted = False
        for completed in asyncio.as_completed(tasks):
            outcome = await completed
            if outcome is None:
                continue
            if isinstance(outcome, AiFixResult):
                results.append(outcome)
                progress.generated += 1
                progress.cost_so_far_usd = round(progress.cost_so_far_usd + outcome.metadata.total_cost_usd, 6)
            else:
                errors.append(outcome)
                progress.failed += 1
                progress.last_error = outcome.message[:240]
                if outcome.error_code == "budget_exceeded":
                    budget_halted = True
            progress.remaining = max(progress.total - progress.from_cache - progress.generated - progress.failed, 0)
            self._update_eta(progress, started_perf=start_perf)
            self._store.write(progress)

            if budget_halted:
                # Cancel the rest — they would all bounce off the same cap.
                # Per-batch cancel: only this batch halts; any other
                # active batches on the run are unaffected.
                self._store.request_cancel(run_id, batch_id)

        # Final status.
        if self._store.is_cancel_requested(run_id, batch_id):
            progress.status = "paused_budget" if budget_halted else "cancelled"
            progress.cancel_requested = True
        else:
            progress.status = "complete"
        progress.finished_at = _now_iso()
        progress.remaining = 0
        self._store.write(progress)
        self._sync_batch_row(progress, batch_id)

        # Telemetry: publish the cache-hit ratio for this run as a gauge
        # so the dashboard's "cache hit ratio trend" sparkline picks it up.
        update_cache_hit_ratio(
            hits=progress.from_cache,
            total=progress.total,
        )

        return BatchSummary(results=results, errors=errors, progress=progress)

    # ------------------------------------------------------------------
    # Internals
    # ------------------------------------------------------------------

    def _load_findings(
        self,
        run_id: int,
        *,
        finding_ids: list[int] | None,
    ) -> list[AnalysisFinding]:
        """Load the findings to process.

        Always constrained by ``analysis_run_id == run_id`` for safety
        (the same defence-in-depth applied at the router's
        :func:`resolve_scope_findings` layer; we re-check here so the
        pipeline is safe to call without going through the router).
        """
        stmt = select(AnalysisFinding).where(AnalysisFinding.analysis_run_id == run_id)
        if finding_ids is not None:
            if not finding_ids:
                return []
            stmt = stmt.where(AnalysisFinding.id.in_(finding_ids))
        return list(self._db.execute(stmt).scalars())

    def _partition_cache_hits(
        self,
        findings: Sequence[AnalysisFinding],
        *,
        force_refresh: bool,
    ) -> tuple[list[AnalysisFinding], list[AiFixResult]]:
        """Split findings into cache-hit results vs miss-list.

        Cache lookup is per-finding (so the grounding context's normalised
        component name participates in the key). For 1k findings on SQLite
        this is sub-millisecond; on Postgres the index seek is the same
        order. A bulk SELECT IN (…) lookup is a future optimisation.
        """
        misses: list[AnalysisFinding] = []
        hits: list[AiFixResult] = []
        if force_refresh:
            return list(findings), []
        for f in findings:
            try:
                ctx = build_grounding_context(f, db=self._db)
            except Exception as exc:  # noqa: BLE001
                log.debug("ai.batch.grounding_failed: finding=%s err=%s", f.id, exc)
                misses.append(f)
                continue
            key = cache_mod.make_cache_key(
                vuln_id=ctx.cve_id,
                component_name=ctx.component.name,
                component_version=ctx.component.version,
            )
            hit = cache_mod.read_cache(self._db, cache_key=key)
            if hit is not None:
                # The cache hit doesn't write a ledger row from here —
                # AiFixGenerator.generate_for_finding does that for the
                # single-finding path. The batch path hits cache *bulk*
                # so we skip the per-call ledger spam (one summary row
                # per batch is enough; the orchestrator path covers the
                # single-call audit need).
                hits.append(hit.model_copy(update={"finding_id": f.id}))
            else:
                misses.append(f)
        return misses, hits

    @staticmethod
    def _update_eta(progress: BatchProgress, *, started_perf: float | None = None) -> None:
        """Best-effort ETA based on observed throughput.

        Conservative: assumes the misses to come will be roughly as
        expensive as the ones already done. Local providers have ~zero
        cost so the cost estimate stays at 0 throughout; cloud providers
        get a per-finding average extrapolated to the remaining count.
        """
        done_misses = progress.generated + progress.failed
        if done_misses <= 0 or started_perf is None:
            progress.estimated_remaining_seconds = None
            progress.estimated_remaining_cost_usd = None
            return
        elapsed = max(time.perf_counter() - started_perf, 0.001)
        rate = done_misses / elapsed
        misses_left = max(progress.remaining, 0)
        progress.estimated_remaining_seconds = int(misses_left / rate) if rate > 0 else None
        avg_cost = progress.cost_so_far_usd / done_misses if done_misses > 0 else 0.0
        progress.estimated_remaining_cost_usd = round(avg_cost * misses_left, 6)

    def _sync_batch_row(self, progress: BatchProgress, batch_id: str | None) -> None:
        """Mirror progress to the durable ``ai_fix_batch`` row.

        Best-effort: a logging warning on failure, no exception
        propagation. The progress store remains the source of truth for
        in-flight UI; the row is the source of truth for historical
        lookups. They converge at terminal status.
        """
        if batch_id is None:
            return
        update_batch_from_progress(self._db, batch_id=batch_id, progress=progress)


__all__ = ["AiFixBatchPipeline", "BatchSummary"]

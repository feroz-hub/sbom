'use client';

import Link from 'next/link';
import { Sparkles } from 'lucide-react';
import { useMemo, useState } from 'react';
import {
  useCancelAiFixes,
  useRunAiBatches,
  useRunAiFixList,
  useScopedRunBatchEstimate,
  useTriggerScopedAiFixes,
} from '@/hooks/useAiFix';
import { useGlobalAiBatchProgress } from '@/components/ai-fixes/GlobalAiBatchProgress';
import { buildScope, describeScope } from '@/lib/aiFixScope';
import { DEFAULT_FILTERS, type FindingsFilterState } from '@/lib/findingFilters';
import type {
  AiBatchProgress,
  AiFixGenerationScope,
  AiScopedEstimateResponse,
} from '@/types/ai';
import { FreeTierWarningDialog } from '../FreeTierWarningDialog';
import { BatchControls } from './BatchControls';
import { BatchProgressBar } from './BatchProgressBar';

interface RunBatchProgressProps {
  runId: number;
  /** When false, the banner returns null. */
  enabled?: boolean;
  /**
   * Filter state from the findings table — drives scope-aware label,
   * estimate, and trigger payload. When omitted the CTA falls back to
   * "all findings" copy and the legacy run-scoped estimate.
   */
  filter?: FindingsFilterState;
  /**
   * Selected finding IDs (Phase 4 row checkboxes). Takes precedence
   * over ``filter`` when non-empty.
   */
  selectedIds?: number[];
  /**
   * Callback that resets ``selectedIds`` to empty. When supplied along
   * with a non-empty selection, the CTA renders a "Clear selection to
   * use filters" affordance.
   */
  onClearSelection?: () => void;
}

const MAX_ACTIVE_BATCHES = 3;

function formatRemainingTime(seconds: number | null | undefined): string | null {
  if (seconds == null) return null;
  if (seconds < 5) return 'almost done';
  if (seconds < 60) return `~${seconds}s remaining`;
  if (seconds < 3600) return `~${Math.floor(seconds / 60)}m remaining`;
  return `~${Math.floor(seconds / 3600)}h remaining`;
}

function formatDuration(seconds: number | null | undefined): string {
  if (seconds == null || seconds <= 0) return 'instant';
  if (seconds < 60) return `~${seconds}s`;
  if (seconds < 3600) return `~${Math.round(seconds / 60)}m`;
  return `~${Math.round((seconds / 3600) * 10) / 10}h`;
}

function formatCost(usd: number, isFree: boolean): string {
  if (isFree) return 'free';
  if (usd < 0.01) return `~$${usd.toFixed(4)}`;
  return `~$${usd.toFixed(2)}`;
}

function PreFlightEstimateLine({
  estimate,
  contention,
}: {
  estimate: AiScopedEstimateResponse;
  contention: number;
}) {
  const isFree = estimate.provider_tier === 'free' && !estimate.is_local;
  const calls = estimate.llm_call_count;
  const cached = estimate.cached_count;
  const provider = estimate.provider_name !== 'unknown' ? estimate.provider_name : null;
  const duration = formatDuration(estimate.estimated_seconds);
  const cost = formatCost(estimate.estimated_cost_usd, isFree);
  const sharingCapacity = isFree && contention > 0;

  return (
    <p className="font-metric text-xs tabular-nums text-hcl-muted">
      <span className="text-hcl-navy">Estimated:</span>{' '}
      <span>{calls.toLocaleString()} LLM call{calls === 1 ? '' : 's'}</span>
      {' · '}
      <span>{cost}</span>
      {' · '}
      <span>
        {duration}
        {isFree ? ' (rate-limited)' : ''}
      </span>
      {provider ? (
        <>
          {' · '}
          <span>{provider}</span>
        </>
      ) : null}
      {cached > 0 ? (
        <>
          {' · '}
          <span className="text-emerald-700">{cached.toLocaleString()} from cache</span>
        </>
      ) : null}
      {sharingCapacity ? (
        <>
          {' · '}
          <span className="text-amber-700">
            sharing capacity with {contention} active batch{contention === 1 ? '' : 'es'}
          </span>
        </>
      ) : null}
      {isFree ? (
        <>
          {' · '}
          <Link
            href="/settings/ai"
            className="font-medium text-primary underline-offset-2 hover:underline"
          >
            Switch to paid?
          </Link>
        </>
      ) : null}
    </p>
  );
}

function statusCopy(status: AiBatchProgress['status']): string {
  switch (status) {
    case 'pending':
    case 'queued':
      return 'Queued — starting shortly';
    case 'in_progress':
      return 'Generating AI remediation';
    case 'paused_budget':
      return 'Paused at budget cap';
    case 'complete':
      return 'AI remediation complete';
    case 'failed':
      return 'AI remediation failed';
    case 'cancelled':
      return 'AI remediation cancelled';
  }
}

function isActive(status: AiBatchProgress['status'] | string): boolean {
  return status === 'queued' || status === 'pending' || status === 'in_progress';
}

/**
 * Persistent banner shown above the findings table. Three modes:
 *
 *   1. **Idle CTA** — no active batch, render scope-aware label +
 *      estimate + Generate button.
 *   2. **In-flight** — show progress for the most-recent batch
 *      (multi-batch UX surfaces extra rows in the global banner).
 *   3. **Max-concurrent reached** — 3 active batches; CTA disabled
 *      with a "wait for one to complete" message.
 */
export function RunBatchProgress({
  runId,
  enabled = true,
  filter,
  selectedIds,
  onClearSelection,
}: RunBatchProgressProps) {
  const hasSelection = (selectedIds?.length ?? 0) > 0;
  // Subscribe via the global provider so the SSE stream stays open when the
  // user navigates away from this page and back. ``liveProgress`` is:
  //   • undefined — still loading the first snapshot
  //   • null      — backend 204: run exists but has no AI fix batch (idle)
  //   • object    — live or most-recent batch progress
  const { data: liveProgress, isLoading: progressLoading } =
    useGlobalAiBatchProgress(runId, { enabled });

  const trigger = useTriggerScopedAiFixes(runId);
  const cancel = useCancelAiFixes(runId);

  // Resolve the active scope from filter / selection state. ``null``
  // means "all findings" (legacy run-wide).
  const scope: AiFixGenerationScope | null = useMemo(() => {
    if (!filter && (!selectedIds || selectedIds.length === 0)) return null;
    return buildScope({
      filter: filter ?? defaultFilter(),
      selectedIds,
    });
  }, [filter, selectedIds]);

  const scopeDescription = useMemo(() => {
    if (!filter && (!selectedIds || selectedIds.length === 0)) return null;
    return describeScope({ filter: filter ?? defaultFilter(), selectedIds });
  }, [filter, selectedIds]);

  // Scope-aware estimate (debounced).
  const isIdle =
    !liveProgress ||
    liveProgress.status === 'complete' ||
    liveProgress.status === 'failed' ||
    liveProgress.status === 'cancelled' ||
    (liveProgress.status === 'pending' && liveProgress.total === 0);
  const { data: estimate } = useScopedRunBatchEstimate(runId, scope, {
    enabled: enabled && isIdle,
  });

  // Multi-batch awareness: pull the list of batches so we can show
  // "active batches on this run" + enforce the 3-cap client-side.
  const { data: batches } = useRunAiBatches(runId, { enabled });
  const activeBatches = batches?.items.filter((b) => isActive(b.status)) ?? [];
  const atMaxConcurrent = activeBatches.length >= MAX_ACTIVE_BATCHES;

  // Run-level count of fixes available in the tenant-shared cache — the
  // SAME data (and query key) that drives the findings-table AI column.
  // The per-batch counters below describe only the most-recent batch,
  // so a cancelled/empty last batch reads "0" while the run can still
  // have cached fixes available. Surfacing this run-level total keeps
  // the banner and the table telling one consistent story.
  const { data: runFixList } = useRunAiFixList(runId, { enabled });
  const runFixesAvailable = runFixList?.total ?? 0;

  const [showWarning, setShowWarning] = useState(false);

  if (!enabled) return null;

  const handleTrigger = () => {
    if (estimate?.warning_recommended) {
      setShowWarning(true);
      return;
    }
    trigger.mutate({ scope });
  };
  const confirmTrigger = () => {
    setShowWarning(false);
    trigger.mutate({ scope });
  };

  // Still fetching the first snapshot — don't flash the CTA before we know
  // whether this run actually has a batch in flight.
  if (liveProgress === undefined && progressLoading) return null;
  // ``null`` = backend 204 (run exists, no batch yet) or a settled-empty
  // fetch. Render the idle CTA from a local stub. The stub is display-only:
  // it is NOT written to the query cache and the provider does NOT subscribe
  // to it, so it can't trap a phantom subscriber the way a server-fabricated
  // ``pending`` envelope did.
  const progress: AiBatchProgress = liveProgress ?? makeIdleProgress(runId);

  const hasEverRun =
    progress.total > 0 || progress.from_cache > 0 || progress.generated > 0 || progress.failed > 0;

  // Idle CTA path — no in-flight batch.
  if (!hasEverRun && progress.status === 'pending') {
    const scopedTotal = estimate?.total_findings_in_scope ?? null;
    const ctaLabel = computeCtaLabel({
      scopeDescription,
      scopedTotal,
      atMaxConcurrent,
      activeBatchCount: activeBatches.length,
      hasSelection,
    });
    const cached = estimate?.cached_count ?? 0;
    const allCached =
      scopedTotal != null && scopedTotal > 0 && estimate != null && estimate.llm_call_count === 0;
    const emptyScope = scopedTotal === 0;

    return (
      <>
        <div
          className="flex flex-col gap-2 rounded-lg border border-border-subtle bg-surface px-4 py-3 shadow-card"
          data-testid="ai-batch-banner"
          role="region"
          aria-label="AI remediation"
        >
          <div className="flex items-start justify-between gap-3">
            <div className="min-w-0 flex-1 space-y-1">
              <div className="flex items-center gap-2 text-sm font-medium text-hcl-navy">
                <Sparkles className="h-4 w-4 text-primary" aria-hidden />
                <span data-testid="ai-batch-cta-label">{ctaLabel}</span>
              </div>
              {emptyScope ? (
                <p className="text-xs text-hcl-muted">
                  No findings match the current filters. Adjust filters to scope a generation batch.
                </p>
              ) : allCached ? (
                <p className="text-xs text-emerald-700">
                  All {cached.toLocaleString()} findings already have cached AI fixes.
                </p>
              ) : estimate ? (
                <PreFlightEstimateLine
                  estimate={estimate}
                  contention={Math.max(estimate.active_batches_using_provider, activeBatches.length)}
                />
              ) : null}
              {atMaxConcurrent ? (
                <p className="text-xs text-amber-700" role="status">
                  {activeBatches.length} active batches on this run (max concurrent reached). Wait
                  for one to complete or cancel an active batch before starting another.
                </p>
              ) : activeBatches.length > 0 ? (
                <p className="text-xs text-hcl-muted">
                  {activeBatches.length} active batch{activeBatches.length === 1 ? '' : 'es'} on
                  this run — fire another with a different scope?
                </p>
              ) : null}
              {hasSelection && onClearSelection ? (
                <p className="text-xs text-hcl-muted">
                  Selection takes precedence over filters.{' '}
                  <button
                    type="button"
                    onClick={onClearSelection}
                    className="font-medium text-primary underline-offset-2 hover:underline focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-hcl-blue/30"
                    data-testid="ai-batch-clear-selection"
                  >
                    Clear selection to use filters
                  </button>
                </p>
              ) : null}
            </div>
            <BatchControls
              progress={progress}
              onTrigger={handleTrigger}
              onCancel={() => cancel.mutate()}
              triggering={trigger.isPending}
              cancelling={cancel.isPending}
              disabledReason={
                atMaxConcurrent
                  ? 'Wait for one to complete before starting another.'
                  : emptyScope
                    ? 'No findings match the current scope.'
                    : allCached
                      ? 'All findings in scope are already cached.'
                      : undefined
              }
            />
          </div>
        </div>
        <FreeTierWarningDialog
          open={showWarning}
          estimate={estimate ? legacyEstimateShim(estimate) : null}
          onContinue={confirmTrigger}
          onCancel={() => setShowWarning(false)}
        />
      </>
    );
  }

  const remaining = formatRemainingTime(progress.estimated_remaining_seconds);
  const cost = `$${progress.cost_so_far_usd.toFixed(4)}`;
  // When the displayed batch has finished (complete/cancelled/failed/
  // paused), its counters are historical — scope them to "Last batch"
  // so they're not read as a run-wide tally.
  const batchActive = isActive(progress.status);

  return (
    <>
      <div
        className="flex flex-col gap-2 rounded-lg border border-border-subtle bg-surface px-4 py-3 shadow-card"
        data-testid="ai-batch-banner"
        role="region"
        aria-label="AI remediation progress"
      >
        <div className="flex items-center justify-between gap-3">
          <div className="flex items-center gap-2 text-sm font-medium text-hcl-navy">
            <Sparkles className="h-4 w-4 text-primary" aria-hidden />
            <span>{statusCopy(progress.status)}</span>
            {progress.scope_label ? (
              <span
                className="rounded-md bg-surface-muted px-2 py-0.5 text-[11px] font-medium uppercase tracking-wide text-hcl-muted"
                data-testid="ai-batch-scope-label"
              >
                {progress.scope_label}
              </span>
            ) : null}
          </div>
          <BatchControls
            progress={progress}
            onTrigger={handleTrigger}
            onCancel={() => cancel.mutate()}
            triggering={trigger.isPending}
            cancelling={cancel.isPending}
          />
        </div>

        <BatchProgressBar progress={progress} />

        <div className="flex flex-wrap items-center gap-x-4 gap-y-1 text-xs text-hcl-muted">
          {!batchActive ? (
            <span className="font-medium text-hcl-navy">Last batch</span>
          ) : null}
          <span>
            <span className="font-medium text-hcl-navy">
              {progress.from_cache + progress.generated + progress.failed}
            </span>{' '}
            / {progress.total}
          </span>
          <span>
            Cached: <span className="font-medium text-emerald-700">{progress.from_cache}</span>
          </span>
          <span>
            Generated: <span className="font-medium text-primary">{progress.generated}</span>
          </span>
          {progress.failed > 0 ? (
            <span>
              Failed: <span className="font-medium text-red-700">{progress.failed}</span>
            </span>
          ) : null}
          <span>
            Spent: <span className="font-medium text-hcl-navy">{cost}</span>
          </span>
          {remaining ? <span>{remaining}</span> : null}
          {progress.provider_used ? (
            <span>
              Provider:{' '}
              <span className="font-medium text-hcl-navy">{progress.provider_used}</span>
            </span>
          ) : null}
        </div>

        {!batchActive && runFixesAvailable > 0 ? (
          <p className="text-xs text-emerald-700" data-testid="ai-batch-run-available">
            {runFixesAvailable.toLocaleString()} AI fix{runFixesAvailable === 1 ? '' : 'es'}{' '}
            available for this run
          </p>
        ) : null}

        {progress.last_error ? (
          <p className="text-xs text-red-700">{progress.last_error}</p>
        ) : null}
      </div>
      <FreeTierWarningDialog
        open={showWarning}
        estimate={estimate ? legacyEstimateShim(estimate) : null}
        onContinue={confirmTrigger}
        onCancel={() => setShowWarning(false)}
      />
    </>
  );
}

function computeCtaLabel(args: {
  scopeDescription: string | null;
  scopedTotal: number | null;
  atMaxConcurrent: boolean;
  activeBatchCount: number;
  hasSelection: boolean;
}): string {
  const { scopeDescription, scopedTotal, atMaxConcurrent, hasSelection } = args;
  if (atMaxConcurrent) {
    return 'Generate AI fixes (disabled — max concurrent batches reached)';
  }
  if (scopedTotal === 0) return 'No findings match the current scope.';

  // Selection-driven copy: ``scopeDescription`` already starts with the
  // count ("12 selected findings"), so we don't prefix another count.
  if (hasSelection && scopeDescription) {
    return `Generate AI fixes for ${scopeDescription}`;
  }

  const total = scopedTotal != null ? scopedTotal.toLocaleString() : null;
  if (scopeDescription && scopeDescription !== 'all findings') {
    if (total != null) {
      return `Generate AI fixes for ${total} ${pluraliseDescription(scopeDescription, scopedTotal!)}`;
    }
    return `Generate AI fixes for ${scopeDescription}`;
  }
  if (total != null) {
    return `Generate AI fixes for ${total} finding${scopedTotal === 1 ? '' : 's'} in this run`;
  }
  return 'Generate AI fixes for every finding in this run';
}

function pluraliseDescription(description: string, count: number): string {
  // The scope description always reads as plural ("Critical findings");
  // for a count of 1 we re-render with "finding". Lowercase the head
  // so it sits naturally after the numeric count.
  const lowered = description.toLowerCase();
  if (count === 1 && lowered.includes('findings')) {
    return lowered.replace(/findings/i, 'finding');
  }
  return lowered;
}

/**
 * Display-only idle envelope for a run whose ``/progress`` returned 204
 * (run exists, no AI fix batch yet). Lets the banner render its "Generate"
 * CTA without a server-fabricated ``pending`` payload — and without
 * subscribing, since the real query data stays ``null`` (see
 * ``useGlobalAiBatchProgress``, which only tracks live statuses).
 */
function makeIdleProgress(runId: number): AiBatchProgress {
  return {
    run_id: runId,
    batch_id: null,
    scope_label: null,
    status: 'pending',
    total: 0,
    from_cache: 0,
    generated: 0,
    failed: 0,
    remaining: 0,
    cost_so_far_usd: 0,
    estimated_remaining_seconds: null,
    estimated_remaining_cost_usd: null,
    started_at: null,
    finished_at: null,
    last_error: null,
    cancel_requested: false,
    provider_used: null,
    model_used: null,
  };
}

function defaultFilter(): FindingsFilterState {
  // Use the canonical defaults so adding fields to FindingsFilterState
  // (e.g. PR-E's matchReasonFilter / matchConfidenceMin /
  // matchStrategies) doesn't ripple across local duplicates.
  return { ...DEFAULT_FILTERS };
}

/**
 * Adapt the new ``AiScopedEstimateResponse`` to the legacy
 * ``AiBatchDurationEstimate`` shape that the FreeTierWarningDialog
 * still expects. Drops contention + blocked fields the dialog
 * doesn't read.
 */
function legacyEstimateShim(e: AiScopedEstimateResponse) {
  return {
    run_id: e.run_id,
    findings_total: e.total_findings_in_scope,
    findings_to_generate: e.llm_call_count,
    cached_count: e.cached_count,
    provider: e.provider_name,
    tier: e.provider_tier,
    is_local: e.is_local,
    concurrency: 0,
    requests_per_minute: e.rate_per_minute,
    estimated_seconds: e.estimated_seconds,
    estimated_cost_usd: e.estimated_cost_usd,
    bottleneck: e.bottleneck,
    warning_recommended: e.warning_recommended,
  };
}

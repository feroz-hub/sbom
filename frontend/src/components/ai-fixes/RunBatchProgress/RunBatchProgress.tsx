'use client';

import Link from 'next/link';
import { Sparkles } from 'lucide-react';
import { useState } from 'react';
import { useRunBatchEstimate } from '@/hooks/useAiCredentials';
import {
  useCancelAiFixes,
  useTriggerAiFixes,
} from '@/hooks/useAiFix';
import { useGlobalAiBatchProgress } from '@/components/ai-fixes/GlobalAiBatchProgress';
import type { AiBatchDurationEstimate, AiBatchProgress } from '@/types/ai';
import { FreeTierWarningDialog } from '../FreeTierWarningDialog';
import { BatchControls } from './BatchControls';
import { BatchProgressBar } from './BatchProgressBar';

interface RunBatchProgressProps {
  runId: number;
  /** When false, the banner returns null. */
  enabled?: boolean;
  /** Override default copy on the trigger CTA. */
  triggerLabel?: string;
}

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
  if (usd < 1) return `~$${usd.toFixed(2)}`;
  return `~$${usd.toFixed(2)}`;
}

function PreFlightEstimateLine({ estimate }: { estimate: AiBatchDurationEstimate }) {
  const isFree = estimate.tier === 'free' && !estimate.is_local;
  const calls = estimate.findings_to_generate;
  const cached = estimate.cached_count;
  const provider = estimate.provider !== 'unknown' ? estimate.provider : null;
  const duration = formatDuration(estimate.estimated_seconds);
  const cost = formatCost(estimate.estimated_cost_usd, isFree);

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

/**
 * Persistent banner shown above the findings table during a batch run.
 *
 * Phase 4 §4.1 (Integration 2). Hides itself on rare empty states (a run
 * with zero findings) so the page doesn't carry dead UI. Surfaces all
 * three numbers (cache / generated / failed) and the cumulative cost.
 */
export function RunBatchProgress({ runId, enabled = true }: RunBatchProgressProps) {
  // Subscribe via the global provider so the SSE stream stays open when
  // the user navigates away from this page and back. The provider also
  // drives the sticky banner shown across other routes.
  const { data: progress } = useGlobalAiBatchProgress(runId, { enabled });
  const trigger = useTriggerAiFixes(runId);
  const cancel = useCancelAiFixes(runId);
  // Phase 3 §3.5 — fetch the duration projection for the active provider.
  // Only enabled when the user is in a "could trigger" state (no active
  // batch); avoids fetching during in-flight batches when it would be stale.
  const isIdle =
    !progress ||
    progress.status === 'complete' ||
    progress.status === 'failed' ||
    progress.status === 'cancelled' ||
    (progress.status === 'pending' && progress.total === 0);
  const { data: estimate } = useRunBatchEstimate(runId, { enabled: enabled && isIdle });
  const [showWarning, setShowWarning] = useState(false);

  if (!enabled) return null;

  // The trigger handler — short-circuit through the warning dialog when
  // the estimate flags a slow free-tier batch.
  const handleTrigger = () => {
    if (estimate?.warning_recommended) {
      setShowWarning(true);
      return;
    }
    trigger.mutate({});
  };
  const confirmTrigger = () => {
    setShowWarning(false);
    trigger.mutate({});
  };

  // Render nothing until we have any batch data AND either the run has
  // findings OR a run has been triggered before. This avoids a banner
  // on a brand-new run page where AI has never been asked.
  if (!progress) return null;
  const hasEverRun =
    progress.total > 0 || progress.from_cache > 0 || progress.generated > 0 || progress.failed > 0;
  if (!hasEverRun && progress.status === 'pending') {
    // Idle CTA — surfaces the pre-flight estimate so the user sees the
    // call count, cost, duration, and provider before clicking Generate.
    // Falls back to a minimal copy line when the estimate is still loading
    // so the banner doesn't pop from one shape to another.
    const totalFindings = estimate?.findings_total ?? null;
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
                <span>
                  {totalFindings != null
                    ? `Generate AI remediation for ${totalFindings.toLocaleString()} finding${totalFindings === 1 ? '' : 's'} in this run.`
                    : 'Generate AI remediation for every finding in this run.'}
                </span>
              </div>
              {estimate ? <PreFlightEstimateLine estimate={estimate} /> : null}
            </div>
            <BatchControls
              progress={progress}
              onTrigger={handleTrigger}
              onCancel={() => cancel.mutate()}
              triggering={trigger.isPending}
              cancelling={cancel.isPending}
            />
          </div>
        </div>
        <FreeTierWarningDialog
          open={showWarning}
          estimate={estimate ?? null}
          onContinue={confirmTrigger}
          onCancel={() => setShowWarning(false)}
        />
      </>
    );
  }

  const remaining = formatRemainingTime(progress.estimated_remaining_seconds);
  const cost = `$${progress.cost_so_far_usd.toFixed(4)}`;

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
            Provider: <span className="font-medium text-hcl-navy">{progress.provider_used}</span>
          </span>
        ) : null}
      </div>

      {progress.last_error ? (
        <p className="text-xs text-red-700">{progress.last_error}</p>
      ) : null}
    </div>
    <FreeTierWarningDialog
      open={showWarning}
      estimate={estimate ?? null}
      onContinue={confirmTrigger}
      onCancel={() => setShowWarning(false)}
    />
    </>
  );
}

'use client';

import { Sparkles } from 'lucide-react';
import { useState } from 'react';
import { useRunBatchEstimate } from '@/hooks/useAiCredentials';
import {
  useAiBatchProgress,
  useCancelAiFixes,
  useTriggerAiFixes,
} from '@/hooks/useAiFix';
import type { AiBatchProgress } from '@/types/ai';
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
  const { data: progress } = useAiBatchProgress(runId, { enabled });
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
    // Show a minimal "Generate" CTA on first visit.
    return (
      <>
        <div
          className="flex items-center justify-between gap-3 rounded-lg border border-border-subtle bg-surface px-4 py-3 shadow-card"
          data-testid="ai-batch-banner"
          role="region"
          aria-label="AI remediation"
        >
          <div className="flex items-center gap-2 text-sm text-hcl-navy">
            <Sparkles className="h-4 w-4 text-primary" aria-hidden />
            <span>
              Generate AI remediation for every finding in this run.
            </span>
          </div>
          <BatchControls
            progress={progress}
            onTrigger={handleTrigger}
            onCancel={() => cancel.mutate()}
            triggering={trigger.isPending}
            cancelling={cancel.isPending}
          />
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

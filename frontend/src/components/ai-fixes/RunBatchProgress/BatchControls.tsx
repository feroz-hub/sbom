'use client';

import { CircleX, Sparkles } from 'lucide-react';
import type { AiBatchProgress } from '@/types/ai';

interface BatchControlsProps {
  progress: AiBatchProgress;
  onTrigger: () => void;
  onCancel: () => void;
  triggering?: boolean;
  cancelling?: boolean;
  disabledReason?: string;
}

/**
 * Trigger / cancel buttons for the batch banner.
 *
 * The control set adapts to the current status:
 *   * idle / terminal       → "Generate AI fixes for run"
 *   * in_progress / pending → "Cancel"
 *   * paused_budget         → "Increase budget" (disabled — owner CTA via Settings)
 */
export function BatchControls({
  progress,
  onTrigger,
  onCancel,
  triggering,
  cancelling,
  disabledReason,
}: BatchControlsProps) {
  // ``pending`` only counts as "running" when we already have findings
  // queued. A pending+total=0 banner is the initial empty state and
  // should still offer the Generate CTA.
  const isRunning =
    progress.status === 'in_progress' ||
    (progress.status === 'pending' && progress.total > 0);
  const isTerminal =
    progress.status === 'complete' ||
    progress.status === 'failed' ||
    progress.status === 'cancelled';
  const isPaused = progress.status === 'paused_budget';

  if (isPaused) {
    return (
      <div className="flex items-center gap-2 text-xs text-amber-800">
        <span>Daily AI budget reached.</span>
        <a
          href="/settings#ai"
          className="rounded-md border border-amber-400 bg-amber-50 px-2 py-1 font-medium hover:bg-amber-100"
        >
          Increase in Settings
        </a>
      </div>
    );
  }

  if (isRunning) {
    return (
      <button
        type="button"
        onClick={onCancel}
        disabled={cancelling}
        className="inline-flex items-center gap-1 rounded-md border border-border-subtle bg-surface px-2 py-1 text-xs font-medium text-hcl-navy hover:bg-surface-muted disabled:cursor-progress disabled:opacity-60"
      >
        <CircleX className="h-3.5 w-3.5" aria-hidden />
        {cancelling ? 'Cancelling…' : 'Cancel'}
      </button>
    );
  }

  return (
    <button
      type="button"
      onClick={onTrigger}
      disabled={triggering || Boolean(disabledReason) || (isTerminal && progress.total === 0)}
      title={disabledReason}
      className="inline-flex items-center gap-1 rounded-md bg-primary px-3 py-1.5 text-xs font-medium text-white shadow-elev-1 hover:bg-hcl-dark disabled:cursor-not-allowed disabled:opacity-60"
    >
      <Sparkles className="h-3.5 w-3.5" aria-hidden />
      {triggering ? 'Starting…' : 'Generate AI fixes'}
    </button>
  );
}

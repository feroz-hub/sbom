'use client';

import { PermissionButton } from '@/components/ui/PermissionButton';

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
 *   * queued / in_progress / pending → "Cancel"
 *   * paused_budget         → budget explanation and retry
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
    progress.status === 'queued' ||
    progress.status === 'in_progress' ||
    (progress.status === 'pending' && progress.total > 0);
  if (isRunning) {
    return (
      <PermissionButton size="sm" variant="secondary" permission="analysis:run"
        type="button"
        onClick={onCancel}
        disabled={cancelling}
        disabledReason={cancelling ? 'Cancellation requested; waiting for active requests to finish.' : undefined}
      >
        <CircleX className="h-3.5 w-3.5" aria-hidden />
        {cancelling ? 'Cancelling…' : 'Cancel'}
      </PermissionButton>
    );
  }

  return (
    <div className="flex max-w-full flex-col items-start gap-2">
      {progress.status === 'paused_budget' ? (
        <p className="text-xs text-hcl-muted">
          AI budget reached. Retry after the budget resets or is updated in{' '}
          <a href="/settings/ai" className="text-primary underline">AI settings</a>.
        </p>
      ) : null}
      <PermissionButton size="sm" variant="primary" permission="analysis:run"
        type="button"
        onClick={onTrigger}
        disabled={triggering || Boolean(disabledReason)}
        disabledReason={triggering ? 'Starting an AI remediation batch.' : disabledReason}
        className="shrink-0 whitespace-nowrap"
      >
        <Sparkles className="h-3.5 w-3.5" aria-hidden />
        {triggering ? 'Starting…' : 'Generate AI fixes'}
      </PermissionButton>
      {disabledReason ? <p className="text-xs text-hcl-muted" role="status">{disabledReason}</p> : null}
    </div>
  );
}

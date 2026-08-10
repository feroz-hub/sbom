'use client';

import { Sparkles } from 'lucide-react';
import type { AiBatchDurationEstimate } from '@/types/ai';

interface EstimatedTimelineProps {
  estimate: AiBatchDurationEstimate;
}

/**
 * Visual timeline pill for the FreeTierWarningDialog options.
 *
 * Renders the wall-clock + cost projection for one provider option,
 * highlighting the bottleneck (free tier rate limit vs paid tier
 * concurrency).
 */
export function EstimatedTimeline({ estimate }: EstimatedTimelineProps) {
  const minutes = estimate.estimated_seconds / 60;
  const display =
    estimate.estimated_seconds < 60
      ? `${estimate.estimated_seconds}s`
      : minutes < 60
        ? `~${Math.ceil(minutes)} min`
        : `~${Math.ceil(minutes / 60)}h`;

  const cost = estimate.estimated_cost_usd === 0
    ? 'free'
    : estimate.estimated_cost_usd < 0.01
      ? '<$0.01'
      : `$${estimate.estimated_cost_usd.toFixed(2)}`;

  return (
    <div
      className="flex items-center justify-between rounded-md border border-border-subtle bg-surface-muted px-3 py-2 text-sm"
      data-bottleneck={estimate.bottleneck}
    >
      <div className="flex items-center gap-2 text-hcl-navy">
        <Sparkles className="h-3.5 w-3.5 text-primary" aria-hidden />
        <span>
          <span className="font-medium">{estimate.provider}</span>{' '}
          <span className="text-hcl-muted">({estimate.tier})</span>
        </span>
      </div>
      <div className="flex items-center gap-3 font-metric tabular-nums text-xs text-hcl-muted">
        <span>{display}</span>
        <span>{cost}</span>
      </div>
    </div>
  );
}

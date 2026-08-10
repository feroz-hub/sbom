'use client';

import { ArrowDownRight, ArrowUpRight, Minus } from 'lucide-react';
import { cn } from '@/lib/utils';

interface PostureTileProps {
  label: string;
  valueA: string;
  valueB: string;
  delta: number;
  /**
   * "down-good" — a decrease is interpreted as improvement (green).
   * "up-good"   — an increase is improvement (used for fix-available coverage).
   */
  direction: 'down-good' | 'up-good';
  /** Suffix appended to the delta (e.g. "%", "pp"). */
  deltaSuffix?: string;
  tooltip?: string;
}

/**
 * Compact posture tile for the new hero composition.
 *
 *   - Border-only (no shadow) so it reads as *context*, not *headline*.
 *   - Smaller numbers + tighter padding vs the v1 PostureMetricTile.
 *   - Same direction logic / tone mapping — verified by the
 *     PostureMetricTile.test.tsx suite (tone class names match).
 */
export function PostureTile({
  label,
  valueA,
  valueB,
  delta,
  direction,
  deltaSuffix = '',
  tooltip,
}: PostureTileProps) {
  const improving =
    delta === 0
      ? 'neutral'
      : direction === 'down-good'
        ? delta < 0
          ? 'positive'
          : 'negative'
        : delta > 0
          ? 'positive'
          : 'negative';

  const Icon = delta === 0 ? Minus : delta < 0 ? ArrowDownRight : ArrowUpRight;

  const tone =
    improving === 'positive'
      ? 'text-emerald-700 dark:text-emerald-300'
      : improving === 'negative'
        ? 'text-red-700 dark:text-red-300'
        : 'text-hcl-muted';

  return (
    <div
      className="rounded-lg border border-border-subtle bg-surface p-3"
      title={tooltip}
    >
      <p className="text-[10px] font-semibold uppercase tracking-wider text-hcl-muted">
        {label}
      </p>
      <div className="mt-1 flex items-baseline gap-1.5">
        <span className="font-metric text-xl font-bold tabular-nums text-hcl-navy">
          {valueA}
        </span>
        <span className="text-hcl-muted">→</span>
        <span className="font-metric text-xl font-bold tabular-nums text-hcl-navy">
          {valueB}
        </span>
      </div>
      <div
        className={cn(
          'mt-0.5 inline-flex items-center gap-1 text-xs font-semibold tabular-nums',
          tone,
        )}
      >
        <Icon className="h-3.5 w-3.5" aria-hidden />
        <span>
          {delta > 0 ? '+' : ''}
          {Number.isInteger(delta) ? delta : delta.toFixed(1)}
          {deltaSuffix}
        </span>
      </div>
    </div>
  );
}

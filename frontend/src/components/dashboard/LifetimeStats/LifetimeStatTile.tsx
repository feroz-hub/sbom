'use client';

import type { ReactNode } from 'react';
import { cn } from '@/lib/utils';

interface LifetimeStatTileProps {
  /** Uppercase 11px label sitting above the big number. */
  label: string;
  /**
   * The growth metric. Renders with `font-metric` and tabular-nums so the
   * tile width never jumps when the number rolls from "9" to "10".
   */
  value: ReactNode;
  /** 12px hcl-muted sub-line; describes scope ("across N projects"). */
  caption?: ReactNode;
  className?: string;
}

/**
 * One tile in the "Your Analyzer, So Far" panel. Deliberately *not*
 * interactive — these are growth metrics, not actionable. The left accent
 * border ties the row to the brand without escalating tone; severity
 * colours are reserved for posture, not lifetime.
 *
 * See `docs/dashboard-redesign.md` §6 for layout and §13 for the
 * anti-patterns this tile explicitly rejects (no deltas, no comparisons).
 */
export function LifetimeStatTile({
  label,
  value,
  caption,
  className,
}: LifetimeStatTileProps) {
  return (
    <div
      className={cn(
        'rounded-xl border border-l-4 border-border border-l-hcl-blue bg-surface px-6 py-5 shadow-card',
        'transition-colors duration-base',
        className,
      )}
    >
      <p className="text-[11px] font-medium uppercase tracking-wider text-hcl-muted">
        {label}
      </p>
      <p className="mt-1 font-metric text-[2.5rem] font-bold leading-none text-hcl-navy tabular-nums">
        {value}
      </p>
      {caption && (
        <p className="mt-2 text-xs text-hcl-muted">{caption}</p>
      )}
    </div>
  );
}

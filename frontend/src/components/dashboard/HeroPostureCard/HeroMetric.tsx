'use client';

import type { ReactNode } from 'react';
import { cn } from '@/lib/utils';

export type HeroMetricTone = 'red' | 'sky' | 'emerald' | 'neutral';

interface HeroMetricProps {
  /** Uppercase 10-11px label sitting above the number. */
  label: string;
  /** Optional icon — sized 14px to match label baseline. */
  icon?: ReactNode;
  /**
   * The big value. Children are rendered with tabular-nums so layout never
   * shifts when the number changes by an order of magnitude.
   */
  children: ReactNode;
  /** Optional sub-line — 10-11px, hcl-muted. */
  caption?: ReactNode;
  /** Color treatment. `neutral` is the default calm state. */
  tone?: HeroMetricTone;
  /** Hover tooltip — same string is exposed to screen readers via aria-label. */
  tooltip?: string;
  className?: string;
}

const TONE_CLASSES: Record<HeroMetricTone, string> = {
  red: 'border-red-200 bg-red-50/60 text-red-700 dark:border-red-900 dark:bg-red-950/30 dark:text-red-300',
  sky: 'border-sky-200 bg-sky-50/60 text-sky-700 dark:border-sky-900 dark:bg-sky-950/30 dark:text-sky-300',
  emerald:
    'border-emerald-200 bg-emerald-50/60 text-emerald-700 dark:border-emerald-900 dark:bg-emerald-950/30 dark:text-emerald-300',
  neutral: 'border-border bg-surface/60 text-hcl-muted',
};

/**
 * One tile in the hero metric row. Four of these sit horizontally below
 * the severity bar, each answering one specific question — see
 * `docs/dashboard-redesign.md` §3.1. Tones are deliberately calm: a tile
 * paints color only when its value is meaningful (KEV > 0, fixes
 * available, etc.); otherwise stays neutral so the eye isn't trained to
 * tune them out.
 */
export function HeroMetric({
  label,
  icon,
  children,
  caption,
  tone = 'neutral',
  tooltip,
  className,
}: HeroMetricProps) {
  return (
    <div
      title={tooltip}
      aria-label={tooltip ? `${label}: ${tooltip}` : label}
      className={cn(
        'rounded-lg border px-3 py-2 transition-colors duration-base',
        TONE_CLASSES[tone],
        className,
      )}
    >
      <div className="flex items-center gap-1.5 text-[10px] font-semibold uppercase tracking-wider">
        {icon}
        {label}
      </div>
      <div className="mt-0.5 font-metric text-xl font-bold leading-tight tabular-nums">
        {children}
      </div>
      {caption && (
        <div className="mt-0.5 text-[10px] font-medium text-hcl-muted">
          {caption}
        </div>
      )}
    </div>
  );
}

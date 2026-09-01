'use client';

import type { ReactNode } from 'react';
import type { LucideIcon } from 'lucide-react';
import { Surface } from '@/components/ui/Surface';
import { cn } from '@/lib/utils';

interface LifetimeStatTileProps {
  /** Uppercase 11px label sitting above the number. */
  label: string;
  /**
   * The growth metric. Renders with `font-metric` and tabular-nums so the
   * tile width never jumps when the number rolls from "9" to "10".
   */
  value: ReactNode;
  /** 10px hcl-muted sub-line; describes scope ("across all SBOMs"). */
  caption?: ReactNode;
  /** Left-hand glyph. Present so this row lines up with `CounterTiles`. */
  icon?: LucideIcon;
  /** Hover text spelling out exactly what the number counts. */
  tooltip?: string;
  className?: string;
}

/**
 * One tile in the lifetime-totals row.
 *
 * Structurally identical to a `CounterTiles` tile — same Surface, same icon
 * block, same label / value / caption type scale — because the two rows sit
 * directly on top of each other on the dashboard and any difference in
 * padding or number size reads as a mistake rather than a distinction.
 *
 * Deliberately *not* interactive: these are growth metrics, not actionable
 * ones. See `docs/dashboard-redesign.md` §13 for the anti-patterns this tile
 * rejects (no deltas, no comparisons).
 */
export function LifetimeStatTile({
  label,
  value,
  caption,
  icon: Icon,
  tooltip,
  className,
}: LifetimeStatTileProps) {
  return (
    <Surface variant="elevated" className={cn('p-0', className)}>
      <div
        className="flex w-full items-center gap-4 rounded-xl px-5 py-4 text-left"
        title={tooltip}
      >
        {Icon ? (
          <span className="flex h-11 w-11 shrink-0 items-center justify-center rounded-lg bg-hcl-light text-hcl-blue">
            <Icon className="h-5 w-5" aria-hidden />
          </span>
        ) : null}
        <span className="min-w-0">
          <span className="block text-[11px] font-semibold uppercase tracking-wider text-hcl-muted">
            {label}
          </span>
          <span className="block font-metric text-2xl font-bold tabular-nums text-hcl-navy">
            {value}
          </span>
          {caption ? (
            <span className="mt-0.5 block text-[10px] text-hcl-muted">{caption}</span>
          ) : null}
        </span>
      </div>
    </Surface>
  );
}

'use client';

import { Sparkline } from '@/components/ui/Sparkline';
import { cn } from '@/lib/utils';
import type { DashboardTrendPoint } from '@/types';

interface HeroMiniTrendProps {
  /**
   * Last-N daily totals. Component is forgiving — handles empty / undefined
   * arrays gracefully so it can render before the trend query resolves.
   */
  points?: DashboardTrendPoint[];
  daysLabel?: number;
  className?: string;
}

/**
 * The fourth tile in the hero metric row — an inline 60×24 sparkline over
 * the trend window. Lives next to the numeric tiles so the eye gets a
 * shape *and* an absolute number side-by-side. Uses the same
 * `--color-hcl-blue` token as the rest of the brand sparklines, with
 * dark-mode parity coming through the CSS variable.
 */
export function HeroMiniTrend({
  points,
  daysLabel = 30,
  className,
}: HeroMiniTrendProps) {
  const series = (points ?? []).map((p) => p.total ?? 0);
  const label = `${daysLabel}-day finding trend`;

  return (
    <div
      className={cn(
        'rounded-lg border border-border bg-surface/60 px-3 py-2',
        className,
      )}
      title={label}
    >
      <div className="flex items-center gap-1.5 text-[10px] font-semibold uppercase tracking-wider text-hcl-muted">
        {daysLabel}-day mini trend
      </div>
      <div className="mt-1">
        <Sparkline
          data={series}
          width={140}
          height={28}
          color="var(--color-hcl-blue)"
          ariaLabel={label}
        />
      </div>
    </div>
  );
}

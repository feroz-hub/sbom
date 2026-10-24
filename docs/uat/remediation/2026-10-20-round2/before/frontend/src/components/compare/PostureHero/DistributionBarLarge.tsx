'use client';

import { cn } from '@/lib/utils';

interface Props {
  added: number;
  severityChanged: number;
  unchanged: number;
  resolved: number;
}

const SEGMENTS = [
  {
    key: 'added' as const,
    color: 'bg-red-500 dark:bg-red-400',
    label: 'added',
  },
  {
    key: 'severityChanged' as const,
    color: 'bg-amber-500 dark:bg-amber-400',
    label: 'severity-changed',
  },
  {
    key: 'unchanged' as const,
    color: 'bg-slate-300 dark:bg-slate-600',
    label: 'unchanged',
  },
  {
    key: 'resolved' as const,
    color: 'bg-emerald-500 dark:bg-emerald-400',
    label: 'resolved',
  },
];

/**
 * The promoted distribution bar. Was 12px tall and grey; now 28px tall
 * with full-saturation severity colours and inline numeric labels.
 *
 * Reading order (left → right): added · severity-changed · unchanged ·
 * resolved. The "green sweeping in from the right" tells the safety story
 * at a glance.
 *
 * Empty-data state: when every segment is zero, renders a single muted
 * track with "no data" copy beneath. Caller (`<PostureHero />`) typically
 * doesn't render this in the identical-runs case — the IdenticalRunsCard
 * takes over the whole region.
 */
export function DistributionBarLarge({
  added,
  severityChanged,
  unchanged,
  resolved,
}: Props) {
  const counts = { added, severityChanged, unchanged, resolved };
  const total = added + severityChanged + unchanged + resolved;

  if (total === 0) {
    return (
      <div className="space-y-2">
        <div
          className="w-full bg-border-subtle"
          style={{
            height: 'var(--distribution-bar-height)',
            borderRadius: 'var(--distribution-bar-radius)',
          }}
          aria-hidden
        />
        <p className="text-xs text-hcl-muted">
          No findings on either side.
        </p>
      </div>
    );
  }

  return (
    <div className="space-y-2">
      <div
        role="img"
        aria-label={`Added ${added}, severity-changed ${severityChanged}, unchanged ${unchanged}, resolved ${resolved}`}
        className="flex w-full overflow-hidden bg-border-subtle"
        style={{
          height: 'var(--distribution-bar-height)',
          borderRadius: 'var(--distribution-bar-radius)',
        }}
      >
        {SEGMENTS.map((seg) => {
          const n = counts[seg.key];
          if (n === 0) return null;
          const pct = (n / total) * 100;
          // Hide the inline numeric label when the segment is too narrow
          // to fit it (~6%). The text would clip, the legend below covers
          // it anyway.
          const showLabel = pct >= 6;
          return (
            <div
              key={seg.key}
              className={cn(
                'relative flex items-center justify-center text-[11px] font-semibold text-white tabular-nums',
                'transition-[width] duration-slower ease-spring motion-reduce:transition-none',
                seg.color,
              )}
              style={{ width: `${pct}%` }}
              title={`${n.toLocaleString()} ${seg.label}`}
            >
              {showLabel && (
                <span aria-hidden className="px-1 leading-none">
                  {n.toLocaleString()}
                </span>
              )}
            </div>
          );
        })}
      </div>
      <ul className="flex flex-wrap gap-x-4 gap-y-1 text-xs text-hcl-muted">
        {SEGMENTS.map((seg) => {
          const n = counts[seg.key];
          if (n === 0) return null;
          return (
            <li key={seg.key} className="inline-flex items-center gap-1.5">
              <span
                aria-hidden
                className={cn('inline-block h-2 w-2 rounded-full', seg.color)}
              />
              {seg.label}:{' '}
              <strong className="text-hcl-navy">{n.toLocaleString()}</strong>
            </li>
          );
        })}
      </ul>
    </div>
  );
}

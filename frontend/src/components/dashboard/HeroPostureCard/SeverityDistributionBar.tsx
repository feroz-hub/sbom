'use client';

import { useMemo } from 'react';
import { cn } from '@/lib/utils';
import type { SeverityData } from '@/types';

interface SeverityDistributionBarProps {
  severity: SeverityData | undefined;
  className?: string;
}

const SEGMENTS: Array<{
  key: keyof Pick<SeverityData, 'critical' | 'high' | 'medium' | 'low'>;
  label: string;
  color: string;
}> = [
  { key: 'critical', label: 'Critical', color: '#C0392B' },
  { key: 'high', label: 'High', color: '#D4680A' },
  { key: 'medium', label: 'Medium', color: '#B8860B' },
  { key: 'low', label: 'Low', color: '#0067B1' },
];

/**
 * v2 severity distribution bar — h-7 (28px) per redesign §3.4. The taller
 * geometry anchors the eye on the severity ratio without making it loud;
 * proportions land harder than absolute numbers when scanning.
 *
 * Unknown is excluded from the bar (it's a data-quality signal, not a
 * tier — see `docs/terminology.md`) and rendered as a separate pill below.
 */
export function SeverityDistributionBar({
  severity,
  className,
}: SeverityDistributionBarProps) {
  const segments = useMemo(() => {
    if (!severity) return [];
    const totalSev =
      severity.critical + severity.high + severity.medium + severity.low;
    if (totalSev === 0) return [];
    return SEGMENTS.map((s) => ({
      ...s,
      value: severity[s.key],
      pct: (severity[s.key] / totalSev) * 100,
    })).filter((s) => s.value > 0);
  }, [severity]);

  const unknownCount = severity?.unknown ?? 0;
  const totalSev = segments.reduce((s, x) => s + x.value, 0);

  if (totalSev === 0) {
    return (
      <div className={cn('space-y-2', className)}>
        <div className="flex h-7 w-full items-center justify-center rounded-full bg-emerald-100 dark:bg-emerald-950/60">
          <span className="text-[11px] font-medium uppercase tracking-wider text-emerald-700 dark:text-emerald-300">
            No findings in scope
          </span>
        </div>
        {unknownCount > 0 && <UnknownPill count={unknownCount} />}
      </div>
    );
  }

  return (
    <div className={cn('space-y-2', className)}>
      <div
        role="img"
        aria-label={`Severity distribution: ${segments
          .map((s) => `${s.label} ${s.value}`)
          .join(', ')}`}
        className="flex h-7 w-full overflow-hidden rounded-full bg-border-subtle gap-px"
      >
        {segments.map((seg) => (
          <div
            key={seg.key}
            className="h-full transition-all duration-slower ease-spring"
            style={{
              width: `${seg.pct}%`,
              backgroundColor: seg.color,
            }}
            title={`${seg.label}: ${seg.value.toLocaleString()} (${seg.pct.toFixed(0)}%)`}
          />
        ))}
      </div>
      <div className="flex flex-wrap items-center gap-x-4 gap-y-1 text-xs text-hcl-muted">
        {segments.map((seg) => (
          <span key={seg.key} className="inline-flex items-center gap-1.5">
            <span
              className="h-2 w-2 rounded-full"
              style={{ backgroundColor: seg.color }}
              aria-hidden
            />
            {seg.label}:{' '}
            <strong className="font-metric tabular-nums text-hcl-navy">
              {seg.value.toLocaleString()}
            </strong>
          </span>
        ))}
        {unknownCount > 0 && <UnknownPill count={unknownCount} inline />}
      </div>
    </div>
  );
}

function UnknownPill({
  count,
  inline = false,
}: {
  count: number;
  inline?: boolean;
}) {
  return (
    <span
      className={cn(
        'inline-flex items-center gap-1.5 rounded-full bg-slate-100 px-2 py-0.5 text-[11px] text-slate-600 ring-1 ring-slate-200 dark:bg-slate-900/60 dark:text-slate-300 dark:ring-slate-700/60',
        !inline && 'mt-2',
      )}
      title="Unknown is a data-quality signal — these findings have no CVSS score in our feeds. Not counted in severity totals."
    >
      <span className="h-1.5 w-1.5 rounded-full bg-slate-400" aria-hidden />
      {count.toLocaleString()} with unscored severity
    </span>
  );
}

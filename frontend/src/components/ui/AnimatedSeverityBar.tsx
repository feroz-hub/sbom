'use client';

import { useEffect, useState } from 'react';
import { cn } from '@/lib/utils';

interface SeverityCounts {
  critical: number;
  high: number;
  medium: number;
  low: number;
  unknown?: number;
}

interface AnimatedSeverityBarProps {
  counts: SeverityCounts;
  /** Trigger the fill animation when this key changes (e.g. on completion). */
  triggerKey?: string | number;
  /** Compact mode reduces height. */
  compact?: boolean;
  className?: string;
}

const SEVERITY_DEFS = [
  { key: 'critical' as const, label: 'Critical', color: '#C0392B' },
  { key: 'high' as const, label: 'High', color: '#D4680A' },
  { key: 'medium' as const, label: 'Medium', color: '#B8860B' },
  { key: 'low' as const, label: 'Low', color: '#0067B1' },
  { key: 'unknown' as const, label: 'Unknown', color: '#6B7A8D' },
];

/**
 * Spring-eased severity bar. On `triggerKey` change, segments fill from
 * 0 → final width with a staggered delay so heaviest severities animate first.
 */
export function AnimatedSeverityBar({ counts, triggerKey, compact, className }: AnimatedSeverityBarProps) {
  const [armed, setArmed] = useState(false);
  const total =
    counts.critical + counts.high + counts.medium + counts.low + (counts.unknown ?? 0);

  // Re-arm on triggerKey change so the bar replays.
  useEffect(() => {
    setArmed(false);
    const id = window.requestAnimationFrame(() => {
      window.requestAnimationFrame(() => setArmed(true));
    });
    return () => window.cancelAnimationFrame(id);
  }, [triggerKey]);

  if (total === 0) {
    return (
      <div
        className={cn(
          'flex w-full items-center justify-center rounded-full bg-emerald-100 dark:bg-emerald-950/60',
          compact ? 'h-2' : 'h-3',
          className,
        )}
      >
        <span className="text-[9px] font-semibold uppercase tracking-wider text-emerald-700 dark:text-emerald-300">
          No findings
        </span>
      </div>
    );
  }

  return (
    <div className={cn('w-full', className)}>
      <div
        role="img"
        aria-label={`Severity distribution: ${SEVERITY_DEFS.map((d) => `${d.label} ${counts[d.key] ?? 0}`).join(', ')}`}
        className={cn(
          'relative flex w-full overflow-hidden rounded-full bg-border-subtle',
          compact ? 'h-2' : 'h-3',
        )}
      >
        {SEVERITY_DEFS.map((d, idx) => {
          const value = counts[d.key] ?? 0;
          if (value === 0) return null;
          const widthPct = (value / total) * 100;
          return (
            <div
              key={d.key}
              className="h-full transition-[width,opacity] ease-spring motion-reduce:transition-none"
              style={{
                width: armed ? `${widthPct}%` : '0%',
                opacity: armed ? 1 : 0,
                backgroundColor: d.color,
                transitionDuration: '700ms',
                transitionDelay: `${idx * 90}ms`,
              }}
              title={`${d.label}: ${value.toLocaleString()}`}
            />
          );
        })}
      </div>
    </div>
  );
}

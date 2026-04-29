import { cn } from '@/lib/utils';

interface CvssMeterProps {
  /** CVSS base score 0..10. Null/undefined renders a neutral placeholder. */
  score: number | null | undefined;
  /** CVSS spec version, e.g. "3.1", "4.0". Optional. */
  version?: string | null;
  /** Compact (no version chip, smaller bar) — for dense tables. */
  compact?: boolean;
  className?: string;
}

function bandFor(score: number): {
  bg: string;
  fill: string;
  text: string;
  label: string;
} {
  if (score >= 9) {
    return {
      bg: 'bg-red-100 dark:bg-red-950/40',
      fill: 'bg-red-600',
      text: 'text-red-700 dark:text-red-300',
      label: 'Critical',
    };
  }
  if (score >= 7) {
    return {
      bg: 'bg-orange-100 dark:bg-orange-950/40',
      fill: 'bg-orange-500',
      text: 'text-orange-700 dark:text-orange-300',
      label: 'High',
    };
  }
  if (score >= 4) {
    return {
      bg: 'bg-amber-100 dark:bg-amber-950/40',
      fill: 'bg-amber-500',
      text: 'text-amber-700 dark:text-amber-300',
      label: 'Medium',
    };
  }
  if (score > 0) {
    return {
      bg: 'bg-sky-100 dark:bg-sky-950/40',
      fill: 'bg-sky-600',
      text: 'text-sky-700 dark:text-sky-300',
      label: 'Low',
    };
  }
  return {
    bg: 'bg-border-subtle',
    fill: 'bg-hcl-muted',
    text: 'text-hcl-muted',
    label: 'None',
  };
}

/**
 * Compact CVSS score visualization — numeric score, severity-banded fill bar,
 * optional CVSS version chip.
 */
export function CvssMeter({ score, version, compact = false, className }: CvssMeterProps) {
  if (score == null) {
    return (
      <span
        className={cn('font-metric text-xs text-hcl-muted', className)}
        aria-label="No CVSS score"
      >
        —
      </span>
    );
  }

  const clamped = Math.max(0, Math.min(10, score));
  const band = bandFor(clamped);
  const widthPct = (clamped / 10) * 100;

  return (
    <div
      className={cn('inline-flex items-center gap-1.5', className)}
      title={`CVSS ${version ? `v${version} ` : ''}${clamped.toFixed(1)} — ${band.label}`}
      role="img"
      aria-label={`CVSS ${version ? `v${version} ` : ''}${clamped.toFixed(1)}, ${band.label}`}
    >
      <span className={cn('font-metric font-semibold tabular-nums', band.text, compact ? 'text-xs' : 'text-sm')}>
        {clamped.toFixed(1)}
      </span>
      <div
        className={cn(
          'overflow-hidden rounded-full',
          band.bg,
          compact ? 'h-1 w-10' : 'h-1.5 w-14',
        )}
      >
        <div
          className={cn('h-full rounded-full transition-[width] duration-slow ease-spring motion-reduce:transition-none', band.fill)}
          style={{ width: `${widthPct}%` }}
        />
      </div>
      {!compact && version && (
        <span className="font-metric rounded border border-border-subtle bg-surface-muted px-1 py-px text-[9px] font-semibold uppercase tracking-wider text-hcl-muted">
          v{version}
        </span>
      )}
    </div>
  );
}

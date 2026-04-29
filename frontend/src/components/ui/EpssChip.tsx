import { cn } from '@/lib/utils';

interface EpssChipProps {
  /** EPSS probability of exploitation (0..1). */
  epss: number;
  /** Percentile rank in EPSS catalog (0..1). Null when uncached. */
  percentile: number | null;
  /** Compact mode for dense table rows. */
  compact?: boolean;
  className?: string;
}

function bandFor(percentile: number | null): { tone: string; label: string } {
  if (percentile == null) {
    return { tone: 'bg-surface-muted text-hcl-muted ring-border-subtle', label: '—' };
  }
  if (percentile >= 0.95) {
    return {
      tone: 'bg-red-100 text-red-800 ring-red-300/60 dark:bg-red-950/60 dark:text-red-200 dark:ring-red-900/60',
      label: 'Top 5%',
    };
  }
  if (percentile >= 0.75) {
    return {
      tone: 'bg-orange-100 text-orange-800 ring-orange-300/60 dark:bg-orange-950/60 dark:text-orange-200 dark:ring-orange-900/60',
      label: 'High',
    };
  }
  if (percentile >= 0.4) {
    return {
      tone: 'bg-amber-100 text-amber-800 ring-amber-300/60 dark:bg-amber-950/60 dark:text-amber-200 dark:ring-amber-900/60',
      label: 'Medium',
    };
  }
  return {
    tone: 'bg-sky-50 text-sky-800 ring-sky-200 dark:bg-sky-950/40 dark:text-sky-300 dark:ring-sky-900/60',
    label: 'Low',
  };
}

/**
 * EPSS percentile chip — shows the FIRST.org EPSS exploit-likelihood
 * percentile with a tone scaled to the percentile bucket. The probability
 * itself is shown as a small label inside.
 */
export function EpssChip({ epss, percentile, compact = false, className }: EpssChipProps) {
  const band = bandFor(percentile);
  const epssPct = (epss * 100).toFixed(epss < 0.01 ? 2 : 1);
  const percentilePct = percentile != null ? (percentile * 100).toFixed(0) : null;

  return (
    <span
      title={
        percentile != null
          ? `EPSS ${epssPct}% — ${(percentile * 100).toFixed(1)}th percentile (${band.label})`
          : 'No EPSS data cached for this CVE yet'
      }
      aria-label={
        percentile != null
          ? `EPSS exploit probability ${epssPct} percent, ${(percentile * 100).toFixed(0)}th percentile`
          : 'No EPSS data'
      }
      className={cn(
        'inline-flex shrink-0 items-center gap-1 rounded-full ring-1 font-metric tabular-nums font-semibold',
        band.tone,
        compact ? 'h-5 px-1.5 text-[10px]' : 'h-5 px-2 text-[10px]',
        className,
      )}
    >
      {percentilePct != null ? (
        <>
          <span className="text-[9px] font-bold uppercase tracking-wider opacity-75">EPSS</span>
          <span>{percentilePct}%</span>
        </>
      ) : (
        <>
          <span className="text-[9px] font-bold uppercase tracking-wider opacity-75">EPSS</span>
          <span>—</span>
        </>
      )}
    </span>
  );
}

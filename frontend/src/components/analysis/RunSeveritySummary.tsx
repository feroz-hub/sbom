import type { AnalysisRun } from '@/types';

const buckets = [
  ['critical_count', 'Critical', 'C', 'bg-red-50 text-red-700 dark:bg-red-950/40 dark:text-red-200'],
  ['high_count', 'High', 'H', 'bg-orange-50 text-orange-700 dark:bg-orange-950/40 dark:text-orange-200'],
  ['medium_count', 'Medium', 'M', 'bg-amber-50 text-amber-700 dark:bg-amber-950/40 dark:text-amber-200'],
  ['low_count', 'Low', 'L', 'bg-sky-50 text-sky-700 dark:bg-sky-950/40 dark:text-sky-200'],
  ['unknown_count', 'Unknown', 'U', 'bg-surface-muted text-hcl-muted'],
] as const;

export function RunSeveritySummary({ run, expanded = false }: { run: AnalysisRun; expanded?: boolean }) {
  return <div className={expanded ? 'grid grid-cols-2 gap-2 sm:grid-cols-3 xl:grid-cols-6' : 'flex flex-wrap gap-1'}>
    {expanded && <div className="rounded-lg border border-border bg-surface-muted p-3">
      <p className="text-xs text-hcl-muted">Total findings</p>
      <p className="mt-1 text-2xl font-semibold tabular-nums text-hcl-navy">{run.total_findings?.toLocaleString() ?? 'Unavailable'}</p>
    </div>}
    {buckets.map(([key, label, short, tone]) => <div key={key}
      className={`${tone} ${expanded ? 'rounded-lg border border-border p-3' : 'rounded px-1.5 py-0.5 text-xs tabular-nums'}`}
      aria-label={`${label}: ${run[key] ?? 'unavailable'}`} title={`${label} findings`}>
      {expanded ? <><p className="text-xs">{label}</p><p className="mt-1 text-2xl font-semibold tabular-nums">{run[key]?.toLocaleString() ?? '—'}</p></>
        : `${short}:${run[key] ?? '—'}`}
    </div>)}
  </div>;
}

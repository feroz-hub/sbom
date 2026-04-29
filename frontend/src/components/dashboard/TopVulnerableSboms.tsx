'use client';

import Link from 'next/link';
import { useMemo } from 'react';
import { useQuery } from '@tanstack/react-query';
import { ArrowUpRight, ShieldAlert } from 'lucide-react';
import { Surface, SurfaceContent, SurfaceHeader } from '@/components/ui/Surface';
import { Skeleton } from '@/components/ui/Spinner';
import { EmptyState } from '@/components/ui/EmptyState';
import { getRuns } from '@/lib/api';
import { cn } from '@/lib/utils';
import type { AnalysisRun } from '@/types';

const TOP_N = 5;

interface SbomBucket {
  sbomId: number;
  sbomName: string;
  critical: number;
  high: number;
  medium: number;
  low: number;
  totalFindings: number;
  latestRunId: number;
  weighted: number;
}

function aggregateRuns(runs: AnalysisRun[]): SbomBucket[] {
  const buckets = new Map<number, SbomBucket>();
  // Keep only the latest run per SBOM (runs come back desc by id).
  for (const run of runs) {
    if (run.sbom_id == null) continue;
    if (buckets.has(run.sbom_id)) continue;
    const critical = run.critical_count ?? 0;
    const high = run.high_count ?? 0;
    const medium = run.medium_count ?? 0;
    const low = run.low_count ?? 0;
    const totalFindings = run.total_findings ?? 0;
    if (totalFindings === 0) continue;
    buckets.set(run.sbom_id, {
      sbomId: run.sbom_id,
      sbomName: run.sbom_name ?? `SBOM #${run.sbom_id}`,
      critical,
      high,
      medium,
      low,
      totalFindings,
      latestRunId: run.id,
      weighted: critical * 100 + high * 25 + medium * 8 + low * 2,
    });
  }
  return Array.from(buckets.values())
    .sort((a, b) => b.weighted - a.weighted)
    .slice(0, TOP_N);
}

export function TopVulnerableSboms() {
  // Pull the most recent FAIL runs — those are the ones with findings.
  const runsQuery = useQuery({
    queryKey: ['top-vulnerable-runs'],
    queryFn: ({ signal }) =>
      getRuns({ run_status: 'FAIL', page: 1, page_size: 100 }, signal),
  });

  const top = useMemo(() => aggregateRuns(runsQuery.data ?? []), [runsQuery.data]);
  const maxWeighted = top[0]?.weighted ?? 1;

  return (
    <Surface variant="elevated">
      <SurfaceHeader>
        <div>
          <h3 className="flex items-center gap-2 text-base font-semibold text-hcl-navy">
            <ShieldAlert className="h-4 w-4 text-red-600 dark:text-red-400" aria-hidden />
            Top vulnerable SBOMs
          </h3>
          <p className="mt-0.5 text-xs text-hcl-muted">
            Ranked by weighted severity across latest analysis runs.
          </p>
        </div>
        <Link
          href="/analysis?tab=runs&status=FAIL"
          className="inline-flex items-center gap-1 text-xs font-medium text-primary transition-colors hover:text-hcl-dark"
        >
          All failing runs <ArrowUpRight className="h-3 w-3" aria-hidden />
        </Link>
      </SurfaceHeader>
      <SurfaceContent>
        {runsQuery.isLoading ? (
          <ul className="space-y-3">
            {[0, 1, 2, 3, 4].map((i) => (
              <li key={i} className="flex items-center gap-3">
                <Skeleton className="h-8 w-8 rounded-md" />
                <div className="flex-1 space-y-2">
                  <Skeleton className="h-3 w-1/2" />
                  <Skeleton className="h-2 w-full" />
                </div>
              </li>
            ))}
          </ul>
        ) : runsQuery.error ? (
          <p className="text-sm text-red-700 dark:text-red-300">
            Failed to load runs: {runsQuery.error.message}
          </p>
        ) : top.length === 0 ? (
          <EmptyState
            illustration="all-clear"
            title="No vulnerable SBOMs"
            description="Every analyzed SBOM is currently free of findings."
            compact
          />
        ) : (
          <ul className="space-y-2.5 stagger">
            {top.map((bucket, idx) => {
              const widthPct = (bucket.weighted / maxWeighted) * 100;
              return (
                <li key={bucket.sbomId}>
                  <Link
                    href={`/analysis/${bucket.latestRunId}`}
                    className={cn(
                      'group flex items-center gap-3 rounded-lg border border-transparent px-2 py-2 transition-all duration-base ease-spring',
                      'hover:-translate-y-px hover:border-border-subtle hover:bg-surface-muted',
                      'focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-hcl-blue/40',
                    )}
                  >
                    <span className="flex h-8 w-8 shrink-0 items-center justify-center rounded-md bg-hcl-light font-metric text-xs font-bold text-hcl-navy">
                      {idx + 1}
                    </span>
                    <div className="min-w-0 flex-1 space-y-1.5">
                      <div className="flex items-baseline justify-between gap-2">
                        <span className="truncate text-sm font-medium text-hcl-navy group-hover:text-primary">
                          {bucket.sbomName}
                        </span>
                        <span className="font-metric text-xs text-hcl-muted">
                          {bucket.totalFindings.toLocaleString()} findings
                        </span>
                      </div>
                      {/* Severity stack bar */}
                      <div
                        className="flex h-1.5 w-full overflow-hidden rounded-full bg-border-subtle"
                        style={{ width: `${Math.max(20, widthPct)}%` }}
                        role="img"
                        aria-label={`Critical ${bucket.critical}, High ${bucket.high}, Medium ${bucket.medium}, Low ${bucket.low}`}
                      >
                        {bucket.critical > 0 && (
                          <div
                            className="h-full bg-red-600"
                            style={{ flex: bucket.critical, transition: 'flex 600ms var(--ease-spring)' }}
                          />
                        )}
                        {bucket.high > 0 && (
                          <div
                            className="h-full bg-orange-500"
                            style={{ flex: bucket.high }}
                          />
                        )}
                        {bucket.medium > 0 && (
                          <div
                            className="h-full bg-amber-500"
                            style={{ flex: bucket.medium }}
                          />
                        )}
                        {bucket.low > 0 && (
                          <div
                            className="h-full bg-sky-600"
                            style={{ flex: bucket.low }}
                          />
                        )}
                      </div>
                      <div className="flex flex-wrap gap-x-3 gap-y-0.5 text-[10px] text-hcl-muted">
                        {bucket.critical > 0 && (
                          <span>
                            <span className="mr-1 inline-block h-1.5 w-1.5 rounded-full bg-red-600" aria-hidden />
                            <strong className="font-metric text-hcl-navy">{bucket.critical}</strong> Critical
                          </span>
                        )}
                        {bucket.high > 0 && (
                          <span>
                            <span className="mr-1 inline-block h-1.5 w-1.5 rounded-full bg-orange-500" aria-hidden />
                            <strong className="font-metric text-hcl-navy">{bucket.high}</strong> High
                          </span>
                        )}
                        {bucket.medium > 0 && (
                          <span>
                            <span className="mr-1 inline-block h-1.5 w-1.5 rounded-full bg-amber-500" aria-hidden />
                            <strong className="font-metric text-hcl-navy">{bucket.medium}</strong> Medium
                          </span>
                        )}
                        {bucket.low > 0 && (
                          <span>
                            <span className="mr-1 inline-block h-1.5 w-1.5 rounded-full bg-sky-600" aria-hidden />
                            <strong className="font-metric text-hcl-navy">{bucket.low}</strong> Low
                          </span>
                        )}
                      </div>
                    </div>
                    <ArrowUpRight
                      className="h-3.5 w-3.5 shrink-0 text-hcl-border transition-colors group-hover:text-primary"
                      aria-hidden
                    />
                  </Link>
                </li>
              );
            })}
          </ul>
        )}
      </SurfaceContent>
    </Surface>
  );
}

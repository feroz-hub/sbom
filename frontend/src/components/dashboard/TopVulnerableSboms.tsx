'use client';

import Link from 'next/link';
import { useMemo } from 'react';
import { useQuery } from '@tanstack/react-query';
import { ArrowUpRight, ShieldAlert } from 'lucide-react';
import { Surface, SurfaceContent, SurfaceHeader } from '@/components/ui/Surface';
import { Skeleton } from '@/components/ui/Spinner';
import { EmptyState } from '@/components/ui/EmptyState';
import { getRuns } from '@/lib/api';
import { aggregateRuns, type SeverityKey } from '@/lib/topVulnerableRuns';
import { severityKeyToParam } from '@/lib/severityParam';
import { cn } from '@/lib/utils';

const TOP_N = 5;

// Severity legend/badge config — colors mirror the stack-bar segments below.
const SEVERITY_BADGES: Array<{ key: SeverityKey; label: string; dot: string }> = [
  { key: 'critical', label: 'Critical', dot: 'bg-red-600' },
  { key: 'high', label: 'High', dot: 'bg-orange-500' },
  { key: 'medium', label: 'Medium', dot: 'bg-amber-500' },
  { key: 'low', label: 'Low', dot: 'bg-sky-600' },
];

export function TopVulnerableSboms() {
  // Pull the most recent runs that produced findings.
  // ADR-0001 renamed this status from FAIL to FINDINGS.
  const runsQuery = useQuery({
    queryKey: ['top-vulnerable-runs'],
    queryFn: ({ signal }) =>
      getRuns({ run_status: 'FINDINGS', page: 1, page_size: 100 }, signal),
  });

  // aggregateRuns returns the full ranked set; this panel shows the top N.
  const top = useMemo(
    () => aggregateRuns(runsQuery.data ?? []).slice(0, TOP_N),
    [runsQuery.data],
  );
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
          href="/analysis?tab=runs&status=FINDINGS"
          className="inline-flex items-center gap-1 text-xs font-medium text-primary transition-colors hover:text-hcl-dark"
        >
          All runs with findings <ArrowUpRight className="h-3 w-3" aria-hidden />
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
                  {/* The row container owns hover/focus affordance. The main
                      link (→ unfiltered run) and the per-severity deep-link
                      badges are SIBLINGS — nesting <a> in <a> is invalid. */}
                  <div
                    className={cn(
                      'group rounded-lg border border-transparent px-2 py-2 transition-all duration-base ease-spring',
                      'hover:-translate-y-px hover:border-border-subtle hover:bg-surface-muted',
                    )}
                  >
                    <Link
                      href={`/analysis/${bucket.latestRunId}`}
                      className="flex items-center gap-3 rounded-lg focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-hcl-blue/40"
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
                      </div>
                      <ArrowUpRight
                        className="h-3.5 w-3.5 shrink-0 text-hcl-border transition-colors group-hover:text-primary"
                        aria-hidden
                      />
                    </Link>
                    {/* Per-severity deep-links — drill into THIS app's run
                        pre-filtered to one tier. Run-scoped, so no globalCount
                        (and therefore no reconciliation banner). */}
                    <div className="mt-1.5 flex flex-wrap gap-x-1 gap-y-0.5 pl-11 text-[10px] text-hcl-muted">
                      {SEVERITY_BADGES.map((sev) => {
                        const value = bucket[sev.key];
                        if (value <= 0) return null;
                        return (
                          <Link
                            key={sev.key}
                            href={`/analysis/${bucket.latestRunId}?severity=${severityKeyToParam(sev.key)}`}
                            aria-label={`View ${sev.label} findings for ${bucket.sbomName}`}
                            className="inline-flex items-center gap-1 rounded px-1 py-0.5 transition-colors hover:bg-surface hover:text-hcl-navy focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-hcl-blue/40"
                          >
                            <span className={cn('inline-block h-1.5 w-1.5 rounded-full', sev.dot)} aria-hidden />
                            <strong className="font-metric text-hcl-navy">{value}</strong> {sev.label}
                          </Link>
                        );
                      })}
                    </div>
                  </div>
                </li>
              );
            })}
          </ul>
        )}
      </SurfaceContent>
    </Surface>
  );
}

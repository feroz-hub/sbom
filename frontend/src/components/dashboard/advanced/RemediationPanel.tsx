'use client';

import { useQuery } from '@tanstack/react-query';
import { RefreshCw, Timer } from 'lucide-react';
import { Surface, SurfaceContent, SurfaceHeader } from '@/components/ui/Surface';
import { Spinner } from '@/components/ui/Spinner';
import { EmptyState } from '@/components/ui/EmptyState';
import { Button } from '@/components/ui/Button';
import { getDashboardRemediation, getDashboardRemediationStats } from '@/lib/api';
import { cn } from '@/lib/utils';
import type { SlaSeverity } from '@/types';

/**
 * Remediation & SLA panel — "are we fixing things fast enough?".
 *
 * Three reads in one card:
 *  1. MTTR by severity vs its SLA budget (CISA-BOD-19-02-flavoured
 *     defaults: 7/30/90/180 days) — measured from finding lifecycles
 *     across run history.
 *  2. 30-day fix velocity — inflow vs outflow with the net direction.
 *  3. SLA countdown — overdue / due-soon / on-track counts plus the worst
 *     offenders with how far past budget each one is.
 */

const SEVERITY_COLOR: Record<string, string> = {
  critical: '#C0392B',
  high: '#D4680A',
  medium: '#B8860B',
  low: '#0067B1',
  unknown: '#5B7083',
};

const MTTR_ORDER: SlaSeverity[] = ['critical', 'high', 'medium', 'low'];

export function RemediationPanel() {
  const query = useQuery({
    queryKey: ['dashboard-remediation'],
    queryFn: ({ signal }) => getDashboardRemediation(signal),
  });
  const statsQuery = useQuery({
    queryKey: ['dashboard-remediation-stats'],
    queryFn: ({ signal }) => getDashboardRemediationStats(signal),
  });
  const data = query.data;
  const stats = statsQuery.data;
  const sla = data?.sla;
  const offenders = sla?.worst_offenders ?? [];
  const velocity = data?.velocity;
  const counts = stats?.status_counts ?? {};
  const openCount = counts.open ?? 0;
  const inProgressCount = counts.in_progress ?? 0;
  const fixedCount = counts.fixed ?? 0;
  const acceptedRiskCount = counts.accepted_risk ?? 0;
  const statusTotal = Object.values(counts).reduce((sum, value) => sum + value, 0);
  const hasAnyActivity =
    (data?.resolved_total ?? 0) > 0 ||
    statusTotal > 0 ||
    (stats?.aging_count ?? 0) > 0 ||
    (sla && sla.overdue + sla.due_soon + sla.ok > 0);
  const isLoading = query.isLoading || statsQuery.isLoading;
  const isError = query.isError || statsQuery.isError;

  const refetch = () => {
    void query.refetch();
    void statsQuery.refetch();
  };

  return (
    <Surface variant="elevated">
      <SurfaceHeader>
        <div>
          <h3 className="text-base font-semibold text-hcl-navy">Remediation &amp; SLA</h3>
          <p className="mt-0.5 text-xs text-hcl-muted">
            Time-to-remediate vs budget · 30-day fix velocity · countdowns per active finding
          </p>
        </div>
        {sla && sla.overdue > 0 && (
          <span className="inline-flex items-center gap-1.5 rounded-full bg-red-50 px-2.5 py-1 text-xs font-semibold text-red-700 dark:bg-red-950/40 dark:text-red-300">
            <Timer className="h-3.5 w-3.5" aria-hidden />
            {sla.overdue.toLocaleString()} past SLA
          </span>
        )}
      </SurfaceHeader>
      <SurfaceContent>
        {isLoading ? (
          <div className="flex h-48 items-center justify-center">
            <Spinner />
          </div>
        ) : isError ? (
          <EmptyState
            illustration="generic"
            title="Remediation metrics unavailable"
            description="The dashboard could not load remediation status or SLA data."
            action={
              <Button variant="secondary" size="sm" onClick={refetch}>
                <RefreshCw className="h-3.5 w-3.5" aria-hidden />
                Retry
              </Button>
            }
            compact
          />
        ) : !data || !hasAnyActivity ? (
          <EmptyState
            illustration="generic"
            title="No remediation history yet"
            description="Lifecycle metrics appear once findings are detected and later resolved across runs."
            compact
          />
        ) : (
          <div className="space-y-4">
            <div className="grid grid-cols-2 gap-2 md:grid-cols-3 xl:grid-cols-6">
              {[
                { label: 'Open', value: openCount, tone: 'text-red-700 dark:text-red-300' },
                { label: 'In progress', value: inProgressCount, tone: 'text-amber-700 dark:text-amber-300' },
                { label: 'Fixed', value: fixedCount, tone: 'text-emerald-700 dark:text-emerald-300' },
                { label: 'Accepted risk', value: acceptedRiskCount, tone: 'text-violet-700 dark:text-violet-300' },
                { label: 'Overdue', value: stats?.sla.overdue ?? sla?.overdue ?? 0, tone: 'text-red-700 dark:text-red-300' },
                { label: 'Aging 30d', value: stats?.aging_count ?? 0, tone: 'text-hcl-navy dark:text-white' },
              ].map((item) => (
                <div key={item.label} className="rounded-lg bg-surface-muted px-3 py-2">
                  <div className={cn('font-metric text-lg font-bold tabular-nums', item.tone)}>
                    {item.value.toLocaleString()}
                  </div>
                  <div className="text-[10px] font-medium uppercase tracking-wider text-hcl-muted">
                    {item.label}
                  </div>
                </div>
              ))}
            </div>

            <div className="grid grid-cols-1 gap-4 lg:grid-cols-3">
              {/* MTTR vs budget */}
              <div>
                <h4 className="text-[10px] font-medium uppercase tracking-wider text-hcl-muted">
                  Mean time to remediate
                </h4>
                <ul className="mt-1.5 space-y-1">
                  {MTTR_ORDER.map((sev) => {
                    const mttr = data.mttr_days?.[sev];
                    const budget = sla?.budgets_days?.[sev];
                    const over = mttr != null && budget != null && mttr > budget;
                    return (
                      <li key={sev} className="flex items-center justify-between gap-2 text-xs">
                        <span className="flex items-center gap-2 capitalize text-hcl-navy">
                          <span
                            className="h-2 w-2 rounded-full"
                            style={{ backgroundColor: SEVERITY_COLOR[sev] }}
                            aria-hidden
                          />
                          {sev}
                        </span>
                        <span className="font-metric tabular-nums">
                          {mttr != null ? (
                            <>
                              <span className={cn('font-semibold', over ? 'text-red-600 dark:text-red-400' : 'text-hcl-navy')}>
                                {mttr}d
                              </span>
                              <span className="text-hcl-muted"> / {budget}d</span>
                            </>
                          ) : (
                            <span className="text-hcl-muted">— / {budget}d</span>
                          )}
                        </span>
                      </li>
                    );
                  })}
                </ul>
                <p className="mt-1.5 text-[10px] text-hcl-muted">
                  {data.resolved_total.toLocaleString()} resolved lifecycles
                  {data.reopened_total > 0 && ` · ${data.reopened_total} reopened`}
                </p>
              </div>

              {/* Velocity */}
              <div>
                <h4 className="text-[10px] font-medium uppercase tracking-wider text-hcl-muted">
                  Fix velocity ({velocity?.window_days ?? 30}d)
                </h4>
                <div className="mt-1.5 flex items-end gap-4">
                  <div>
                    <div className="font-metric text-xl font-bold text-hcl-navy">
                      {velocity?.new_findings.toLocaleString() ?? 0}
                    </div>
                    <div className="text-[10px] text-hcl-muted">new</div>
                  </div>
                  <div>
                    <div className="font-metric text-xl font-bold text-emerald-700 dark:text-emerald-400">
                      {velocity?.resolved_findings.toLocaleString() ?? 0}
                    </div>
                    <div className="text-[10px] text-hcl-muted">resolved</div>
                  </div>
                  <div
                    className={cn(
                      'mb-0.5 rounded-full px-2 py-0.5 text-xs font-semibold',
                      (velocity?.net ?? 0) > 0
                        ? 'bg-red-50 text-red-700 dark:bg-red-950/40 dark:text-red-300'
                        : 'bg-emerald-50 text-emerald-700 dark:bg-emerald-950/40 dark:text-emerald-300',
                    )}
                  >
                    {(velocity?.net ?? 0) > 0 ? '+' : ''}
                    {velocity?.net ?? 0} net
                  </div>
                </div>
                <p className="mt-1.5 text-[10px] text-hcl-muted">
                  {(velocity?.net ?? 0) > 0
                    ? 'Inflow is outpacing fixes — debt is growing.'
                    : 'Fixes are keeping pace with inflow.'}
                </p>
              </div>

              {/* SLA counts */}
              <div>
                <h4 className="text-[10px] font-medium uppercase tracking-wider text-hcl-muted">
                  SLA status (active findings)
                </h4>
                <div className="mt-1.5 flex gap-2">
                  <div className="flex-1 rounded-lg bg-red-50 px-2.5 py-2 text-center dark:bg-red-950/30">
                    <div className="font-metric text-lg font-bold text-red-700 dark:text-red-300">
                      {sla?.overdue.toLocaleString() ?? 0}
                    </div>
                    <div className="text-[10px] font-medium text-red-700/80 dark:text-red-300/80">overdue</div>
                  </div>
                  <div className="flex-1 rounded-lg bg-amber-50 px-2.5 py-2 text-center dark:bg-amber-950/30">
                    <div className="font-metric text-lg font-bold text-amber-700 dark:text-amber-300">
                      {sla?.due_soon.toLocaleString() ?? 0}
                    </div>
                    <div className="text-[10px] font-medium text-amber-700/80 dark:text-amber-300/80">due soon</div>
                  </div>
                  <div className="flex-1 rounded-lg bg-emerald-50 px-2.5 py-2 text-center dark:bg-emerald-950/30">
                    <div className="font-metric text-lg font-bold text-emerald-700 dark:text-emerald-300">
                      {sla?.ok.toLocaleString() ?? 0}
                    </div>
                    <div className="text-[10px] font-medium text-emerald-700/80 dark:text-emerald-300/80">on track</div>
                  </div>
                </div>
                <p className="mt-1.5 text-[10px] text-hcl-muted">
                  Budgets: C {sla?.budgets_days.critical}d · H {sla?.budgets_days.high}d · M{' '}
                  {sla?.budgets_days.medium}d · L {sla?.budgets_days.low}d
                </p>
              </div>
            </div>

            {/* Worst offenders */}
            {offenders.length > 0 && (
              <div className="border-t border-border-subtle pt-3">
                <h4 className="text-[10px] font-medium uppercase tracking-wider text-hcl-muted">
                  Longest past budget
                </h4>
                <ul className="mt-1.5 space-y-1.5">
                  {offenders.map((o) => {
                    const pct = Math.min(100, (o.age_days / Math.max(1, o.sla_days)) * 100);
                    return (
                      <li
                        key={`${o.vuln_id}-${o.component_name}-${o.component_version}`}
                        className="flex items-center gap-3 text-xs"
                      >
                        <span
                          className="h-2 w-2 shrink-0 rounded-full"
                          style={{ backgroundColor: SEVERITY_COLOR[o.severity] }}
                          aria-hidden
                        />
                        <span className="w-36 shrink-0 truncate font-metric font-medium text-hcl-navy">
                          {o.vuln_id || '(no id)'}
                        </span>
                        <span className="min-w-0 flex-1 truncate text-hcl-muted">
                          {o.component_name}@{o.component_version} · {o.sbom_name}
                        </span>
                        <span className="relative hidden h-1.5 w-24 overflow-hidden rounded-full bg-surface-muted sm:block" aria-hidden>
                          <span
                            className="absolute inset-y-0 left-0 rounded-full bg-red-500/80"
                            style={{ width: `${pct}%` }}
                          />
                        </span>
                        <span className="w-16 shrink-0 text-right font-metric font-semibold tabular-nums text-red-600 dark:text-red-400">
                          +{o.days_over}d
                        </span>
                      </li>
                    );
                  })}
                </ul>
              </div>
            )}
          </div>
        )}
      </SurfaceContent>
    </Surface>
  );
}

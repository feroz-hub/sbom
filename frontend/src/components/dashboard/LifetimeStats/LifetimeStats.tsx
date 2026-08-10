'use client';

import { Skeleton } from '@/components/ui/Spinner';
import { pluralize } from '@/lib/pluralize';
import type { LifetimeMetrics } from '@/types';
import { LifetimeStatTile } from './LifetimeStatTile';

interface LifetimeStatsProps {
  data: LifetimeMetrics | undefined;
  isLoading: boolean;
}

/**
 * "Your Analyzer, So Far" — the cumulative-value panel.
 *
 * Four growth metrics that only go up over time. Answers the user's
 * implicit question "has the tool been working for me?" without surfacing
 * deltas — the implicit story is the steadiness, not the wobble.
 *
 * Layout / copy locked in `docs/dashboard-redesign.md` §6.
 */
export function LifetimeStats({ data, isLoading }: LifetimeStatsProps) {
  if (isLoading) {
    return (
      <section aria-labelledby="lifetime-heading" className="space-y-3">
        <h3
          id="lifetime-heading"
          className="text-xs font-semibold uppercase tracking-wider text-hcl-muted"
        >
          Your Analyzer, So Far
        </h3>
        <div className="grid grid-cols-2 gap-4 lg:grid-cols-4">
          {[0, 1, 2, 3].map((i) => (
            <div
              key={i}
              className="rounded-xl border border-l-4 border-border border-l-hcl-blue bg-surface px-6 py-5"
            >
              <Skeleton className="h-3 w-20" />
              <Skeleton className="mt-3 h-10 w-16" />
              <Skeleton className="mt-2 h-3 w-24" />
            </div>
          ))}
        </div>
      </section>
    );
  }

  const sboms = data?.sboms_scanned_total ?? 0;
  const projects = data?.projects_total ?? 0;
  const runsTotal = data?.runs_executed_total ?? 0;
  const runsThisWeek = data?.runs_executed_this_week ?? 0;
  const surfaced = data?.findings_surfaced_total ?? 0;
  const resolved = data?.findings_resolved_total ?? 0;
  const days = data?.days_monitoring ?? 0;
  const firstRun = data?.first_run_at;

  // Format the "since" line — short month / day for the firstRun, or a
  // calm fallback when nothing has run yet.
  let sinceLine = 'ready when you are';
  if (firstRun) {
    const dt = new Date(firstRun);
    if (!Number.isNaN(dt.getTime())) {
      const month = dt.toLocaleString('en-US', { month: 'short' });
      sinceLine = `since ${month} ${dt.getDate()}`;
    }
  }

  return (
    <section aria-labelledby="lifetime-heading" className="space-y-3">
      <div className="flex items-baseline justify-between">
        <h3
          id="lifetime-heading"
          className="text-xs font-semibold uppercase tracking-wider text-hcl-muted"
        >
          Your Analyzer, So Far
        </h3>
        <p className="text-[11px] text-hcl-muted">
          Growth metrics — they only go up.
        </p>
      </div>
      <div className="grid grid-cols-2 gap-4 lg:grid-cols-4">
        <LifetimeStatTile
          label="SBOMs scanned"
          value={sboms.toLocaleString()}
          caption={
            projects > 0
              ? `across ${pluralize(projects, 'project', 'projects')}`
              : 'no projects yet'
          }
        />
        <LifetimeStatTile
          label="Runs executed"
          value={runsTotal.toLocaleString()}
          caption={
            runsThisWeek > 0
              ? `${runsThisWeek.toLocaleString()} this week`
              : 'none this week'
          }
        />
        <LifetimeStatTile
          label="Findings surfaced"
          value={surfaced.toLocaleString()}
          caption={
            surfaced > 0
              ? `${resolved.toLocaleString()} resolved to date`
              : 'no findings yet'
          }
        />
        <LifetimeStatTile
          label="Monitoring for"
          value={
            days === 0 && !firstRun
              ? '—'
              : `${days.toLocaleString()} ${pluralize(days, 'day', 'days').replace(/^\d[\d,]*\s/, '')}`
          }
          caption={sinceLine}
        />
      </div>
    </section>
  );
}

'use client';

import { CalendarClock, ShieldAlert, Waypoints } from 'lucide-react';
import { Skeleton } from '@/components/ui/Spinner';
import { Surface } from '@/components/ui/Surface';
import { pluralize } from '@/lib/pluralize';
import type { LifetimeMetrics } from '@/types';
import { LifetimeStatTile } from './LifetimeStatTile';

interface LifetimeStatsProps {
  data: LifetimeMetrics | undefined;
  /**
   * Vulnerabilities across the portfolio, from `posture.total_findings`
   * (`findings.latest_per_sbom.total`).
   *
   * Deliberately NOT `lifetime.findings_surfaced_total`: that field is
   * Convention B (distinct CVE+component+version ever seen) and reads as a
   * bug sitting above a severity bar built from Convention A. Sourcing this
   * tile from the same payload as the severity bar, KEV and Critical tiles
   * means the whole screen can only ever agree.
   */
  findingsTotal: number | undefined;
  isLoading: boolean;
}

/**
 * The cumulative-value panel: three growth metrics that only go up over time.
 *
 * Answers the user's implicit question "has the tool been working for me?"
 * without surfacing deltas — the story is the steadiness, not the wobble.
 * Renders with no section heading; the tile labels carry the meaning.
 *
 * SBOM count deliberately lives in `CounterTiles` only — it appeared in both
 * panels and the duplicate read as a discrepancy whenever the two were
 * scoped differently.
 *
 * Layout / copy originally from `docs/dashboard-redesign.md` §6.
 */
export function LifetimeStats({ data, findingsTotal, isLoading }: LifetimeStatsProps) {
  if (isLoading) {
    return (
      <section aria-label="Lifetime totals" className="space-y-3">
        <div className="grid grid-cols-1 gap-4 sm:grid-cols-3">
          {[0, 1, 2].map((i) => (
            <Surface key={i} variant="elevated" className="p-0">
              <div className="flex w-full items-center gap-4 rounded-xl px-5 py-4">
                <Skeleton className="h-11 w-11 shrink-0 rounded-lg" />
                <span className="min-w-0 flex-1">
                  <Skeleton className="h-3 w-24" />
                  <Skeleton className="mt-1 h-7 w-16" />
                  <Skeleton className="mt-1 h-2.5 w-28" />
                </span>
              </div>
            </Surface>
          ))}
        </div>
      </section>
    );
  }

  const runsTotal = data?.runs_executed_total ?? 0;
  const runsThisWeek = data?.runs_executed_this_week ?? 0;
  const findings = findingsTotal ?? 0;
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
    <section aria-label="Lifetime totals" className="space-y-3">
      <div className="grid grid-cols-1 gap-4 sm:grid-cols-3">
        <LifetimeStatTile
          label="Vulnerabilities found so far"
          value={findings.toLocaleString()}
          icon={ShieldAlert}
          caption={
            findings === 0 ? 'no vulnerabilities yet' : 'across all SBOMs, latest scan of each'
          }
          tooltip={
            'Every vulnerability in the most recent completed scan of each SBOM. ' +
            'This is the same set the severity breakdown, KEV and Critical tiles count, ' +
            'so the numbers on this page always agree. Re-scanning an SBOM replaces its ' +
            'contribution rather than adding to it, so fixing something makes this go down.'
          }
        />
        <LifetimeStatTile
          label="Analysis runs completed"
          value={runsTotal.toLocaleString()}
          icon={Waypoints}
          caption={
            runsThisWeek > 0
              ? `${runsThisWeek.toLocaleString()} this week`
              : 'none this week'
          }
          tooltip="Every analysis run recorded, across all SBOMs and projects."
        />
        <LifetimeStatTile
          label="Monitoring for"
          value={
            days === 0 && !firstRun
              ? '—'
              : `${days.toLocaleString()} ${pluralize(days, 'day', 'days').replace(/^\d[\d,]*\s/, '')}`
          }
          icon={CalendarClock}
          caption={sinceLine}
          tooltip="Days elapsed since the first completed analysis run."
        />
      </div>
    </section>
  );
}

'use client';

import Link from 'next/link';
import { Filter, X } from 'lucide-react';
import type { DrilldownDimension } from '@/hooks/useFindingsFilterFromUrl';

interface DrilldownReconciliationBannerProps {
  dimension: DrilldownDimension;
  /** Human label for a severity drill-down, e.g. "Critical". */
  severityLabel?: string;
  /** Portfolio-wide count the user clicked on the dashboard hero. */
  globalCount: number;
  /** Filtered finding count in THIS run, when known (severity drill-downs
   *  carry an exact server count; client-side kev/fix narrowing may omit it). */
  inRunCount?: number;
  /** Clears the drill-down filter and returns to the unfiltered run view. */
  onClear: () => void;
}

function dimensionNoun(dimension: DrilldownDimension, severityLabel?: string): string {
  switch (dimension) {
    case 'severity':
      return severityLabel ? `${severityLabel} findings` : 'findings';
    case 'kev':
      return 'KEV-listed findings';
    case 'fix':
      return 'findings with a fix available';
    case 'epss':
      return 'likely-exploited findings (high EPSS)';
    case 'review':
      return 'findings that need review';
  }
}

/**
 * Reconciliation banner shown when a user arrives at a run via a dashboard
 * hero drill-down. The hero counts are portfolio-wide (latest successful run
 * per SBOM); a drill-down lands on ONE run, so the count here is naturally a
 * subset. This banner makes that relationship explicit instead of leaving the
 * user wondering why "Critical: 42" on the dashboard shows fewer rows here.
 *
 * Only rendered when `globalCount` is present (hero drill-downs). Per-app
 * badges in TopVulnerableSboms are already run-scoped and omit `globalCount`,
 * so they filter without this banner.
 */
export function DrilldownReconciliationBanner({
  dimension,
  severityLabel,
  globalCount,
  inRunCount,
  onClear,
}: DrilldownReconciliationBannerProps) {
  const noun = dimensionNoun(dimension, severityLabel);

  return (
    <div
      role="status"
      className="flex flex-wrap items-center gap-x-3 gap-y-2 rounded-lg border border-sky-200 bg-sky-50/70 px-4 py-2.5 text-sm text-sky-900 dark:border-sky-900 dark:bg-sky-950/30 dark:text-sky-200"
    >
      <Filter className="h-4 w-4 shrink-0 text-sky-600 dark:text-sky-400" aria-hidden />
      <p className="min-w-0 flex-1 leading-relaxed">
        Filtered from the dashboard to{' '}
        <strong className="font-semibold">{noun}</strong>.{' '}
        {inRunCount != null ? (
          <>
            Showing{' '}
            <strong className="font-metric tabular-nums">
              {inRunCount.toLocaleString()}
            </strong>{' '}
            in this run ·{' '}
          </>
        ) : null}
        <strong className="font-metric tabular-nums">
          {globalCount.toLocaleString()}
        </strong>{' '}
        across the latest run of every SBOM.{' '}
        <Link
          href="/analysis?tab=runs"
          className="font-medium underline decoration-sky-400 underline-offset-2 hover:text-sky-700 dark:hover:text-sky-100"
        >
          View all runs
        </Link>
      </p>
      <button
        type="button"
        onClick={onClear}
        className="inline-flex shrink-0 items-center gap-1 rounded-md border border-sky-300 px-2 py-1 text-xs font-medium text-sky-800 transition-colors hover:bg-sky-100 focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-sky-400 dark:border-sky-800 dark:text-sky-200 dark:hover:bg-sky-900/40"
      >
        <X className="h-3 w-3" aria-hidden />
        Clear filter
      </button>
    </div>
  );
}

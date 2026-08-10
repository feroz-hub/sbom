'use client';

import { useSearchParams } from 'next/navigation';
import { normalizeSeverityParam } from '@/lib/severityParam';

/**
 * Drill-down dimension that brought the user to a run-detail page. `null`
 * when the page was opened directly (no deep-link params).
 */
export type DrilldownDimension = 'severity' | 'kev' | 'fix' | 'epss' | 'review';

export interface FindingsFilterFromUrl {
  /** Canonical UPPERCASE severity, or '' when absent/unrecognized. Seeds the
   *  `severityFilter` state that feeds `['findings-enriched', id, severityFilter]`
   *  AND the `?severity=` API param — they are the same value by construction. */
  severityFromUrl: string;
  /** Seeds `filter.kevOnly` (client-side narrowing). */
  kevOnlyFromUrl: boolean;
  /** Seeds `filter.hasFixOnly` (client-side narrowing). */
  hasFixOnlyFromUrl: boolean;
  /** Minimum EPSS percentile (0–100) from `?epss=`; 0 = no narrowing. Seeds
   *  `filter.epssMinPct` (client-side). Powers the "likely-exploited"
   *  drill-down — the destination filter already supports it. */
  epssMinPctFromUrl: number;
  /** `?review=1` — seeds `filter.matchReasonFilter='not_verified'` to surface
   *  low-confidence / unverified matches that need a human look. */
  needsReviewFromUrl: boolean;
  /** Portfolio-wide count the user clicked on the dashboard hero, passed so
   *  the destination can reconcile "this run vs. all SBOMs" without a second
   *  dashboard round-trip. `null` when not a hero drill-down (e.g. a per-app
   *  badge, which is already run-scoped and needs no reconciliation). */
  globalCount: number | null;
  /** Which tile/segment was clicked, or `null` for a direct visit. */
  drilldownDimension: DrilldownDimension | null;
  /** True when ANY drill-down param is present (severity/kev/fix). */
  hasDrilldown: boolean;
}

function readBool(raw: string | null): boolean {
  return raw === '1' || raw === 'true';
}

/**
 * Reads drill-down params from the URL on the run-detail page.
 *
 * This is the destination half of the drill-down chain. The value it returns
 * is fed straight into the page's `severityFilter`/`filter` state, which in
 * turn keys the findings query — closing the loop:
 *
 *   click → router.push('/analysis/{id}?severity=CRITICAL&globalCount=M')
 *         → useFindingsFilterFromUrl() reads `severity`
 *         → seeds severityFilter='CRITICAL'
 *         → ['findings-enriched', id, 'CRITICAL'] + GET ...?severity=CRITICAL
 *
 * MUST be called inside a `<Suspense>` boundary (App Router requirement for
 * `useSearchParams`) — see app/analysis/[id]/page.tsx.
 */
export function useFindingsFilterFromUrl(): FindingsFilterFromUrl {
  const params = useSearchParams();

  const severityFromUrl = normalizeSeverityParam(params.get('severity'));
  const kevOnlyFromUrl = readBool(params.get('kev'));
  const hasFixOnlyFromUrl = readBool(params.get('fix'));
  const needsReviewFromUrl = readBool(params.get('review'));

  const rawEpss = params.get('epss');
  const parsedEpss = rawEpss != null ? Number.parseInt(rawEpss, 10) : NaN;
  const epssMinPctFromUrl =
    Number.isFinite(parsedEpss) && parsedEpss > 0 ? Math.min(parsedEpss, 100) : 0;

  const rawGlobal = params.get('globalCount');
  const parsedGlobal = rawGlobal != null ? Number.parseInt(rawGlobal, 10) : NaN;
  const globalCount =
    Number.isFinite(parsedGlobal) && parsedGlobal >= 0 ? parsedGlobal : null;

  // Precedence for the banner label when several params co-exist: the most
  // specific server narrowing (severity) first, then exploitability signals.
  const drilldownDimension: DrilldownDimension | null = severityFromUrl
    ? 'severity'
    : epssMinPctFromUrl > 0
      ? 'epss'
      : kevOnlyFromUrl
        ? 'kev'
        : hasFixOnlyFromUrl
          ? 'fix'
          : needsReviewFromUrl
            ? 'review'
            : null;

  return {
    severityFromUrl,
    kevOnlyFromUrl,
    hasFixOnlyFromUrl,
    epssMinPctFromUrl,
    needsReviewFromUrl,
    globalCount,
    drilldownDimension,
    hasDrilldown: drilldownDimension != null,
  };
}

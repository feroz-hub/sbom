/**
 * Canonical owner of the severity ⇆ URL/API param conversion.
 *
 * The whole drill-down chain agrees on ONE canonical form: **UPPERCASE**
 * (`CRITICAL`, `HIGH`, `MEDIUM`, `LOW`, `UNKNOWN`). That is what:
 *   - the URL carries          (`/analysis/{id}?severity=CRITICAL`)
 *   - the page state holds      (`severityFilter`)
 *   - the query key is keyed by (`['findings-enriched', id, severityFilter]`)
 *   - the API param sends        (`?severity=CRITICAL`)
 *   - the backend matches        (`AnalysisFinding.severity == severity.upper()`,
 *                                  app/routers/runs.py — values stored uppercase)
 *   - the FindingFilterPanel `<select>` option values use
 *     (so a seeded value keeps the controlled select in sync).
 *
 * Dashboard severity data (`SeverityData`) is keyed in lowercase, so the
 * dashboard converts at the boundary via {@link severityKeyToParam}. The
 * destination validates+normalizes anything it reads via
 * {@link normalizeSeverityParam}. Nobody else should `.toUpperCase()` a
 * severity for routing — funnel it through here.
 */

/** Lowercase severity buckets as keyed in `SeverityData`. `unknown` is a
 *  data-quality signal, not a drill-down tier (see docs/terminology.md). */
export type SeverityKey = 'critical' | 'high' | 'medium' | 'low';

/** Canonical UPPERCASE values accepted as a `?severity=` param / filter. */
export const SEVERITY_FILTER_VALUES: ReadonlySet<string> = new Set([
  'CRITICAL',
  'HIGH',
  'MEDIUM',
  'LOW',
  'UNKNOWN',
]);

/** lowercase `SeverityData` key → canonical UPPERCASE param. */
export function severityKeyToParam(key: SeverityKey): string {
  return key.toUpperCase();
}

/**
 * Normalize an arbitrary `?severity=` value (URL is user-editable) to the
 * canonical UPPERCASE form, or `''` when absent/unrecognized. `''` means
 * "no server-side severity narrowing" — the same sentinel `DEFAULT_FILTERS`
 * uses — so an unknown param degrades gracefully to the unfiltered view
 * rather than seeding a filter that matches nothing.
 */
export function normalizeSeverityParam(raw: string | null | undefined): string {
  if (!raw) return '';
  const up = raw.trim().toUpperCase();
  return SEVERITY_FILTER_VALUES.has(up) ? up : '';
}

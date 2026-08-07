/**
 * Source-coverage reading of an analysis run.
 *
 * A run can finish with zero findings for two very different reasons:
 *   1. every selected source assessed every component and found nothing —
 *      genuinely clean; or
 *   2. some source assessed nothing at all (OSV skips components with no
 *      supported package identity, NVD skips components with no
 *      authoritative CPE) — nobody looked.
 *
 * Only (1) may be shown as "Clean / All clear". The backend encodes the same
 * distinction by returning PARTIAL for (2); see
 * `source_has_coverage_gap()` in `app/sources/routing.py` — the predicates
 * here mirror it deliberately and must stay in step with it.
 */

import type { SourceQuerySummary } from '@/types';

/** Per-source coverage state, ordered worst-first for display. */
export type SourceCoverageState = 'error' | 'skipped' | 'partial' | 'complete';

export const SOURCE_COVERAGE_LABEL: Record<SourceCoverageState, string> = {
  error: 'Error',
  skipped: 'Skipped',
  partial: 'Partial',
  complete: 'Complete',
};

/** Statuses meaning the source never assessed the components it was given. */
const NON_ASSESSING_STATUSES = new Set(['skipped', 'disabled']);

const count = (value: number | null | undefined): number =>
  typeof value === 'number' && Number.isFinite(value) ? value : 0;

/** Coverage state for one source summary. */
export function sourceCoverageState(summary: SourceQuerySummary): SourceCoverageState {
  if (count(summary.errors) > 0) return 'error';
  const status = (summary.status ?? '').trim().toLowerCase();
  if (NON_ASSESSING_STATUSES.has(status)) return 'skipped';
  if (count(summary.queried) === 0 && count(summary.skipped) > 0) return 'skipped';
  if (count(summary.skipped) > 0) return 'partial';
  return 'complete';
}

/** True when this source left part of the SBOM unassessed. */
export function sourceHasCoverageGap(summary: SourceQuerySummary): boolean {
  const state = sourceCoverageState(summary);
  return state === 'error' || state === 'skipped';
}

/** Names of the selected sources that left coverage gaps, in order. */
export function coverageGapSources(summaries: SourceQuerySummary[] | null | undefined): string[] {
  if (!Array.isArray(summaries)) return [];
  const names: string[] = [];
  for (const summary of summaries) {
    if (summary && sourceHasCoverageGap(summary)) {
      const name = (summary.source ?? '').trim().toUpperCase();
      if (name && !names.includes(name)) names.push(name);
    }
  }
  return names;
}

/** Readable copy for the machine-readable skip/error reasons the API emits. */
const REASON_LABELS: Record<string, string> = {
  missing_supported_package_identity: 'Missing supported package identity',
  missing_authoritative_cpe: 'Missing authoritative CPE',
  missing_authoritative_mapping: 'Missing authoritative CPE',
  missing_cpe: 'Missing authoritative CPE',
  missing_credentials: 'Missing credentials',
  missing_name: 'Missing component name',
  missing_version: 'Missing component version',
  unsupported_ecosystem: 'Unsupported ecosystem',
  placeholder_version: 'Placeholder version',
  not_queryable_component: 'Component type not queryable',
  placeholder_component: 'Placeholder component',
  no_match: 'No advisories matched',
  disabled: 'Source disabled',
  skipped: 'Source skipped',
};

/** Fallback copy per source when the API recorded no reason at all. */
const DEFAULT_SKIP_REASON: Record<string, string> = {
  NVD: 'Missing authoritative CPE',
  OSV: 'Missing supported package identity',
};

const ACRONYMS: Record<string, string> = {
  cpe: 'CPE',
  cve: 'CVE',
  purl: 'PURL',
  sbom: 'SBOM',
  ghsa: 'GHSA',
  nvd: 'NVD',
  osv: 'OSV',
  api: 'API',
  http: 'HTTP',
  tls: 'TLS',
  ssl: 'SSL',
};

/** Humanise an unmapped reason code rather than showing raw snake_case. */
function humanizeReason(reason: string): string {
  const words = reason
    .replace(/[_-]+/g, ' ')
    .trim()
    .split(/\s+/)
    .map((word) => ACRONYMS[word.toLowerCase()] ?? word);
  if (words.length === 0) return reason;
  const [first, ...rest] = words;
  const head = ACRONYMS[first.toLowerCase()] ? first : first.charAt(0).toUpperCase() + first.slice(1).toLowerCase();
  return [head, ...rest].join(' ');
}

/**
 * Readable reason for a source's coverage gap, or `undefined` when the
 * source covered the SBOM. Never hides a recorded reason.
 */
export function sourceCoverageReason(summary: SourceQuerySummary): string | undefined {
  const raw = (summary.reason ?? '').trim();
  if (raw) return REASON_LABELS[raw.toLowerCase()] ?? humanizeReason(raw);
  const state = sourceCoverageState(summary);
  if (state === 'complete') return undefined;
  if (state === 'error') return 'Source lookup failed';
  return DEFAULT_SKIP_REASON[(summary.source ?? '').trim().toUpperCase()] ?? 'Source assessed no components';
}

/** "69 queried" / "69 skipped" — the count that explains the state. */
export function sourceCoverageDetail(summary: SourceQuerySummary): string {
  const state = sourceCoverageState(summary);
  const queried = count(summary.queried);
  const skipped = count(summary.skipped);
  const errors = count(summary.errors);
  const parts: string[] = [];
  if (state === 'skipped') {
    parts.push(`${skipped.toLocaleString()} skipped`);
  } else {
    parts.push(`${queried.toLocaleString()} queried`);
    if (skipped > 0) parts.push(`${skipped.toLocaleString()} skipped`);
  }
  if (errors > 0) parts.push(`${errors.toLocaleString()} error${errors === 1 ? '' : 's'}`);
  return parts.join(' · ');
}

const listSources = (names: string[]): string =>
  names.length <= 1
    ? (names[0] ?? '')
    : `${names.slice(0, -1).join(', ')} and ${names[names.length - 1]}`;

/**
 * Outcome sentence for the run-detail footnote. For PARTIAL runs with zero
 * findings it names the sources that could not assess the SBOM and states
 * plainly that the result is not proof of a vulnerability-free SBOM.
 * Falls back to the generic per-status copy the caller passes in.
 */
export function runCoverageOutcome(
  status: string | null | undefined,
  summaries: SourceQuerySummary[] | null | undefined,
  fallbackDescription: string,
  totalFindings = 0,
): string {
  if ((status ?? '').toUpperCase() !== 'PARTIAL') return fallbackDescription;
  const gapped = coverageGapSources(summaries);
  if (gapped.length === 0) return fallbackDescription;
  const reported =
    totalFindings > 0
      ? `${totalFindings.toLocaleString()} vulnerabilit${totalFindings === 1 ? 'y was' : 'ies were'} reported by the sources that could run`
      : 'No vulnerabilities were reported by the sources that could run';
  return `${reported}, but ${listSources(gapped)} could not assess these components. The result does not establish that the SBOM is vulnerability-free.`;
}

/**
 * Dashboard posture state machine — see ADR-0001 / docs/terminology.md.
 *
 * One function. Pure. Easy to unit-test. Used by the hero, the LIVE pill,
 * and any future consumer that needs to know "what is the current security
 * posture, and is the data behind it trustworthy?".
 */

import type { CoverageStatus, DashboardPosture, SeverityData } from '@/types';

export type PostureBand =
  | 'clean'
  | 'incomplete_coverage'
  | 'coverage_unknown'
  | 'stable'
  | 'action_needed'
  | 'urgent'
  | 'degraded'
  | 'empty';

export interface DashboardHealthInput {
  /** API ping is healthy (response received and status === 'ok'). */
  apiOk: boolean;
}

export interface PostureInput {
  posture: DashboardPosture | undefined;
  health: DashboardHealthInput;
  /** ISO timestamp considered "now". Inject for deterministic tests. */
  now?: Date;
}

export interface PostureResult {
  band: PostureBand;
  /** Human-readable reason this band was chosen — used for tooltips/aria. */
  reason: string;
  /** Hours since the most recent successful run, null when none ever ran. */
  hoursSinceLatestRun: number | null;
  /** True when degraded — the underlying numbers may be stale or partial. */
  isDegraded: boolean;
  /**
   * Coverage as reported by the backend, normalised. Carried on EVERY result —
   * including the severity bands — so a findings-present dashboard can still
   * warn that the numbers are a floor, not a total.
   */
  coverageStatus: CoverageStatus;
  /** Sources that left coverage gaps, when the backend named them. */
  coverageGapSources: string[];
  /**
   * Amber note to render alongside the headline when coverage is not
   * complete, else `null`. Never claims the scope is vulnerability-free.
   */
  coverageWarning: string | null;
}

/**
 * Number of hours after which we treat the data as stale enough to flip the
 * hero into Degraded. ADR-0001 sets this to 24h. If you change it, document
 * the change in docs/risk-index.md and the ADR.
 */
export const STALE_HOURS_THRESHOLD = 24;

export function exploitableCount(severity: SeverityData | undefined): number {
  if (!severity) return 0;
  return (severity.critical ?? 0) + (severity.high ?? 0);
}

export function totalSeverity(severity: SeverityData | undefined): number {
  if (!severity) return 0;
  return (
    (severity.critical ?? 0) +
    (severity.high ?? 0) +
    (severity.medium ?? 0) +
    (severity.low ?? 0)
    // Unknown is intentionally excluded — see docs/terminology.md.
  );
}

function hoursBetween(a: Date, b: Date): number {
  return Math.abs(a.getTime() - b.getTime()) / 3_600_000;
}

/**
 * Copy for a coverage shortfall. Used both as the headline reason (zero
 * findings) and as the warning kept beside a severity band (findings > 0).
 * It states what was and was not established — it never says "no
 * vulnerabilities" and never implies the scope is vulnerability-free.
 */
export const COVERAGE_INCOMPLETE_NOTE =
  'No vulnerabilities were reported, but one or more configured sources could not assess all components.';
export const COVERAGE_UNKNOWN_NOTE =
  'Source coverage for these components could not be established, so findings may be incomplete.';

/** "Coverage gaps: OSV, NVD" — omitted when the backend named no sources. */
export function coverageGapLabel(gapSources: string[] | undefined): string | null {
  if (!gapSources || gapSources.length === 0) return null;
  return `Coverage gaps: ${gapSources.join(', ')}`;
}

/**
 * Normalise the backend's coverage field. An absent field means the API
 * predates it — the FE does NOT infer coverage in that case, it keeps
 * today's behaviour by treating the scope as covered.
 */
function coverageOf(posture: DashboardPosture | undefined): CoverageStatus {
  const raw = posture?.coverage_status;
  if (raw === 'incomplete' || raw === 'unknown' || raw === 'complete') return raw;
  return 'complete';
}

function coverageNote(status: CoverageStatus, gapSources: string[]): string | null {
  if (status === 'complete') return null;
  const base = status === 'incomplete' ? COVERAGE_INCOMPLETE_NOTE : COVERAGE_UNKNOWN_NOTE;
  const gaps = coverageGapLabel(gapSources);
  return gaps ? `${base} ${gaps}.` : base;
}

/**
 * Derive the posture band. Health gates take precedence over severity-based
 * bands because the underlying severity numbers may be wrong when the
 * pipeline is unhealthy.
 */
export function derivePosture(input: PostureInput): PostureResult {
  const { posture, health } = input;
  const now = input.now ?? new Date();

  const last = posture?.last_successful_run_at ?? null;
  const lastDate = last ? new Date(last) : null;
  const hoursSinceLatestRun =
    lastDate && !Number.isNaN(lastDate.getTime()) ? hoursBetween(now, lastDate) : null;

  const coverageStatus = coverageOf(posture);
  const coverageGapSources = posture?.coverage_gap_sources ?? [];
  const coverageWarning = coverageNote(coverageStatus, coverageGapSources);
  const base = { hoursSinceLatestRun, coverageStatus, coverageGapSources, coverageWarning };

  // 1. Health gates — these always win.
  if (!health.apiOk) {
    return degraded('API unhealthy', base);
  }

  // 2. No data ever — onboarding state, not a posture claim.
  if (hoursSinceLatestRun === null || (posture?.total_sboms ?? 0) === 0) {
    return { ...base, band: 'empty', reason: 'No SBOMs have been analysed yet.', isDegraded: false };
  }

  // 3. Data exists but is older than the threshold.
  if (hoursSinceLatestRun > STALE_HOURS_THRESHOLD) {
    return degraded(
      `Data is older than ${STALE_HOURS_THRESHOLD}h (${hoursSinceLatestRun.toFixed(0)}h)`,
      base,
    );
  }

  // 4. Zero findings — the answer depends entirely on coverage. "Nothing was
  //    found" and "nobody looked" produce identical severity counts, and only
  //    the first one is All clear.
  const sev = posture?.severity;
  if (!sev || totalSeverity(sev) === 0) {
    if (coverageStatus === 'incomplete') {
      return {
        ...base,
        band: 'incomplete_coverage',
        reason: coverageWarning ?? COVERAGE_INCOMPLETE_NOTE,
        isDegraded: false,
      };
    }
    if (coverageStatus === 'unknown') {
      return {
        ...base,
        band: 'coverage_unknown',
        reason: coverageWarning ?? COVERAGE_UNKNOWN_NOTE,
        isDegraded: false,
      };
    }
    return {
      ...base,
      band: 'clean',
      reason: 'No findings in the latest successful run.',
      isDegraded: false,
    };
  }

  // 5. Severity-based bands. Findings outrank coverage — real vulnerabilities
  //    stay the headline — but ``coverageWarning`` rides along so the UI can
  //    say the count is a floor rather than a total.
  if ((sev.critical ?? 0) > 0) {
    return { ...base, band: 'urgent', reason: `${sev.critical} Critical findings in scope.`, isDegraded: false };
  }
  if ((sev.high ?? 0) > 0) {
    return { ...base, band: 'action_needed', reason: `${sev.high} High findings in scope.`, isDegraded: false };
  }
  return {
    ...base,
    band: 'stable',
    reason: 'Only Medium / Low findings — no urgent action required.',
    isDegraded: false,
  };
}

function degraded(
  reason: string,
  base: Pick<PostureResult, 'hoursSinceLatestRun' | 'coverageStatus' | 'coverageGapSources' | 'coverageWarning'>,
): PostureResult {
  return { ...base, band: 'degraded', reason, isDegraded: true };
}

export const POSTURE_COPY: Record<
  PostureBand,
  { headline: string; tone: 'green' | 'sky' | 'orange' | 'red' | 'amber' | 'neutral' }
> = {
  clean: { headline: 'All clear', tone: 'green' },
  // Zero findings, but a source could not assess every component: amber, and
  // deliberately not the word "clear".
  incomplete_coverage: { headline: 'Incomplete coverage', tone: 'amber' },
  coverage_unknown: { headline: 'Coverage not fully assessed', tone: 'amber' },
  stable: { headline: 'Stable', tone: 'sky' },
  action_needed: { headline: 'Action needed', tone: 'orange' },
  urgent: { headline: 'Urgent attention required', tone: 'red' },
  degraded: { headline: 'Posture unavailable', tone: 'amber' },
  empty: { headline: 'Ready to scan', tone: 'neutral' },
};

/**
 * Dashboard posture state machine — see ADR-0001 / docs/terminology.md.
 *
 * One function. Pure. Easy to unit-test. Used by the hero, the LIVE pill,
 * and any future consumer that needs to know "what is the current security
 * posture, and is the data behind it trustworthy?".
 */

import type { DashboardPosture, SeverityData } from '@/types';

export type PostureBand =
  | 'clean'
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

  // 1. Health gates — these always win.
  if (!health.apiOk) {
    return degraded('API unhealthy', hoursSinceLatestRun);
  }

  // 2. No data ever — onboarding state, not a posture claim.
  if (hoursSinceLatestRun === null || (posture?.total_sboms ?? 0) === 0) {
    return {
      band: 'empty',
      reason: 'No SBOMs have been analysed yet.',
      hoursSinceLatestRun,
      isDegraded: false,
    };
  }

  // 3. Data exists but is older than the threshold.
  if (hoursSinceLatestRun > STALE_HOURS_THRESHOLD) {
    return degraded(
      `Data is older than ${STALE_HOURS_THRESHOLD}h (${hoursSinceLatestRun.toFixed(0)}h)`,
      hoursSinceLatestRun,
    );
  }

  // 4. Severity-based bands.
  const sev = posture?.severity;
  if (!sev || totalSeverity(sev) === 0) {
    return {
      band: 'clean',
      reason: 'No findings in the latest successful run.',
      hoursSinceLatestRun,
      isDegraded: false,
    };
  }
  if ((sev.critical ?? 0) > 0) {
    return {
      band: 'urgent',
      reason: `${sev.critical} Critical findings in scope.`,
      hoursSinceLatestRun,
      isDegraded: false,
    };
  }
  if ((sev.high ?? 0) > 0) {
    return {
      band: 'action_needed',
      reason: `${sev.high} High findings in scope.`,
      hoursSinceLatestRun,
      isDegraded: false,
    };
  }
  return {
    band: 'stable',
    reason: 'Only Medium / Low findings — no urgent action required.',
    hoursSinceLatestRun,
    isDegraded: false,
  };
}

function degraded(reason: string, hoursSinceLatestRun: number | null): PostureResult {
  return { band: 'degraded', reason, hoursSinceLatestRun, isDegraded: true };
}

export const POSTURE_COPY: Record<
  PostureBand,
  { headline: string; tone: 'green' | 'sky' | 'orange' | 'red' | 'amber' | 'neutral' }
> = {
  clean: { headline: 'All clear', tone: 'green' },
  stable: { headline: 'Stable', tone: 'sky' },
  action_needed: { headline: 'Action needed', tone: 'orange' },
  urgent: { headline: 'Urgent attention required', tone: 'red' },
  degraded: { headline: 'Posture unavailable', tone: 'amber' },
  empty: { headline: 'Ready to scan', tone: 'neutral' },
};

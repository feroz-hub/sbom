import type { AnalysisRun } from '@/types';
import type { SeverityKey } from '@/lib/severityParam';

export type { SeverityKey };

/**
 * One SBOM's latest finding-bearing run, flattened for ranking and
 * drill-down. `weighted` is the severity-weighted score used to order the
 * "Top vulnerable SBOMs" list; `latestRunId` is the run a drill-down lands
 * on.
 */
export interface SbomBucket {
  sbomId: number;
  sbomName: string;
  critical: number;
  high: number;
  medium: number;
  low: number;
  totalFindings: number;
  latestRunId: number;
  weighted: number;
}

/**
 * Collapse a list of runs to one bucket per SBOM (its latest finding-bearing
 * run) and sort by weighted severity, descending.
 *
 * Assumes `runs` arrive newest-first (the `getRuns` default is desc by id),
 * so the first run seen for an SBOM is its latest. Runs with zero findings
 * are dropped — they can't seed any severity drill-down.
 *
 * NOTE: this returns the FULL ranked set, not a top-N slice. The dashboard's
 * `TopVulnerableSboms` list slices afterwards, while `topRunForSeverity`
 * needs the whole set (the run with the most `Low` findings may rank well
 * below the weighted top 5).
 */
export function aggregateRuns(runs: AnalysisRun[]): SbomBucket[] {
  const buckets = new Map<number, SbomBucket>();
  for (const run of runs) {
    if (run.sbom_id == null) continue;
    if (buckets.has(run.sbom_id)) continue; // first seen = latest (desc by id)
    const critical = run.critical_count ?? 0;
    const high = run.high_count ?? 0;
    const medium = run.medium_count ?? 0;
    const low = run.low_count ?? 0;
    const totalFindings = run.total_findings ?? 0;
    if (totalFindings === 0) continue;
    buckets.set(run.sbom_id, {
      sbomId: run.sbom_id,
      sbomName: run.sbom_name ?? `SBOM #${run.sbom_id}`,
      critical,
      high,
      medium,
      low,
      totalFindings,
      latestRunId: run.id,
      weighted: critical * 100 + high * 25 + medium * 8 + low * 2,
    });
  }
  return Array.from(buckets.values()).sort((a, b) => b.weighted - a.weighted);
}

/**
 * The run a hero severity drill-down should land on: the bucket with the
 * most findings of `severity`. Returns `undefined` when no run has any
 * finding at that severity — the caller MUST treat that as "not a drill-down
 * target" and render the tile non-interactively (no dead buttons).
 */
export function topRunForSeverity(
  buckets: SbomBucket[],
  severity: SeverityKey,
): SbomBucket | undefined {
  let best: SbomBucket | undefined;
  for (const b of buckets) {
    if (b[severity] <= 0) continue;
    if (!best || b[severity] > best[severity]) best = b;
  }
  return best;
}

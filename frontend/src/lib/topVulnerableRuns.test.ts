import { describe, expect, it } from 'vitest';
import { aggregateRuns, topRunForSeverity } from '@/lib/topVulnerableRuns';
import type { AnalysisRun } from '@/types';

function run(overrides: Partial<AnalysisRun>): AnalysisRun {
  return {
    id: 0,
    sbom_id: 0,
    sbom_name: null,
    project_id: null,
    run_status: 'FINDINGS',
    source: 'NVD',
    total_components: 0,
    components_with_cpe: 0,
    total_findings: 0,
    critical_count: 0,
    high_count: 0,
    medium_count: 0,
    low_count: 0,
    unknown_count: 0,
    query_error_count: 0,
    duration_ms: 0,
    started_on: null,
    completed_on: null,
    error_message: null,
    ...overrides,
  };
}

describe('aggregateRuns', () => {
  it('keeps the latest run per SBOM (first seen wins, desc-by-id input)', () => {
    const buckets = aggregateRuns([
      run({ id: 20, sbom_id: 1, critical_count: 1, total_findings: 1 }), // latest
      run({ id: 10, sbom_id: 1, critical_count: 9, total_findings: 9 }), // older — ignored
    ]);
    expect(buckets).toHaveLength(1);
    expect(buckets[0]!.latestRunId).toBe(20);
    expect(buckets[0]!.critical).toBe(1);
  });

  it('drops runs with zero findings and sorts by weighted severity desc', () => {
    const buckets = aggregateRuns([
      run({ id: 1, sbom_id: 1, low_count: 5, total_findings: 5 }),
      run({ id: 2, sbom_id: 2, critical_count: 1, total_findings: 1 }),
      run({ id: 3, sbom_id: 3, total_findings: 0 }), // clean — dropped
    ]);
    expect(buckets.map((b) => b.sbomId)).toEqual([2, 1]); // critical (100) > 5 lows (10)
  });
});

describe('topRunForSeverity', () => {
  const buckets = aggregateRuns([
    run({ id: 1, sbom_id: 1, critical_count: 2, low_count: 1, total_findings: 3 }),
    run({ id: 2, sbom_id: 2, critical_count: 5, low_count: 0, total_findings: 5 }),
    run({ id: 3, sbom_id: 3, critical_count: 0, low_count: 9, total_findings: 9 }),
  ]);

  it('returns the run with the most findings of the given severity', () => {
    expect(topRunForSeverity(buckets, 'critical')!.latestRunId).toBe(2); // 5 > 2 > 0
    expect(topRunForSeverity(buckets, 'low')!.latestRunId).toBe(3); // 9 > 1 — NOT the weighted top
  });

  it('returns undefined when no run has that severity (→ non-clickable tile)', () => {
    expect(topRunForSeverity(buckets, 'high')).toBeUndefined();
    expect(topRunForSeverity(buckets, 'medium')).toBeUndefined();
  });
});

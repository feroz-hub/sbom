import { describe, expect, it } from 'vitest';
import {
  COVERAGE_INCOMPLETE_NOTE,
  COVERAGE_UNKNOWN_NOTE,
  coverageGapLabel,
  derivePosture,
  exploitableCount,
  POSTURE_COPY,
  STALE_HOURS_THRESHOLD,
  totalSeverity,
} from './dashboardPosture';
import type { DashboardPosture } from '@/types';

const NOW = new Date('2026-04-30T12:00:00Z');

const HEALTHY = { apiOk: true };

function postureOf(overrides: Partial<DashboardPosture>): DashboardPosture {
  return {
    severity: { critical: 0, high: 0, medium: 0, low: 0, unknown: 0 },
    kev_count: 0,
    fix_available_count: 0,
    last_successful_run_at: '2026-04-30T11:00:00Z', // 1 hour ago
    total_sboms: 1,
    total_active_projects: 1,
    ...overrides,
  };
}

describe('exploitableCount', () => {
  it('sums Critical + High only', () => {
    expect(exploitableCount({ critical: 2, high: 3, medium: 5, low: 8, unknown: 4 })).toBe(5);
  });
  it('returns 0 for undefined', () => {
    expect(exploitableCount(undefined)).toBe(0);
  });
});

describe('totalSeverity', () => {
  it('excludes Unknown — Unknown is a data-quality signal, not a severity', () => {
    expect(totalSeverity({ critical: 1, high: 1, medium: 1, low: 1, unknown: 99 })).toBe(4);
  });
});

describe('derivePosture', () => {
  it('returns empty when no successful run has ever happened', () => {
    const r = derivePosture({
      posture: postureOf({ last_successful_run_at: null, total_sboms: 0 }),
      health: HEALTHY,
      now: NOW,
    });
    expect(r.band).toBe('empty');
    expect(r.isDegraded).toBe(false);
  });

  it('returns degraded when API is unhealthy regardless of severity', () => {
    const r = derivePosture({
      posture: postureOf({
        severity: { critical: 100, high: 0, medium: 0, low: 0, unknown: 0 },
      }),
      health: { apiOk: false },
      now: NOW,
    });
    expect(r.band).toBe('degraded');
    expect(r.reason).toMatch(/API/);
    expect(r.isDegraded).toBe(true);
  });

  it('returns degraded when data is older than the staleness threshold', () => {
    const stale = new Date(NOW.getTime() - (STALE_HOURS_THRESHOLD + 1) * 3_600_000).toISOString();
    const r = derivePosture({
      posture: postureOf({ last_successful_run_at: stale }),
      health: HEALTHY,
      now: NOW,
    });
    expect(r.band).toBe('degraded');
    expect(r.reason).toMatch(/older/);
  });

  it('returns urgent when any Critical exists', () => {
    const r = derivePosture({
      posture: postureOf({
        severity: { critical: 1, high: 50, medium: 100, low: 100, unknown: 0 },
      }),
      health: HEALTHY,
      now: NOW,
    });
    expect(r.band).toBe('urgent');
  });

  it('returns action_needed when only High findings exist (no Critical)', () => {
    const r = derivePosture({
      posture: postureOf({
        severity: { critical: 0, high: 7, medium: 0, low: 0, unknown: 0 },
      }),
      health: HEALTHY,
      now: NOW,
    });
    expect(r.band).toBe('action_needed');
  });

  it('returns stable when only Medium / Low exist', () => {
    const r = derivePosture({
      posture: postureOf({
        severity: { critical: 0, high: 0, medium: 12, low: 4, unknown: 0 },
      }),
      health: HEALTHY,
      now: NOW,
    });
    expect(r.band).toBe('stable');
  });

  it('returns clean when there are zero findings (Unknown does not count)', () => {
    const r = derivePosture({
      posture: postureOf({
        severity: { critical: 0, high: 0, medium: 0, low: 0, unknown: 99 },
      }),
      health: HEALTHY,
      now: NOW,
    });
    expect(r.band).toBe('clean');
  });

  it('audit screenshot scenario — 175 critical / 790 high should be urgent, NEVER "Critical risk"', () => {
    const r = derivePosture({
      posture: postureOf({
        severity: { critical: 175, high: 790, medium: 650, low: 225, unknown: 25 },
      }),
      health: HEALTHY,
      now: NOW,
    });
    expect(r.band).toBe('urgent');
    expect(r.reason).toContain('175');
  });

  it('health gate beats severity gate — degraded overrides urgent', () => {
    const r = derivePosture({
      posture: postureOf({
        severity: { critical: 999, high: 0, medium: 0, low: 0, unknown: 0 },
      }),
      health: { apiOk: false },
      now: NOW,
    });
    expect(r.band).toBe('degraded');
  });
});

/**
 * Zero findings means two different things depending on coverage. The reported
 * case: 69 components, GITHUB completed, OSV and NVD assessed none — zero
 * findings, and NOT a clean result.
 */
describe('derivePosture — source coverage', () => {
  const ZERO = { critical: 0, high: 0, medium: 0, low: 0, unknown: 0 };

  it('zero findings + complete coverage => All clear', () => {
    const r = derivePosture({
      posture: postureOf({ severity: ZERO, coverage_status: 'complete' }),
      health: HEALTHY,
      now: NOW,
    });

    expect(r.band).toBe('clean');
    expect(POSTURE_COPY[r.band].headline).toBe('All clear');
    expect(r.coverageWarning).toBeNull();
  });

  it('zero findings + incomplete coverage => Incomplete coverage, never All clear', () => {
    const r = derivePosture({
      posture: postureOf({
        severity: ZERO,
        coverage_status: 'incomplete',
        coverage_gap_sources: ['OSV', 'NVD'],
      }),
      health: HEALTHY,
      now: NOW,
    });

    expect(r.band).toBe('incomplete_coverage');
    expect(POSTURE_COPY[r.band].headline).toBe('Incomplete coverage');
    expect(POSTURE_COPY[r.band].headline).not.toMatch(/clear/i);
    expect(POSTURE_COPY[r.band].tone).toBe('amber');
    expect(r.reason).toContain('could not assess all components');
    expect(r.reason).toContain('Coverage gaps: OSV, NVD');
    expect(r.reason).not.toMatch(/no vulnerabilities\.?$/i);
  });

  it('zero findings + unknown coverage => not All clear', () => {
    const r = derivePosture({
      posture: postureOf({ severity: ZERO, coverage_status: 'unknown' }),
      health: HEALTHY,
      now: NOW,
    });

    expect(r.band).toBe('coverage_unknown');
    expect(POSTURE_COPY[r.band].headline).not.toMatch(/all clear/i);
    expect(POSTURE_COPY[r.band].tone).toBe('amber');
  });

  it('findings + incomplete coverage keeps the vulnerability band and the warning', () => {
    const r = derivePosture({
      posture: postureOf({
        severity: { critical: 3, high: 2, medium: 0, low: 0, unknown: 0 },
        coverage_status: 'incomplete',
        coverage_gap_sources: ['OSV'],
      }),
      health: HEALTHY,
      now: NOW,
    });

    // Real vulnerabilities still lead.
    expect(r.band).toBe('urgent');
    expect(r.reason).toContain('3 Critical');
    // …and the coverage caveat is not dropped.
    expect(r.coverageStatus).toBe('incomplete');
    expect(r.coverageWarning).toContain('could not assess all components');
    expect(r.coverageGapSources).toEqual(['OSV']);
  });

  it('carries coverage through the degraded and empty gates too', () => {
    const stale = new Date(NOW.getTime() - (STALE_HOURS_THRESHOLD + 1) * 3_600_000).toISOString();
    const degradedResult = derivePosture({
      posture: postureOf({ last_successful_run_at: stale, coverage_status: 'incomplete' }),
      health: HEALTHY,
      now: NOW,
    });
    expect(degradedResult.band).toBe('degraded');
    expect(degradedResult.coverageStatus).toBe('incomplete');

    const emptyResult = derivePosture({
      posture: postureOf({ last_successful_run_at: null, total_sboms: 0, coverage_status: 'incomplete' }),
      health: HEALTHY,
      now: NOW,
    });
    expect(emptyResult.band).toBe('empty');
    expect(emptyResult.coverageStatus).toBe('incomplete');
  });

  it('treats an absent coverage field as covered — the FE never infers coverage', () => {
    const r = derivePosture({
      posture: postureOf({ severity: ZERO }),
      health: HEALTHY,
      now: NOW,
    });

    expect(r.band).toBe('clean');
    expect(r.coverageStatus).toBe('complete');
  });

  it('never labels a coverage gap as an error', () => {
    const r = derivePosture({
      posture: postureOf({ severity: ZERO, coverage_status: 'incomplete' }),
      health: HEALTHY,
      now: NOW,
    });

    expect(r.isDegraded).toBe(false);
    expect(POSTURE_COPY[r.band].tone).not.toBe('red');
  });
});

describe('coverageGapLabel', () => {
  it('lists the named sources', () => {
    expect(coverageGapLabel(['OSV', 'NVD'])).toBe('Coverage gaps: OSV, NVD');
  });

  it('is omitted when the backend named none', () => {
    expect(coverageGapLabel([])).toBeNull();
    expect(coverageGapLabel(undefined)).toBeNull();
  });
});

describe('coverage copy', () => {
  it('never claims the scope is vulnerability-free', () => {
    for (const note of [COVERAGE_INCOMPLETE_NOTE, COVERAGE_UNKNOWN_NOTE]) {
      expect(note).not.toMatch(/all clear/i);
      expect(note).not.toMatch(/vulnerability-free/i);
      expect(note).not.toMatch(/no vulnerabilities exist/i);
    }
    expect(COVERAGE_INCOMPLETE_NOTE).toBe(
      'No vulnerabilities were reported, but one or more configured sources could not assess all components.',
    );
  });

  it('keeps All clear reserved for genuinely complete coverage', () => {
    expect(POSTURE_COPY.clean.headline).toBe('All clear');
    expect(POSTURE_COPY.incomplete_coverage.headline).not.toMatch(/clear/i);
    expect(POSTURE_COPY.coverage_unknown.headline).not.toMatch(/clear/i);
  });
});

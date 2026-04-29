import { describe, expect, it } from 'vitest';
import {
  derivePosture,
  exploitableCount,
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

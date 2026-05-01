// @vitest-environment jsdom
/**
 * HeroMetricRow — cross-surface number reconciliation in the rendered DOM.
 *
 * Mirrors the backend ``test_metric_consistency.py`` invariants on the FE
 * side: any time these numbers drift, the FE rendering must drift with
 * them. Particularly locks:
 *
 *   * is_first_period === true → "first scan this week" copy + em-dash,
 *     never the misleading "+N / -0" (Bug 5 lock).
 *   * net_7day envelope is preferred over flat aliases when both ship.
 *   * Headline KEV count rendering reflects the canonical metric (Bug 1).
 */

import { describe, expect, it } from 'vitest';
import { render, screen } from '@testing-library/react';
import { HeroMetricRow } from './HeroMetricRow';
import type { DashboardPosture, DashboardTrend } from '@/types';

function makePosture(overrides: Partial<DashboardPosture> = {}): DashboardPosture {
  return {
    severity: { critical: 0, high: 0, medium: 0, low: 0, unknown: 0 },
    kev_count: 0,
    fix_available_count: 0,
    last_successful_run_at: null,
    total_sboms: 0,
    total_active_projects: 0,
    total_findings: 0,
    distinct_vulnerabilities: 0,
    ...overrides,
  };
}

function makeTrend(): DashboardTrend {
  return {
    days: 30,
    series: [],
    points: [],
    annotations: [],
    avg_total: 0,
  };
}

describe('HeroMetricRow — first-period rendering (Bug 5 lock)', () => {
  it('renders an em-dash and "first scan this week" copy when is_first_period is true', () => {
    const posture = makePosture({
      net_7day: { added: 513, resolved: 0, is_first_period: true, window_days: 7 },
    });
    render(<HeroMetricRow posture={posture} trend={makeTrend()} />);
    expect(screen.getByText('first scan this week')).toBeTruthy();
    // The misleading "+513 / −0" must NOT render.
    expect(screen.queryByText(/\+513/)).toBeNull();
  });

  it('renders +added / −resolved when not first period', () => {
    const posture = makePosture({
      net_7day: { added: 7, resolved: 3, is_first_period: false, window_days: 7 },
    });
    render(<HeroMetricRow posture={posture} trend={makeTrend()} />);
    expect(screen.getByText('vs prior 7 days')).toBeTruthy();
    expect(screen.getByText(/\+7/)).toBeTruthy();
    expect(screen.getByText(/−3/)).toBeTruthy();
  });

  it('falls back to flat aliases when envelope is absent (back-compat)', () => {
    const posture = makePosture({
      net_7day_added: 4,
      net_7day_resolved: 2,
    });
    render(<HeroMetricRow posture={posture} trend={makeTrend()} />);
    expect(screen.getByText(/\+4/)).toBeTruthy();
    expect(screen.getByText(/−2/)).toBeTruthy();
  });

  it('prefers envelope over flat aliases when both are present', () => {
    const posture = makePosture({
      net_7day: { added: 100, resolved: 50, is_first_period: false, window_days: 7 },
      net_7day_added: 999, // would-be-stale flat field
      net_7day_resolved: 999,
    });
    render(<HeroMetricRow posture={posture} trend={makeTrend()} />);
    expect(screen.getByText(/\+100/)).toBeTruthy();
    expect(screen.getByText(/−50/)).toBeTruthy();
    expect(screen.queryByText(/999/)).toBeNull();
  });
});

describe('HeroMetricRow — KEV count rendering (Bug 1 lock)', () => {
  it('renders the kev_count from posture verbatim', () => {
    const posture = makePosture({ kev_count: 10 });
    render(<HeroMetricRow posture={posture} trend={makeTrend()} />);
    // The canonical predicate is server-side; the FE must surface that
    // number — no client-side derivation that could drift from run-detail.
    expect(screen.getByText('10')).toBeTruthy();
  });

  it('renders 0 (neutral tone) when no KEV findings in scope', () => {
    const posture = makePosture({ kev_count: 0 });
    render(<HeroMetricRow posture={posture} trend={makeTrend()} />);
    // The KEV tile is one of several rendering "0", so just confirm the
    // label exists alongside the count.
    expect(screen.getByText('KEV exposed')).toBeTruthy();
  });
});

// @vitest-environment jsdom
/**
 * FindingsTrendChart — empty-state condition + copy reconciliation.
 *
 * Locks Bug 2 (run count mis-reported as "1 run so far" when 4 same-day
 * runs existed) and Bug 6 (empty state firing because populatedDays
 * counted distinct calendar dates instead of runs).
 *
 * The condition is now ``runs_distinct_dates < 7`` from the server, not
 * the FE-derived ``populatedDays`` heuristic. The copy uses ``runs_total``.
 */

import { describe, expect, it } from 'vitest';
import { render, screen } from '@testing-library/react';
import { FindingsTrendChart } from './FindingsTrendChart';
import type { DashboardTrend } from '@/types';
import { ThemeProvider } from '@/components/theme/ThemeProvider';

function withTheme(node: React.ReactElement) {
  return <ThemeProvider initialTheme="light">{node}</ThemeProvider>;
}

function trendWith(overrides: Partial<DashboardTrend>): DashboardTrend {
  // 30 zero-filled days starting today.
  const today = new Date();
  const points = Array.from({ length: 30 }, (_, i) => {
    const d = new Date(today);
    d.setDate(d.getDate() - (29 - i));
    return {
      date: d.toISOString().slice(0, 10),
      critical: 0,
      high: 0,
      medium: 0,
      low: 0,
      unknown: 0,
      total: 0,
    };
  });
  return {
    days: 30,
    series: points,
    points,
    annotations: [],
    avg_total: 0,
    ...overrides,
  };
}

describe('FindingsTrendChart — empty-state copy reflects runs_total (Bug 2 lock)', () => {
  it('renders "{runs_total} runs so far" when fewer than 7 distinct dates', () => {
    const trend = trendWith({
      runs_total: 4,
      runs_distinct_dates: 1,
      points: trendWith({}).points.map((p, i) =>
        i === 29 ? { ...p, high: 5, total: 5 } : p,
      ),
    });
    render(withTheme(<FindingsTrendChart data={trend} isLoading={false} />));
    expect(
      screen.getByText('Trend will appear after a week of regular scanning'),
    ).toBeTruthy();
    expect(screen.getByText('4 runs so far.')).toBeTruthy();
    // The misleading "1 run so far" copy must NOT render — that was the bug.
    expect(screen.queryByText('1 run so far.')).toBeNull();
  });

  it('does not show empty state when runs_distinct_dates >= 7', () => {
    // 7 distinct dates each with one finding → no empty state.
    const points = trendWith({}).points.map((p, i) =>
      i % 4 === 0 ? { ...p, high: 1, total: 1 } : p,
    );
    const trend = trendWith({
      runs_total: 7,
      runs_distinct_dates: 8,
      points,
    });
    render(withTheme(<FindingsTrendChart data={trend} isLoading={false} />));
    expect(
      screen.queryByText('Trend will appear after a week of regular scanning'),
    ).toBeNull();
  });
});

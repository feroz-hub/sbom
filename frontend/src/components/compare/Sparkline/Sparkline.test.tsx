// @vitest-environment jsdom
/**
 * Sparkline — pure-helper tests + component hide-rule integration.
 */

import { describe, expect, it, vi, beforeEach } from 'vitest';
import { waitFor } from '@testing-library/react';
import {
  Sparkline,
  buildSvgPath,
  describeTrend,
  pointY,
} from './Sparkline';
import { renderWithCompareProviders } from '../__tests__/test-utils';
import type { AnalysisRun } from '@/types';

const getRuns = vi.fn();
vi.mock('@/lib/api', () => ({
  getRuns: (...args: unknown[]) => getRuns(...args),
}));

beforeEach(() => {
  getRuns.mockReset();
});

// ─── Pure helpers ────────────────────────────────────────────────────────────

describe('buildSvgPath', () => {
  it('returns empty string for empty input', () => {
    expect(buildSvgPath([], 240, 24)).toBe('');
  });

  it('produces a single M command for a 1-point series', () => {
    const path = buildSvgPath([10], 240, 24);
    expect(path).toMatch(/^M /);
    expect(path).not.toMatch(/L/);
  });

  it('M then N-1 L commands for an N-point series', () => {
    const path = buildSvgPath([1, 2, 3, 4, 5], 240, 24);
    const segments = path.split(/[ML]/).filter(Boolean);
    expect(segments).toHaveLength(5);
    expect((path.match(/L/g) ?? []).length).toBe(4);
  });

  it('Y is normalised so highest value sits near top, lowest near bottom', () => {
    const path = buildSvgPath([0, 100], 100, 100);
    // Two coordinates: first is at min (Y near bottom = ~98 px), second
    // is at max (Y near top = 2 px). With the 2px padding rule.
    const matches = [...path.matchAll(/[ML] ([\d.]+) ([\d.]+)/g)];
    expect(matches).toHaveLength(2);
    const [, , y0] = matches[0];
    const [, , y1] = matches[1];
    expect(parseFloat(y0)).toBeGreaterThan(parseFloat(y1));
  });
});

describe('describeTrend', () => {
  it('returns flat for series with <2 points', () => {
    expect(describeTrend([])).toBe('flat');
    expect(describeTrend([5])).toBe('flat');
  });

  it('classifies a 5%+ increase as up', () => {
    expect(describeTrend([100, 110])).toBe('up');
  });

  it('classifies a 5%+ decrease as down', () => {
    expect(describeTrend([100, 80])).toBe('down');
  });

  it('classifies <5% change as flat', () => {
    expect(describeTrend([100, 102])).toBe('flat');
  });
});

describe('pointY', () => {
  it('clamps to padded range', () => {
    const y_top = pointY(10, [0, 5, 10], 100);
    const y_bottom = pointY(0, [0, 5, 10], 100);
    expect(y_top).toBeLessThan(y_bottom);
    expect(y_top).toBeGreaterThanOrEqual(0);
    expect(y_bottom).toBeLessThanOrEqual(100);
  });
});

// ─── Component hide rules ────────────────────────────────────────────────────

function makeRun(id: number, total: number, status = 'FINDINGS'): AnalysisRun {
  return {
    id,
    sbom_id: 1,
    project_id: null,
    run_status: status as AnalysisRun['run_status'],
    source: 'TEST',
    sbom_name: 'sample',
    total_components: 0,
    components_with_cpe: 0,
    total_findings: total,
    critical_count: 0,
    high_count: 0,
    medium_count: 0,
    low_count: 0,
    unknown_count: 0,
    query_error_count: 0,
    duration_ms: 0,
    started_on: '2026-01-01T00:00:00Z',
    completed_on: '2026-01-01T00:01:00Z',
    error_message: null,
  };
}

describe('Sparkline component', () => {
  it('renders nothing when sbomId is null', () => {
    const { container } = renderWithCompareProviders(<Sparkline sbomId={null} />);
    expect(container.firstChild).toBeNull();
  });

  it('renders nothing when fewer than 2 historical comparable runs exist', async () => {
    getRuns.mockResolvedValue([makeRun(1, 100)]);
    const { container } = renderWithCompareProviders(<Sparkline sbomId={42} />);
    // Wait for the query to settle.
    await waitFor(() => expect(getRuns).toHaveBeenCalled());
    expect(container.firstChild).toBeNull();
  });

  it('skips ERROR / RUNNING runs from the series', async () => {
    getRuns.mockResolvedValue([
      makeRun(1, 100, 'ERROR'),
      makeRun(2, 50, 'RUNNING'),
      makeRun(3, 30, 'FINDINGS'),
    ]);
    const { container } = renderWithCompareProviders(<Sparkline sbomId={42} />);
    await waitFor(() => expect(getRuns).toHaveBeenCalled());
    // Only one comparable run after filtering — under the threshold, so no render.
    expect(container.firstChild).toBeNull();
  });

  it('renders SVG when ≥2 comparable runs are present', async () => {
    getRuns.mockResolvedValue([
      makeRun(1, 50),
      makeRun(2, 60),
      makeRun(3, 70),
    ]);
    const { container, findByRole } = renderWithCompareProviders(
      <Sparkline sbomId={42} />,
    );
    const svg = await findByRole('img');
    expect(svg.tagName.toLowerCase()).toBe('svg');
    // Path element present.
    expect(container.querySelector('path')).toBeTruthy();
  });
});

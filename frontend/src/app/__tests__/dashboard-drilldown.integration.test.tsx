// @vitest-environment jsdom
/**
 * Dashboard drill-down integration — the source half of the chain. Renders
 * the REAL dashboard page, lets the posture + top-runs queries resolve, then
 * clicks the hero "Critical" count and asserts it navigates to the run that
 * best represents that slice, deep-linked with the canonical
 * `?severity=CRITICAL&globalCount=…` the destination reads back.
 *
 * Fail-before: pre-fix, the page passed no handlers and the counts rendered
 * as static <span>/<div> — there was no button to click, so this fails.
 * Pass-after: the count is a real <button> that pushes the deep-link.
 *
 * Sibling panels are stubbed so the assertion is pinned on the hero wiring.
 */

import { describe, expect, it, vi, beforeEach } from 'vitest';
import { render, screen, fireEvent, waitFor } from '@testing-library/react';
import type { ReactNode } from 'react';
import { QueryClient, QueryClientProvider } from '@tanstack/react-query';
import { ToastProvider } from '@/hooks/useToast';
import { ThemeProvider } from '@/components/theme/ThemeProvider';
import type { AnalysisRun } from '@/types';

const push = vi.fn();
vi.mock('next/navigation', () => ({
  useRouter: () => ({ push, replace: vi.fn(), back: vi.fn() }),
  useSearchParams: () => new URLSearchParams(),
  usePathname: () => '/',
}));

const getDashboardPosture = vi.fn();
const getDashboardTrend = vi.fn();
const getDashboardLifetime = vi.fn();
const getRuns = vi.fn();
vi.mock('@/lib/api', async () => {
  const actual = await vi.importActual<typeof import('@/lib/api')>('@/lib/api');
  return {
    ...actual,
    getDashboardPosture: (...a: unknown[]) => getDashboardPosture(...a),
    getDashboardTrend: (...a: unknown[]) => getDashboardTrend(...a),
    getDashboardLifetime: (...a: unknown[]) => getDashboardLifetime(...a),
    getRuns: (...a: unknown[]) => getRuns(...a),
  };
});

// Stub sibling panels — not under test, and several fire their own queries.
vi.mock('@/components/dashboard/QuickActionsV2/QuickActionsV2', () => ({
  QuickActionsV2: () => null,
}));
vi.mock('@/components/dashboard/FindingsTrendChart/FindingsTrendChart', () => ({
  FindingsTrendChart: () => null,
}));
vi.mock('@/components/dashboard/LifetimeStats/LifetimeStats', () => ({
  LifetimeStats: () => null,
}));
vi.mock('@/components/dashboard/TopVulnerableSboms', () => ({
  TopVulnerableSboms: () => null,
}));
vi.mock('@/components/dashboard/ActivityFeed', () => ({
  ActivityFeed: () => null,
}));
vi.mock('@/components/dashboard/AiConfigBanner', () => ({
  AiConfigBanner: () => null,
}));

import DashboardPage from '@/app/page';

const RUN: AnalysisRun = {
  id: 7,
  sbom_id: 100,
  sbom_name: 'demo-sbom',
  project_id: 1,
  run_status: 'FINDINGS',
  source: 'NVD',
  total_components: 10,
  components_with_cpe: 8,
  total_findings: 42,
  critical_count: 42,
  high_count: 0,
  medium_count: 0,
  low_count: 0,
  unknown_count: 0,
  query_error_count: 0,
  duration_ms: 1200,
  started_on: '2026-05-01T10:00:00Z',
  completed_on: '2026-05-01T10:02:00Z',
  error_message: null,
};

function wrap(children: ReactNode) {
  const qc = new QueryClient({
    defaultOptions: { queries: { retry: false, gcTime: 0, staleTime: 0 } },
  });
  return (
    <QueryClientProvider client={qc}>
      <ThemeProvider>
        <ToastProvider>{children}</ToastProvider>
      </ThemeProvider>
    </QueryClientProvider>
  );
}

beforeEach(() => {
  push.mockReset();
  getDashboardPosture.mockReset();
  getDashboardTrend.mockReset();
  getDashboardLifetime.mockReset();
  getRuns.mockReset();
  getDashboardPosture.mockResolvedValue({
    severity: { critical: 42, high: 0, medium: 0, low: 0, unknown: 0 },
    kev_count: 0,
    fix_available_count: 0,
    last_successful_run_at: '2026-05-01T10:02:00Z',
    total_sboms: 3,
    total_active_projects: 1,
    headline_state: 'criticals_no_kev',
  });
  getDashboardTrend.mockResolvedValue({ days: 30, series: [], points: [] });
  getDashboardLifetime.mockResolvedValue({});
  getRuns.mockResolvedValue([RUN]);
});

describe('dashboard hero — Critical drill-down', () => {
  it('navigates to the top critical run with ?severity=CRITICAL&globalCount=42', async () => {
    render(wrap(<DashboardPage />));

    // The Critical count becomes an interactive button once both posture and
    // the top-runs query resolve (severity bar segment + legend badge).
    const buttons = await screen.findAllByRole(
      'button',
      { name: /View Critical findings/i },
      { timeout: 5000 },
    );
    expect(buttons.length).toBeGreaterThan(0);

    fireEvent.click(buttons[0]!);

    expect(push).toHaveBeenCalledWith('/analysis/7?severity=CRITICAL&globalCount=42');
  });

  it('does not make non-resolvable severities clickable (no dead buttons)', async () => {
    // Portfolio reports highs, but no FINDINGS run carries any → not clickable.
    getDashboardPosture.mockResolvedValue({
      severity: { critical: 42, high: 9, medium: 0, low: 0, unknown: 0 },
      kev_count: 0,
      fix_available_count: 0,
      last_successful_run_at: '2026-05-01T10:02:00Z',
      total_sboms: 3,
      total_active_projects: 1,
      headline_state: 'criticals_no_kev',
    });
    // RUN has high_count: 0 → topRunForSeverity('high') is undefined.
    render(wrap(<DashboardPage />));

    await screen.findAllByRole(
      'button',
      { name: /View Critical findings/i },
      { timeout: 5000 },
    );
    expect(
      screen.queryAllByRole('button', { name: /View High findings/i }),
    ).toHaveLength(0);
  });
});

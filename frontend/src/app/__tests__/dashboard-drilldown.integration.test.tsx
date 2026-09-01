// @vitest-environment jsdom
/**
 * Dashboard drill-down integration — the source half of the chain. Renders
 * the REAL dashboard page, lets the posture query resolve, then clicks a hero
 * severity count and asserts where it navigates.
 *
 * A severity slice is portfolio-scoped, so it opens the portfolio-scoped
 * Vulnerabilities tab (`/analysis?tab=vulnerabilities&severity=…`). It used to
 * open `topRunForSeverity(...)` — the single run with the most findings of that
 * severity — which showed a fraction of the number the user had clicked (77 of
 * 289 High, in one real case). Both tests below pin that change: the
 * destination, and the fact that a tier with portfolio findings is clickable
 * even when no single run carries them.
 *
 * The EPSS tile and needs-review chip still drill into a specific run — they
 * have no per-run column to rank by — so those cases are unchanged.
 *
 * Sibling panels are stubbed so the assertions are pinned on the hero wiring.
 */

import { describe, expect, it, vi, beforeEach } from 'vitest';
import { render, screen, fireEvent, waitFor } from '@testing-library/react';
import type { ReactNode } from 'react';
import { QueryClient, QueryClientProvider } from '@tanstack/react-query';
import { ToastProvider } from '@/hooks/useToast';
import { AuthProvider } from '@/hooks/useAuth';
import { ThemeProvider } from '@/components/theme/ThemeProvider';
import type { AnalysisRun } from '@/types';

const push = vi.fn();
vi.mock('next/navigation', () => ({
  useRouter: () => ({ push, replace: vi.fn(), back: vi.fn() }),
  useSearchParams: () => new URLSearchParams(),
  usePathname: () => '/',
}));

const getDashboardSummary = vi.fn();
const getRuns = vi.fn();
vi.mock('@/lib/api', async () => {
  const actual = await vi.importActual<typeof import('@/lib/api')>('@/lib/api');
  return {
    ...actual,
    getDashboardSummary: (...a: unknown[]) => getDashboardSummary(...a),
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
vi.mock('@/components/dashboard/LifecycleHealthTiles', () => ({
  LifecycleHealthTiles: () => null,
}));
vi.mock('@/components/dashboard/VulnerabilityAgePie', () => ({
  VulnerabilityAgePie: () => null,
}));
vi.mock('@/components/dashboard/advanced/CopilotPanel', () => ({
  CopilotPanel: () => null,
}));
vi.mock('@/components/dashboard/advanced/ForecastCard', () => ({
  ForecastCard: () => null,
}));
vi.mock('@/components/dashboard/advanced/ExploitationOutlookCard', () => ({
  ExploitationOutlookCard: () => null,
}));
vi.mock('@/components/dashboard/advanced/PortfolioRiskMap', () => ({
  PortfolioRiskMap: () => null,
}));
vi.mock('@/components/dashboard/advanced/RiskMatrixCard', () => ({
  RiskMatrixCard: () => null,
}));
vi.mock('@/components/dashboard/advanced/RemediationPanel', () => ({
  RemediationPanel: () => null,
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
      <AuthProvider>
        <ThemeProvider>
          <ToastProvider>{children}</ToastProvider>
        </ThemeProvider>
      </AuthProvider>
    </QueryClientProvider>
  );
}

beforeEach(() => {
  push.mockReset();
  getDashboardSummary.mockReset();
  getRuns.mockReset();
  getDashboardSummary.mockResolvedValue({
    posture: {
      severity: { critical: 42, high: 0, medium: 0, low: 0, unknown: 0 },
      kev_count: 0,
      fix_available_count: 0,
      last_successful_run_at: '2026-05-01T10:02:00Z',
      total_sboms: 3,
      total_active_projects: 1,
      headline_state: 'criticals_no_kev',
    },
  });
  getRuns.mockResolvedValue([RUN]);
});

describe('dashboard hero — severity drill-down', () => {
  it('opens the portfolio-wide Vulnerabilities tab for the clicked severity', async () => {
    render(wrap(<DashboardPage />));

    // The Critical count becomes an interactive button once posture resolves
    // (severity bar segment + legend badge).
    const buttons = await screen.findAllByRole(
      'button',
      { name: /View Critical findings/i },
      { timeout: 5000 },
    );
    expect(buttons.length).toBeGreaterThan(0);

    fireEvent.click(buttons[0]!);

    // Portfolio-scoped destination — no run id, no globalCount reconciliation
    // needed, because the list reports the same number the slice showed.
    expect(push).toHaveBeenCalledWith('/analysis?tab=vulnerabilities&severity=critical');
    expect(push).not.toHaveBeenCalledWith(expect.stringContaining('/analysis/7'));
  });

  it('keeps a severity clickable when no single run carries it', async () => {
    // Portfolio reports 9 highs, but RUN has high_count: 0. The old gate
    // required topRunForSeverity('high') to resolve and rendered a dead label
    // here; the portfolio-wide destination needs no per-run target.
    getDashboardSummary.mockResolvedValue({
      posture: {
        severity: { critical: 42, high: 9, medium: 0, low: 0, unknown: 0 },
        kev_count: 0,
        fix_available_count: 0,
        last_successful_run_at: '2026-05-01T10:02:00Z',
        total_sboms: 3,
        total_active_projects: 1,
        headline_state: 'criticals_no_kev',
      },
    });
    render(wrap(<DashboardPage />));

    const highButtons = await screen.findAllByRole(
      'button',
      { name: /View High findings/i },
      { timeout: 5000 },
    );
    expect(highButtons.length).toBeGreaterThan(0);

    fireEvent.click(highButtons[0]!);
    expect(push).toHaveBeenCalledWith('/analysis?tab=vulnerabilities&severity=high');
  });

  it('leaves a severity with zero portfolio findings unclickable', async () => {
    getDashboardSummary.mockResolvedValue({
      posture: {
        severity: { critical: 42, high: 0, medium: 0, low: 0, unknown: 0 },
        kev_count: 0,
        fix_available_count: 0,
        last_successful_run_at: '2026-05-01T10:02:00Z',
        total_sboms: 3,
        total_active_projects: 1,
        headline_state: 'criticals_no_kev',
      },
    });
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

describe('dashboard hero — Phase 2 gated signals (EPSS tile + needs-review chip)', () => {
  const POSTURE_BASE = {
    severity: { critical: 42, high: 0, medium: 0, low: 0, unknown: 0 },
    kev_count: 0,
    fix_available_count: 0,
    last_successful_run_at: '2026-05-01T10:02:00Z',
    total_sboms: 3,
    total_active_projects: 1,
    headline_state: 'criticals_no_kev',
  };

  it('shows the likely-exploited tile and drills to ?epss=90 when high_epss_count is present', async () => {
    getDashboardSummary.mockResolvedValue({ posture: { ...POSTURE_BASE, high_epss_count: 5 } });
    render(wrap(<DashboardPage />));

    const epssBtn = await screen.findByRole(
      'button',
      { name: /Likely exploited/i },
      { timeout: 5000 },
    );
    fireEvent.click(epssBtn);
    expect(push).toHaveBeenCalledWith('/analysis/7?epss=90&globalCount=5');
  });

  it('shows the needs-review chip and drills to ?review=1 when needs_review_count > 0', async () => {
    getDashboardSummary.mockResolvedValue({ posture: { ...POSTURE_BASE, needs_review_count: 3 } });
    render(wrap(<DashboardPage />));

    const chip = await screen.findByRole(
      'button',
      { name: /need review/i },
      { timeout: 5000 },
    );
    fireEvent.click(chip);
    expect(push).toHaveBeenCalledWith('/analysis/7?review=1&globalCount=3');
  });

  it('hides both gated signals when the posture fields are absent', async () => {
    // beforeEach posture carries neither field.
    render(wrap(<DashboardPage />));
    await screen.findAllByRole(
      'button',
      { name: /View Critical findings/i },
      { timeout: 5000 },
    );
    expect(screen.queryByRole('button', { name: /Likely exploited/i })).toBeNull();
    expect(screen.queryByRole('button', { name: /need review/i })).toBeNull();
  });
});

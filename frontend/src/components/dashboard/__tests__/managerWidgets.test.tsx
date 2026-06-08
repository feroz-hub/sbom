// @vitest-environment jsdom
/**
 * Manager dashboard widgets — counters, vulnerability-age pie, trend explorer.
 *
 * Asserts DOM controls and the API calls each widget makes (Recharts doesn't
 * paint SVG under jsdom's zero-size layout, so we target the legend/controls
 * and the fetch args, not chart geometry).
 */

import { describe, expect, it, vi, beforeEach } from 'vitest';
import { render, screen, fireEvent, waitFor } from '@testing-library/react';
import type { ReactNode } from 'react';
import { QueryClient, QueryClientProvider } from '@tanstack/react-query';
import { ThemeProvider } from '@/components/theme/ThemeProvider';

const push = vi.fn();
vi.mock('next/navigation', () => ({
  useRouter: () => ({ push, replace: vi.fn(), back: vi.fn() }),
  useSearchParams: () => new URLSearchParams(),
  usePathname: () => '/',
}));

const getDashboardPosture = vi.fn();
const getVulnerabilityAge = vi.fn();
const getProjects = vi.fn();
const getDashboardTrendFiltered = vi.fn();
vi.mock('@/lib/api', async () => {
  const actual = await vi.importActual<typeof import('@/lib/api')>('@/lib/api');
  return {
    ...actual,
    getDashboardPosture: (...a: unknown[]) => getDashboardPosture(...a),
    getVulnerabilityAge: (...a: unknown[]) => getVulnerabilityAge(...a),
    getProjects: (...a: unknown[]) => getProjects(...a),
    getDashboardTrendFiltered: (...a: unknown[]) => getDashboardTrendFiltered(...a),
  };
});

import { CounterTiles } from '@/components/dashboard/CounterTiles';
import { VulnerabilityAgePie } from '@/components/dashboard/VulnerabilityAgePie';
import { TrendExplorer } from '@/components/dashboard/TrendExplorer';

function wrap(children: ReactNode) {
  const qc = new QueryClient({
    defaultOptions: { queries: { retry: false, gcTime: 0, staleTime: 0 } },
  });
  return (
    <QueryClientProvider client={qc}>
      <ThemeProvider>{children}</ThemeProvider>
    </QueryClientProvider>
  );
}

beforeEach(() => {
  push.mockReset();
  getDashboardPosture.mockReset();
  getVulnerabilityAge.mockReset();
  getProjects.mockReset();
  getDashboardTrendFiltered.mockReset();
  getProjects.mockResolvedValue([]);
  getDashboardTrendFiltered.mockResolvedValue({ days: 0, points: [], series: [], granularity: 'week' });
});

describe('CounterTiles', () => {
  it('renders the three counts from posture and drills to the right list', async () => {
    getDashboardPosture.mockResolvedValue({
      severity: { critical: 0, high: 0, medium: 0, low: 0, unknown: 0 },
      kev_count: 0,
      fix_available_count: 0,
      last_successful_run_at: null,
      total_sboms: 10,
      total_active_projects: 4,
      total_applications_scanned: 3,
      total_sboms_analysed: 7,
    });
    render(wrap(<CounterTiles />));

    expect(await screen.findByText('10')).toBeInTheDocument(); // stored
    expect(screen.getByText('3')).toBeInTheDocument(); // applications scanned
    expect(screen.getByText('7')).toBeInTheDocument(); // analysed

    fireEvent.click(screen.getByRole('button', { name: /Total SBOMs Stored/i }));
    expect(push).toHaveBeenCalledWith('/sboms');
  });
});

describe('VulnerabilityAgePie', () => {
  it('renders age buckets and refetches when the period changes', async () => {
    getVulnerabilityAge.mockResolvedValue({
      buckets: { le_30d: 2, d31_90: 1, d91_365: 0, gt_365: 3, unknown: 1 },
      total: 7,
      period: 'all',
      date_from: null,
      date_to: null,
    });
    render(wrap(<VulnerabilityAgePie />));

    expect(await screen.findByText('≤ 30 days')).toBeInTheDocument();
    expect(screen.getByText('> 1 year')).toBeInTheDocument();
    // default fetch uses the "all" period
    await waitFor(() =>
      expect(getVulnerabilityAge).toHaveBeenCalledWith({ period: 'all' }, expect.anything()),
    );

    fireEvent.change(screen.getByLabelText(/observation window/i), {
      target: { value: 'year' },
    });
    await waitFor(() =>
      expect(getVulnerabilityAge).toHaveBeenCalledWith({ period: 'year' }, expect.anything()),
    );
  });
});

describe('TrendExplorer', () => {
  it('fetches at the chosen granularity and applies the application filter', async () => {
    getProjects.mockResolvedValue([
      { id: 1, project_name: 'App A', project_status: 1, created_on: null, created_by: null, modified_on: null, modified_by: null, project_details: null },
    ]);
    render(wrap(<TrendExplorer />));

    // Default granularity is week.
    await waitFor(() =>
      expect(getDashboardTrendFiltered).toHaveBeenCalledWith(
        { granularity: 'week', applicationIds: undefined },
        expect.anything(),
      ),
    );

    // Switch granularity → refetch at month.
    fireEvent.click(screen.getByRole('button', { name: /^month$/i }));
    await waitFor(() =>
      expect(getDashboardTrendFiltered).toHaveBeenCalledWith(
        { granularity: 'month', applicationIds: undefined },
        expect.anything(),
      ),
    );

    // Select an application → refetch filtered to its id.
    fireEvent.click(await screen.findByLabelText('App A'));
    await waitFor(() =>
      expect(getDashboardTrendFiltered).toHaveBeenCalledWith(
        { granularity: 'month', applicationIds: [1] },
        expect.anything(),
      ),
    );
  });
});

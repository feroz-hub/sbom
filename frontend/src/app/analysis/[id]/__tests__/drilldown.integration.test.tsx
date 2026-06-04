// @vitest-environment jsdom
/**
 * Drill-down destination integration — the link the chain historically broke
 * at. Renders the REAL run-detail page (Suspense + useSearchParams +
 * useFindingsFilterFromUrl + the lifted severityFilter state + the
 * ['findings-enriched', id, severityFilter] query) and proves a
 * `?severity=CRITICAL` deep-link actually narrows the findings request on
 * first load — not just in an isolated mock.
 *
 * Fail-before: with severityFilter seeded from `useState('')` (the pre-fix
 * code), the findings call goes out with `severity: undefined` and this test
 * fails. Pass-after: seeded from the URL, it goes out with `'CRITICAL'`.
 *
 * FindingsTable / RunDetailHero are stubbed — they are presentational and not
 * part of the broken link; stubbing them keeps the test pinned on the
 * URL→state→query-key→API wiring that lives in the page itself.
 */

import { describe, expect, it, vi, beforeEach } from 'vitest';
import { render, screen } from '@testing-library/react';
import type { ReactNode } from 'react';
import { QueryClient, QueryClientProvider } from '@tanstack/react-query';
import { ToastProvider } from '@/hooks/useToast';
import { ThemeProvider } from '@/components/theme/ThemeProvider';
import type { AnalysisRun } from '@/types';

// react@18.3.1 (what vitest resolves) doesn't expose the `use()` API the page
// uses to read route params under Next's runtime. Unwrap the test's resolved
// `params` promise synchronously so the component can render — the drill-down
// wiring under test (useSearchParams → severityFilter → query) stays real.
vi.mock('react', async (importOriginal) => {
  const actual = await importOriginal<typeof import('react')>();
  return {
    ...actual,
    use: (value: unknown) =>
      value && typeof (value as { then?: unknown }).then === 'function'
        ? { id: '7' }
        : value,
  };
});

// ── Per-test mutable URL state ────────────────────────────────────────────
let currentParams = new URLSearchParams();
const routerReplace = vi.fn();
vi.mock('next/navigation', () => ({
  useRouter: () => ({ push: vi.fn(), replace: routerReplace, back: vi.fn() }),
  useSearchParams: () => currentParams,
  usePathname: () => '/analysis/7',
}));

// ── API mocks (the three queryFns the page fires on mount) ────────────────
const getRun = vi.fn();
const getAllEnrichedRunFindings = vi.fn();
const getAnalysisConfig = vi.fn();
vi.mock('@/lib/api', async () => {
  const actual = await vi.importActual<typeof import('@/lib/api')>('@/lib/api');
  return {
    ...actual,
    getRun: (...a: unknown[]) => getRun(...a),
    getAllEnrichedRunFindings: (...a: unknown[]) => getAllEnrichedRunFindings(...a),
    getAnalysisConfig: (...a: unknown[]) => getAnalysisConfig(...a),
  };
});

// ── Presentational stubs that record the props they receive ───────────────
let lastFindingsTableProps: Record<string, unknown> = {};
vi.mock('@/components/analysis/FindingsTable', () => ({
  FindingsTable: (props: Record<string, unknown>) => {
    lastFindingsTableProps = props;
    return (
      <div data-testid="findings-table" data-severity={String(props.severityFilter ?? '')} />
    );
  },
}));
vi.mock('@/components/analysis/RunDetailHero', () => ({
  RunDetailHero: () => <div data-testid="run-hero" />,
}));

import AnalysisDetailPage from '@/app/analysis/[id]/page';

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
  currentParams = new URLSearchParams();
  routerReplace.mockReset();
  getRun.mockReset();
  getAllEnrichedRunFindings.mockReset();
  getAnalysisConfig.mockReset();
  getRun.mockResolvedValue(RUN);
  getAllEnrichedRunFindings.mockResolvedValue({ findings: [], totalCount: 5 });
  getAnalysisConfig.mockResolvedValue({
    cve_modal_enabled: true,
    ai_fixes_enabled: false,
    ai_default_provider: null,
  });
});

describe('run-detail drill-down — ?severity=CRITICAL', () => {
  it('seeds severityFilter from the URL and narrows the findings request', async () => {
    currentParams = new URLSearchParams('severity=CRITICAL&globalCount=42');
    render(wrap(<AnalysisDetailPage params={Promise.resolve({ id: '7' })} />));

    // Wait for the run to load and the table to mount.
    await screen.findByTestId('findings-table', {}, { timeout: 5000 });

    // The findings query must be keyed/sent with the URL severity — this is
    // the exact link the chain broke at.
    expect(getAllEnrichedRunFindings).toHaveBeenCalledWith(
      7,
      { severity: 'CRITICAL' },
      expect.anything(),
    );

    // And the seeded value reached the controlled findings table.
    expect(screen.getByTestId('findings-table').getAttribute('data-severity')).toBe(
      'CRITICAL',
    );
    expect(lastFindingsTableProps.severityFilter).toBe('CRITICAL');
  });

  it('renders the reconciliation banner with the portfolio global count', async () => {
    currentParams = new URLSearchParams('severity=CRITICAL&globalCount=42');
    render(wrap(<AnalysisDetailPage params={Promise.resolve({ id: '7' })} />));

    // Wait for the run to load (the loading spinner also carries role=status,
    // so query the banner only after the table mounts).
    await screen.findByTestId('findings-table', {}, { timeout: 5000 });
    const banner = screen.getByRole('status');
    expect(banner).toHaveTextContent(/Filtered from the dashboard/i);
    expect(banner).toHaveTextContent(/Critical findings/i);
    expect(banner).toHaveTextContent('42'); // portfolio-wide global count
  });
});

describe('run-detail without drill-down params (control)', () => {
  it('requests findings unfiltered and shows no banner', async () => {
    render(wrap(<AnalysisDetailPage params={Promise.resolve({ id: '7' })} />));

    await screen.findByTestId('findings-table', {}, { timeout: 5000 });
    const call = getAllEnrichedRunFindings.mock.calls[0]!;
    expect((call[1] as { severity?: string }).severity).toBeUndefined();
    expect(screen.getByTestId('findings-table').getAttribute('data-severity')).toBe('');
    expect(screen.queryByRole('status')).not.toBeInTheDocument();
  });
});

describe('run-detail drill-down — exploitability/quality params (pre-wired)', () => {
  it('seeds the client EPSS filter from ?epss=90 and labels the banner', async () => {
    currentParams = new URLSearchParams('epss=90&globalCount=12');
    render(wrap(<AnalysisDetailPage params={Promise.resolve({ id: '7' })} />));

    await screen.findByTestId('findings-table', {}, { timeout: 5000 });
    const filter = lastFindingsTableProps.filter as { epssMinPct: number };
    expect(filter.epssMinPct).toBe(90);
    expect(screen.getByRole('status')).toHaveTextContent(/likely-exploited/i);
  });

  it('seeds the not-verified filter from ?review=1 and labels the banner', async () => {
    currentParams = new URLSearchParams('review=1&globalCount=4');
    render(wrap(<AnalysisDetailPage params={Promise.resolve({ id: '7' })} />));

    await screen.findByTestId('findings-table', {}, { timeout: 5000 });
    const filter = lastFindingsTableProps.filter as { matchReasonFilter: string };
    expect(filter.matchReasonFilter).toBe('not_verified');
    expect(screen.getByRole('status')).toHaveTextContent(/need review/i);
  });
});

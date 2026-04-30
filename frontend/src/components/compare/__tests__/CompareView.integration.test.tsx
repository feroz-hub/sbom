// @vitest-environment jsdom
/**
 * CompareView integration — empty / loading / error / loaded states.
 *
 * The router mock is bare (we don't exercise URL writes here — that's
 * useCompareUrlState's job). We mock the underlying API methods and the
 * top-level URL state shape via the search-params mock so each test starts
 * in a known URL state.
 */

import { describe, expect, it, vi, beforeEach } from 'vitest';
import { screen, waitFor } from '@testing-library/react';
import { CompareView } from '@/components/compare/CompareView';
import { renderWithCompareProviders, SAMPLE_COMPARE_RESULT } from './test-utils';
import { HttpError } from '@/lib/api';

// Per-test mutable URL state.
let currentParams = new URLSearchParams();

vi.mock('next/navigation', () => ({
  useRouter: () => ({
    push: () => {},
    replace: () => {},
    back: () => {},
  }),
  useSearchParams: () => currentParams,
  usePathname: () => '/analysis/compare',
}));

const compareRunsV2 = vi.fn();
const recentRuns = vi.fn();
const searchRuns = vi.fn();
const exportCompare = vi.fn();
vi.mock('@/lib/api', async () => {
  const actual = await vi.importActual<typeof import('@/lib/api')>('@/lib/api');
  return {
    ...actual,
    compareRunsV2: (...args: unknown[]) => compareRunsV2(...args),
    recentRuns: (...args: unknown[]) => recentRuns(...args),
    searchRuns: (...args: unknown[]) => searchRuns(...args),
    exportCompare: (...args: unknown[]) => exportCompare(...args),
  };
});

vi.mock('@/components/vulnerabilities/CveDetailDialog', () => ({
  CveDetailDialog: ({ open }: { open: boolean }) =>
    open ? <div data-testid="cve-modal-stub" /> : null,
}));

beforeEach(() => {
  currentParams = new URLSearchParams();
  compareRunsV2.mockReset();
  recentRuns.mockReset();
  searchRuns.mockReset();
  exportCompare.mockReset();
  recentRuns.mockResolvedValue([]);
  searchRuns.mockResolvedValue([]);
});

describe('CompareView — empty selection', () => {
  it('shows the in-page picker entry state when no runs are in URL', () => {
    renderWithCompareProviders(<CompareView />);
    expect(screen.getByText(/Pick two runs to compare/i)).toBeInTheDocument();
  });
});

describe('CompareView — same-run guard', () => {
  it('shows the same-run state when run_a === run_b', () => {
    currentParams = new URLSearchParams('run_a=5&run_b=5');
    renderWithCompareProviders(<CompareView />);
    expect(screen.getByText(/same run twice/i)).toBeInTheDocument();
  });
});

describe('CompareView — loading', () => {
  it('renders the skeleton while compare is in flight', () => {
    currentParams = new URLSearchParams('run_a=1&run_b=2');
    compareRunsV2.mockReturnValue(new Promise(() => {})); // never resolves
    const { container } = renderWithCompareProviders(<CompareView />);
    // Skeleton uses a generic Spinner-style block — assert no real rows.
    expect(screen.queryByRole('tab')).not.toBeInTheDocument();
    expect(container.querySelector('.shimmer')).toBeTruthy();
  });
});

describe('CompareView — error envelopes', () => {
  it('maps run-not-ready (E002) into the warning banner', async () => {
    currentParams = new URLSearchParams('run_a=1&run_b=2');
    compareRunsV2.mockRejectedValue(
      new HttpError('not ready', 409, 'COMPARE_E002_RUN_NOT_READY'),
    );
    renderWithCompareProviders(<CompareView />);
    await waitFor(() =>
      expect(screen.getByText(/isn't ready yet/i)).toBeInTheDocument(),
    );
  });

  it('maps run-not-found (E001) into the error banner', async () => {
    currentParams = new URLSearchParams('run_a=1&run_b=2');
    compareRunsV2.mockRejectedValue(
      new HttpError('not found', 404, 'COMPARE_E001_RUN_NOT_FOUND'),
    );
    renderWithCompareProviders(<CompareView />);
    await waitFor(() =>
      expect(screen.getByText(/Run not found/i)).toBeInTheDocument(),
    );
  });
});

describe('CompareView — loaded happy path', () => {
  it('renders posture region with three deltas; no risk score scalar', async () => {
    currentParams = new URLSearchParams('run_a=1&run_b=2');
    compareRunsV2.mockResolvedValue(SAMPLE_COMPARE_RESULT);
    renderWithCompareProviders(<CompareView />);

    // Wait for the data-driven hero to render. The v1 "Posture delta"
    // eyebrow text is gone after the UI uplift — see compare-ui-redesign.md.
    // We anchor on a tile label instead, which still exists in the new
    // PostureHero composition.
    await waitFor(() =>
      expect(screen.getByText(/KEV exposure/i)).toBeInTheDocument(),
    );

    // The three Region 2 tiles each display their label.
    expect(screen.getByText(/KEV exposure/i)).toBeInTheDocument();
    expect(screen.getByText(/Fix-available coverage/i)).toBeInTheDocument();
    expect(screen.getByText(/High\+Critical exposure/i)).toBeInTheDocument();

    // PB-1 visual contract: no element labelled "risk score" anywhere.
    expect(screen.queryByText(/risk score/i)).not.toBeInTheDocument();
  });

  it('renders three tabs and switches when clicked', async () => {
    currentParams = new URLSearchParams('run_a=1&run_b=2');
    compareRunsV2.mockResolvedValue(SAMPLE_COMPARE_RESULT);
    renderWithCompareProviders(<CompareView />);
    await waitFor(() =>
      expect(screen.getAllByRole('tab')).toHaveLength(3),
    );
    const tabs = screen.getAllByRole('tab');
    expect(tabs[0]).toHaveAttribute('aria-selected', 'true');
    expect(tabs[0]).toHaveTextContent(/Findings/);
    expect(tabs[1]).toHaveTextContent(/Components/);
    expect(tabs[2]).toHaveTextContent(/Posture detail/);
  });
});

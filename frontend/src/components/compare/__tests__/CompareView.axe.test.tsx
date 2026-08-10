// @vitest-environment jsdom
/**
 * Accessibility regression check via vitest-axe — every CompareView state.
 *
 * Looks for:
 *   * dialog/menu/tab/listbox roles correctly applied
 *   * KEV / fix-available chips not colour-only (text labels present)
 *   * change-kind chips not colour-only
 *   * filter buttons have accessible names (aria-label or text)
 */

import { describe, expect, it, vi, beforeEach } from 'vitest';
import { axe } from 'vitest-axe';
import { waitFor } from '@testing-library/react';
import { CompareView } from '@/components/compare/CompareView';
import { renderWithCompareProviders, SAMPLE_COMPARE_RESULT } from './test-utils';
import { HttpError } from '@/lib/api';

let currentParams = new URLSearchParams();

vi.mock('next/navigation', () => ({
  useRouter: () => ({ push: () => {}, replace: () => {}, back: () => {} }),
  useSearchParams: () => currentParams,
  usePathname: () => '/analysis/compare',
}));

const compareRunsV2 = vi.fn();
vi.mock('@/lib/api', async () => {
  const actual = await vi.importActual<typeof import('@/lib/api')>('@/lib/api');
  return {
    ...actual,
    compareRunsV2: (...args: unknown[]) => compareRunsV2(...args),
    recentRuns: () => Promise.resolve([]),
    searchRuns: () => Promise.resolve([]),
  };
});

vi.mock('@/components/vulnerabilities/CveDetailDialog', () => ({
  CveDetailDialog: () => null,
}));

beforeEach(() => {
  compareRunsV2.mockReset();
  currentParams = new URLSearchParams();
});

describe('CompareView accessibility', () => {
  it('empty selection state has zero axe violations', async () => {
    const { container } = renderWithCompareProviders(<CompareView />);
    // heading-order is a page-level rule; the compare view sits inside a
    // layout that supplies <h1> in production. Skip it for component-isolated
    // tests so we don't false-positive on the layout's absence.
    const results = await axe(container, {
      rules: { 'heading-order': { enabled: false } },
    });
    expect(results.violations).toEqual([]);
  }, 10_000);

  it('same-run state has zero axe violations', async () => {
    currentParams = new URLSearchParams('run_a=5&run_b=5');
    const { container } = renderWithCompareProviders(<CompareView />);
    // heading-order is a page-level rule; the compare view sits inside a
    // layout that supplies <h1> in production. Skip it for component-isolated
    // tests so we don't false-positive on the layout's absence.
    const results = await axe(container, {
      rules: { 'heading-order': { enabled: false } },
    });
    expect(results.violations).toEqual([]);
  }, 10_000);

  it('error state has zero axe violations', async () => {
    currentParams = new URLSearchParams('run_a=1&run_b=2');
    compareRunsV2.mockRejectedValue(
      new HttpError('not ready', 409, 'COMPARE_E002_RUN_NOT_READY'),
    );
    const { container, findByText } = renderWithCompareProviders(<CompareView />);
    await findByText(/isn't ready yet/i);
    // heading-order is a page-level rule; the compare view sits inside a
    // layout that supplies <h1> in production. Skip it for component-isolated
    // tests so we don't false-positive on the layout's absence.
    const results = await axe(container, {
      rules: { 'heading-order': { enabled: false } },
    });
    expect(results.violations).toEqual([]);
  }, 10_000);

  it('loaded state has zero axe violations', async () => {
    currentParams = new URLSearchParams('run_a=1&run_b=2');
    compareRunsV2.mockResolvedValue(SAMPLE_COMPARE_RESULT);
    const { container, getAllByRole } = renderWithCompareProviders(<CompareView />);
    await waitFor(() => expect(getAllByRole('tab')).toHaveLength(3));
    // heading-order is a page-level rule; the compare view sits inside a
    // layout that supplies <h1> in production. Skip it for component-isolated
    // tests so we don't false-positive on the layout's absence.
    const results = await axe(container, {
      rules: { 'heading-order': { enabled: false } },
    });
    expect(results.violations).toEqual([]);
  }, 10_000);

  it('identical-runs state (the most common production case) has zero axe violations', async () => {
    currentParams = new URLSearchParams('run_a=1&run_b=2');
    compareRunsV2.mockResolvedValue({
      ...SAMPLE_COMPARE_RESULT,
      posture: {
        ...SAMPLE_COMPARE_RESULT.posture,
        findings_added_count: 0,
        findings_resolved_count: 0,
        findings_severity_changed_count: 0,
        findings_unchanged_count: 373,
      },
      findings: [],
      components: [],
    });
    const { container, findByText } = renderWithCompareProviders(<CompareView />);
    await findByText(/No changes detected/i);
    const results = await axe(container, {
      rules: { 'heading-order': { enabled: false } },
    });
    expect(results.violations).toEqual([]);
  }, 10_000);
});

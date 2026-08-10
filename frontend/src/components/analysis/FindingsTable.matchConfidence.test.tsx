// @vitest-environment jsdom
/**
 * PR-E table-level tests for the confidence chip and strategy-option
 * derivation:
 *
 *   1. ``match_confidence`` renders as a percentage chip next to the
 *      trust badge.
 *   2. Null ``match_confidence`` renders nothing (PR4-style parity).
 *   3. The strategy filter chips surface ONLY values actually present
 *      in the loaded findings — dead strategies don't show.
 */

import { afterEach, describe, expect, it, vi } from 'vitest';
import { fireEvent, render, screen, within } from '@testing-library/react';
import { QueryClient, QueryClientProvider } from '@tanstack/react-query';
import { FindingsTable } from './FindingsTable';
import type { EnrichedFinding } from '@/types';

vi.mock('@/hooks/useAiFix', () => ({
  useRunAiFixList: () => ({ data: undefined, isLoading: false, isError: false }),
}));

vi.mock('@/components/vulnerabilities/CveDetailDialog', () => ({
  CveDetailDialog: () => null,
  useCveHoverPrefetch: () => ({ onHoverStart: () => () => {}, onHoverEnd: () => {} }),
  findingToSeed: () => ({}),
}));

function makeFinding(
  id: number,
  overrides: Partial<EnrichedFinding> = {},
): EnrichedFinding {
  return {
    id,
    analysis_run_id: 1,
    vuln_id: `CVE-2099-${String(id).padStart(5, '0')}`,
    title: `finding ${id}`,
    description: null,
    severity: 'HIGH',
    score: 7.0,
    vector: null,
    published_on: null,
    reference_url: null,
    cwe: null,
    cpe: null,
    component_name: `pkg-${id}`,
    component_version: '1.0.0',
    fixed_versions: null,
    attack_vector: null,
    cvss_version: null,
    aliases: null,
    source: 'NVD',
    in_kev: false,
    epss: 0,
    epss_percentile: null,
    risk_score: 0,
    cve_aliases: [],
    ...overrides,
  } as EnrichedFinding;
}

function renderTable(findings: EnrichedFinding[]) {
  const qc = new QueryClient({
    defaultOptions: { queries: { retry: false }, mutations: { retry: false } },
  });
  return render(
    <QueryClientProvider client={qc}>
      <FindingsTable findings={findings} isLoading={false} error={null} />
    </QueryClientProvider>,
  );
}

afterEach(() => {
  vi.restoreAllMocks();
});

describe('FindingsTable — match_confidence chip', () => {
  it('renders the confidence as a whole-percent chip with tooltip', () => {
    renderTable([
      makeFinding(1, {
        match_strategy: 'cpe_name',
        match_confidence: 0.873,
        match_reason: 'matched',
        matched_range: '>= 2.0.0, < 2.17.0',
      }),
    ]);
    const chip = screen.getByLabelText('Match confidence 87 percent');
    expect(chip.textContent).toContain('87%');
    expect(chip.getAttribute('title')).toMatch(/token-overlap/i);
  });

  it('renders nothing when match_confidence is null AND match_reason is null', () => {
    renderTable([
      makeFinding(2, {
        match_strategy: null,
        match_confidence: null,
        match_reason: null,
      }),
    ]);
    expect(screen.queryByText(/%$/)).toBeNull();
    expect(screen.queryByText('Version confirmed')).toBeNull();
    expect(screen.queryByText('Not verified')).toBeNull();
  });

  it('renders the confidence chip even when match_reason is null', () => {
    // A source can tag confidence + strategy without a #1 verdict
    // (e.g. an OSV finding — match_reason only comes from the NVD
    // version-range filter). The chip must still render.
    renderTable([
      makeFinding(3, {
        source: 'OSV',
        match_strategy: 'purl_direct',
        match_confidence: 0.612,
        match_reason: null,
      }),
    ]);
    expect(screen.getByLabelText('Match confidence 61 percent')).toBeTruthy();
  });
});

describe('FindingsTable — strategy-filter options', () => {
  it('surfaces only strategies actually present in the loaded findings', () => {
    renderTable([
      makeFinding(10, { match_strategy: 'cpe_name' }),
      makeFinding(11, { match_strategy: 'purl_direct' }),
      // Note: NO ghsa_alias / keyword_search rows.
    ]);

    // Open the filter panel.
    fireEvent.click(screen.getByRole('button', { name: /^Filters/i }));

    const matchStrategyLegend = screen.getByText('Match strategy');
    const fieldset = matchStrategyLegend.closest('fieldset');
    expect(fieldset).not.toBeNull();
    const fs = fieldset as HTMLElement;

    // Present strategies render as chips.
    expect(within(fs).getByText('CPE name')).toBeTruthy();
    expect(within(fs).getByText('PURL direct')).toBeTruthy();

    // Absent strategies do NOT render — they have zero tagged rows.
    expect(within(fs).queryByText('GHSA alias')).toBeNull();
    expect(within(fs).queryByText('Keyword search')).toBeNull();
    expect(within(fs).queryByText('Virtual match')).toBeNull();
  });

  it('renders an empty-state placeholder when no findings carry a strategy', () => {
    renderTable([makeFinding(20, { match_strategy: null })]);
    fireEvent.click(screen.getByRole('button', { name: /^Filters/i }));
    expect(screen.getByText(/No strategy tags on these findings/i)).toBeTruthy();
  });
});

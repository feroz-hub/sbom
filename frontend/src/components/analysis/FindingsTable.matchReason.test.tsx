// @vitest-environment jsdom
/**
 * Roadmap #1 PR4 — match-reason trust badge tests for FindingsTable.
 *
 * Covers the three rendering cases the brief calls out:
 *   - `match_reason = 'matched'` + `matched_range` → "Version confirmed"
 *     success badge; range surfaces in the title attribute.
 *   - `match_reason = 'and_node_ambiguous'` (any conservative-keep
 *     reason) → "Not verified" muted badge; reason name in the title.
 *   - `match_reason = null/undefined` → no badge at all; row layout
 *     stays byte-identical to pre-PR1 (the constraint that lets the
 *     flag default to off without visual churn).
 *
 * Mirrors the scaffolding in `FindingsTable.selection.test.tsx` —
 * mocks `useAiFix` + `CveDetailDialog` so jsdom doesn't have to render
 * either subtree.
 */

import { afterEach, describe, expect, it, vi } from 'vitest';
import { screen, render } from '@testing-library/react';
import { QueryClient, QueryClientProvider } from '@tanstack/react-query';
import { FindingsTable } from './FindingsTable';
import type { EnrichedFinding } from '@/types';

// localStorage shim lifted to vitest.setup.ts in PR-E.

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

describe('FindingsTable — match-reason trust badge', () => {
  it('renders the KEV badge when the enriched is_kev flag is true', () => {
    renderTable([makeFinding(99, { is_kev: true, in_kev: false })]);

    expect(screen.getByLabelText('Known exploited vulnerability')).toBeInTheDocument();
  });

  it('renders "Version confirmed" with matched_range in the tooltip for matched findings', () => {
    renderTable([
      makeFinding(1, {
        match_reason: 'matched',
        matched_range: '>= 2.0.0, < 2.17.0',
      }),
    ]);
    const badge = screen.getByText('Version confirmed');
    expect(badge).toBeTruthy();
    // Tooltip lives on the wrapping span (title attribute) per the
    // Badge primitive's no-API-change wrapping pattern.
    const wrapper = badge.closest('[title]');
    expect(wrapper?.getAttribute('title')).toBe('Affected: >= 2.0.0, < 2.17.0');
    // The other state must NOT be present.
    expect(screen.queryByText('Not verified')).toBeNull();
  });

  it('renders "Not verified" with the specific reason in the tooltip for conservative-keep findings', () => {
    renderTable([
      makeFinding(2, {
        match_reason: 'and_node_ambiguous',
        matched_range: null,
      }),
    ]);
    const badge = screen.getByText('Not verified');
    expect(badge).toBeTruthy();
    const wrapper = badge.closest('[title]');
    // The tooltip text comes from the MATCH_REASON_DETAIL table in
    // Badge.tsx; pin to a substring so a copy-edit on the message
    // doesn't cascade-break the test.
    expect(wrapper?.getAttribute('title')).toMatch(/specific platform/i);
    expect(screen.queryByText('Version confirmed')).toBeNull();
  });

  it('renders "Not verified" for every conservative-keep reason', () => {
    const reasons: Array<EnrichedFinding['match_reason']> = [
      'version_unparseable',
      'and_node_ambiguous',
      'ecosystem_unsupported',
      'no_configurations',
    ];
    renderTable(
      reasons.map((reason, i) =>
        makeFinding(10 + i, { match_reason: reason, matched_range: null }),
      ),
    );
    const notVerified = screen.getAllByText('Not verified');
    expect(notVerified).toHaveLength(reasons.length);
  });

  it('renders no badge when match_reason is null — preserves pre-filter layout', () => {
    renderTable([
      makeFinding(3, { match_reason: null, matched_range: null }),
    ]);
    expect(screen.queryByText('Version confirmed')).toBeNull();
    expect(screen.queryByText('Not verified')).toBeNull();
  });

  it('renders no badge when match_reason is undefined — flag-off scan parity', () => {
    // EnrichedFinding's match_reason is optional; leaving it off entirely
    // is what flag-off rows actually look like.
    renderTable([makeFinding(4)]);
    expect(screen.queryByText('Version confirmed')).toBeNull();
    expect(screen.queryByText('Not verified')).toBeNull();
  });
});

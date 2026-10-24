// @vitest-environment jsdom

import { QueryClient, QueryClientProvider } from '@tanstack/react-query';
import { fireEvent, render, screen, waitFor, within } from '@testing-library/react';
import { useState } from 'react';
import { beforeEach, describe, expect, it, vi } from 'vitest';
import { DEFAULT_FILTERS, type FindingsFilterState } from '@/lib/findingFilters';
import type { EnrichedFinding } from '@/types';
import { FindingsTable } from './FindingsTable';

vi.mock('@/hooks/useAiFix', () => ({
  useRunAiFixList: () => ({ data: undefined, isLoading: false, isError: false }),
}));

vi.mock('@/components/vulnerabilities/CveDetailDialog', () => ({
  CveDetailDialog: () => null,
  useCveHoverPrefetch: () => ({ onHoverStart: () => () => {}, onHoverEnd: () => {} }),
  findingToSeed: () => ({}),
}));

function makeFinding(id: number, overrides: Partial<EnrichedFinding> = {}): EnrichedFinding {
  return {
    id,
    analysis_run_id: 1,
    vuln_id: `CVE-2026-${String(id).padStart(4, '0')}`,
    source: 'NVD',
    title: `Finding ${id}`,
    description: null,
    severity: 'HIGH',
    score: 7.5,
    vector: null,
    cpe: null,
    component_name: `package-${id}`,
    component_version: '1.0.0',
    published_on: null,
    reference_url: null,
    aliases: null,
    attack_vector: null,
    fixed_versions: null,
    cwe: null,
    cvss_version: null,
    in_kev: false,
    is_kev: false,
    epss: 0,
    epss_percentile: null,
    risk_score: 7.5,
    cve_aliases: [],
    ...overrides,
  } as EnrichedFinding;
}

function renderTable(findings: EnrichedFinding[]) {
  const client = new QueryClient({
    defaultOptions: { queries: { retry: false }, mutations: { retry: false } },
  });

  function Harness() {
    const [filter, setFilter] = useState<FindingsFilterState>({ ...DEFAULT_FILTERS });
    return (
      <FindingsTable
        findings={findings}
        isLoading={false}
        error={null}
        filter={filter}
        onFilterChange={setFilter}
        severityFilter={filter.severityFilter}
        onSeverityChange={(severity) =>
          setFilter((current) => ({ ...current, severityFilter: severity }))
        }
        totalFindingsCount={findings.length}
      />
    );
  }

  return render(
    <QueryClientProvider client={client}>
      <Harness />
    </QueryClientProvider>,
  );
}

function openAdvancedFilters() {
  fireEvent.click(screen.getByRole('button', { name: /^Filters/ }));
}

describe('FindingsTable KEV filters', () => {
  beforeEach(() => window.localStorage.clear());

  it('filters before pagination and resets an unchanged two-page result to page 1', async () => {
    const findings = Array.from({ length: 30 }, (_, index) =>
      makeFinding(index + 1, {
        vendor_project: index % 2 === 0 ? 'Apache' : 'Microsoft',
        product: index % 2 === 0 ? 'Log4j2' : 'Windows',
      }),
    );
    renderTable(findings);

    fireEvent.click(screen.getByRole('button', { name: 'Next page' }));
    expect(screen.getByRole('button', { current: 'page' })).toHaveTextContent('2');

    openAdvancedFilters();
    fireEvent.change(screen.getByRole('combobox', { name: 'Vendor' }), {
      target: { value: 'Apache' },
    });

    await waitFor(() =>
      expect(screen.getByRole('button', { current: 'page' })).toHaveTextContent('1'),
    );
    expect(screen.getByText(/Matching findings/)).toHaveTextContent('15');
    expect(screen.getByRole('button', { name: 'Next page' })).toBeDisabled();
  });

  it('clears every filter field and restores all findings', async () => {
    renderTable([
      makeFinding(1, {
        component_name: 'log4j-core',
        severity: 'CRITICAL',
        is_kev: true,
        vendor_project: 'Apache',
        product: 'Log4j2',
        ransomware_status: 'Known',
      }),
      makeFinding(2, { vendor_project: 'Microsoft', product: 'Windows' }),
    ]);

    fireEvent.change(screen.getByRole('searchbox', { name: 'Search findings' }), {
      target: { value: 'log4j' },
    });
    fireEvent.change(screen.getByRole('combobox', { name: 'Severity' }), {
      target: { value: 'CRITICAL' },
    });
    fireEvent.change(screen.getByRole('combobox', { name: 'KEV status' }), {
      target: { value: 'kev' },
    });
    fireEvent.change(screen.getByRole('combobox', { name: 'Ransomware status' }), {
      target: { value: 'known' },
    });
    openAdvancedFilters();
    fireEvent.change(screen.getByRole('combobox', { name: 'Vendor' }), {
      target: { value: 'Apache' },
    });
    fireEvent.change(screen.getByRole('combobox', { name: 'Product' }), {
      target: { value: 'Log4j2' },
    });

    expect(screen.getByRole('button', { name: /^Filters/ })).toHaveTextContent('6');
    fireEvent.click(screen.getByRole('button', { name: 'Clear filters' }));

    await waitFor(() => expect(screen.getByRole('searchbox')).toHaveValue(''));
    expect(screen.getByRole('combobox', { name: 'Severity' })).toHaveValue('');
    expect(screen.getByRole('combobox', { name: 'KEV status' })).toHaveValue('all');
    expect(screen.getByRole('combobox', { name: 'Ransomware status' })).toHaveValue('all');
    expect(screen.getByRole('combobox', { name: 'Vendor' })).toHaveValue('');
    expect(screen.getByRole('combobox', { name: 'Product' })).toHaveValue('');
    expect(screen.getByText(/Matching findings/)).toHaveTextContent('2');
  });

  it('renders KEV and ransomware badges only for exact positive statuses', () => {
    renderTable([
      makeFinding(1, { is_kev: true, ransomware_status: 'Known' }),
      makeFinding(2, { is_kev: false, ransomware_status: 'Unknown' }),
      makeFinding(3, { is_kev: false, ransomware_status: 'Not Known' }),
    ]);

    expect(screen.getAllByLabelText('Known exploited vulnerability')).toHaveLength(1);
    expect(screen.getAllByTitle('Known ransomware campaign use')).toHaveLength(1);
  });

  it('shows a filtered empty state with a working clear action', async () => {
    renderTable([makeFinding(1)]);
    fireEvent.change(screen.getByRole('searchbox'), { target: { value: 'no-such-cve' } });

    expect(await screen.findByText('No findings match the selected filters.')).toBeInTheDocument();
    const table = screen.getByRole('region', { name: 'Vulnerability findings' });
    fireEvent.click(within(table).getByRole('button', { name: 'Clear filters' }));
    await waitFor(() => expect(screen.getByRole('searchbox')).toHaveValue(''));
    expect(screen.queryByText('No findings match the selected filters.')).not.toBeInTheDocument();
  });

  it('distinguishes a run with no findings from a filtered result', () => {
    renderTable([]);
    expect(screen.getByText('No findings were detected for this analysis.')).toBeInTheDocument();
    expect(screen.queryByRole('button', { name: 'Clear filters' })).not.toBeInTheDocument();
  });
});

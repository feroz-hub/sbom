// @vitest-environment jsdom
import { describe, expect, it, vi } from 'vitest';
import { fireEvent, render, screen } from '@testing-library/react';
import { QueryClient, QueryClientProvider } from '@tanstack/react-query';
import { FindingsTable } from './FindingsTable';
import type { EnrichedFinding } from '@/types';

vi.mock('@/hooks/usePermission', () => ({ usePermissions: () => ({ can: () => true, permissionsLoaded: true }) }));

vi.mock('@/hooks/useAiFix', () => ({ useRunAiFixList: () => ({ data: undefined, isLoading: false, isError: false }) }));
vi.mock('@/components/vulnerabilities/CveDetailDialog', () => ({
  CveDetailDialog: () => null,
  useCveHoverPrefetch: () => ({ onHoverStart: () => () => {}, onHoverEnd: () => {} }),
  findingToSeed: () => ({}),
}));

const finding: EnrichedFinding = {
  id: 1, analysis_run_id: 1, component_id: 5, vuln_id: 'CVE-2021-45105',
  title: null, description: 'Log4j fixture', severity: 'MEDIUM', score: 5.9,
  vector: null, published_on: null, reference_url: null, cpe: null,
  component_name: 'log4j-core', component_version: '2.14.1', fixed_versions: null,
  attack_vector: null, aliases: null, source: 'NVD,OSV', cvss_version: '3.1', cvss_source: 'NVD',
  in_kev: false, epss: 0.2, epss_percentile: 0.9, risk_score: 11.8, cve_aliases: ['CVE-2021-45105'],
  bom_ref: 'original-log4j', rating_disagreement: true,
  source_observations: [
    { provider: 'NVD', vuln_id: 'CVE-2021-45105', severity: 'MEDIUM', score: 5.9, references: ['https://nvd.nist.gov/vuln/detail/CVE-2021-45105'] },
    { provider: 'OSV', vuln_id: 'GHSA-fixture', severity: 'HIGH', score: null, applicability: { status: 'affected', reason: 'osv_version_qualified_query' } },
  ],
};

function show(row = finding) {
  render(<QueryClientProvider client={new QueryClient({ defaultOptions: { queries: { retry: false } } })}>
    <FindingsTable findings={[row]} isLoading={false} error={null} />
  </QueryClientProvider>);
  fireEvent.click(screen.getByRole('button', { name: 'Expand details' }));
}

describe('canonical finding evidence', () => {
  it('shows the selected assessment, original identity, and both source classifications', () => {
    show();
    expect(screen.getByText(/Selected CVSS: 5.9/)).toHaveTextContent('3.1 · NVD');
    expect(screen.getByText('Reference: original-log4j')).toBeInTheDocument();
    expect(screen.getByText(/Provider rating disagreement/)).toBeInTheDocument();
    expect(screen.getByText('Verified source observations (2)')).toBeInTheDocument();
    expect(screen.getByText('NVD · CVE-2021-45105 · MEDIUM · CVSS 5.9')).toBeInTheDocument();
    expect(screen.getByText('OSV · GHSA-fixture · HIGH · CVSS Unscored')).toBeInTheDocument();
    expect(screen.getByText(/EPSS probability: 20.00% · Percentile: 90.00%/)).toBeInTheDocument();
    expect(screen.getByText('https://nvd.nist.gov/vuln/detail/CVE-2021-45105')).toHaveAttribute('rel', 'noopener noreferrer');
  });
  it('labels estimated risk inputs and preserves historical readability', () => {
    show({ ...finding, score: null, risk_input_estimated: true, risk_cvss_input: 7.5, source_observations: [] });
    expect(screen.getByText(/Estimated risk input: 7.5 from severity/)).toBeInTheDocument();
    expect(screen.getByText(/Detailed source evidence was not recorded/)).toBeInTheDocument();
  });
});

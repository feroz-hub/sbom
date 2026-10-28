// @vitest-environment jsdom
import { QueryClient, QueryClientProvider, useMutation, useQuery } from '@tanstack/react-query';
import { fireEvent, render, screen, waitFor } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { afterEach, beforeEach, expect, it, vi } from 'vitest';
import type { VexInvestigationDetail } from '@/types';
import { invalidateVexSurfaces, invalidateDashboardTiles } from '@/lib/queryInvalidation';
import { uploadSbomVexDocument, discoverSbomVexDocuments } from '@/lib/api';
import { VexDecisionEditor } from './VexDecisionEditor';
import { VexInvestigationPanel } from './VexInvestigationPanel';
import { PortfolioTrend } from '@/components/dashboard/PortfolioTrend';

const api = vi.hoisted(() => ({ decision: vi.fn(), assignment: vi.fn(), import: vi.fn(), discovery: vi.fn(), summary: vi.fn(), resolver: vi.fn(), trend: vi.fn() }));
vi.mock('@/lib/api', async original => ({ ...(await original<typeof import('@/lib/api')>()),
  setVexInvestigationDecision: (...args: unknown[]) => api.decision(...args), setVexInvestigationAssignment: (...args: unknown[]) => api.assignment(...args),
  uploadSbomVexDocument: (...args: unknown[]) => api.import(...args), discoverSbomVexDocuments: (...args: unknown[]) => api.discovery(...args),
  getDashboardTrend: (...args: unknown[]) => api.trend(...args),
}));
vi.mock('@/hooks/useAuth', () => ({ useAuth: () => ({ user: { permissions: [] }, isLoading: false, hasPermission: () => true }) }));
vi.mock('./AssigneeCombobox', () => ({ AssigneeIdentity: () => null, AssigneeCombobox: ({ onSelect }: { onSelect: (id: string) => void }) => <button onClick={() => onSelect('membership:3')}>Select analyst</button> }));
vi.mock('@/components/dashboard/FindingsTrendChart/FindingsTrendChart', () => ({ FindingsTrendChart: ({ data }: { data?: { total?: number } }) => <output>Trend: {data?.total}</output> }));
const detail: VexInvestigationDetail = {
  capabilities: {
    can_assign: true, can_unassign: true, can_update: true, can_map: true,
    eligible_roles: ['SECURITY_ANALYST', 'DEVELOPER'],
    candidates: [{ id: 'membership:2', label: 'Alice', roles: ['DEVELOPER'] }, { id: 'membership:3', label: 'Analyst', roles: ['SECURITY_ANALYST'] }],
    owner: { id: 'membership:2', label: 'Alice', active: true, is_self: false, roles: ['DEVELOPER'] },
    read_only_reason: null,
  },
  id: 1,
  sbom_id: 5,
  project_name: null,
  product_name: null,
  sbom_name: 'rtos-1',
  vulnerability: {
    canonical_vulnerability_id: 'CVE-2026-4001',
    aliases: ['GHSA-ABCD-1234-5678'],
    severity: 'CRITICAL',
    cvss_score: 9.8,
    description: 'test',
    references: [],
  },
  component: {
    component_id: 11,
    name: 'openssl',
    version: '1.1.1',
    purl: 'pkg:generic/openssl@1.1.1',
    cpe: null,
    bom_ref: null,
    supplier: null,
  },
  analyzer_evidence: {
    detection_state: 'NOT_DETECTED',
    sources: [],
    analysis_run_id: 7,
    match_strategy: null,
    match_confidence: null,
    matched_range: null,
    first_seen_at: '2026-09-24T00:00:00Z',
    last_seen_at: '2026-09-24T00:00:00Z',
  },
  imported_vex: [
    {
      statement_id: 100,
      source_format: 'cyclonedx',
      source_status: 'false_positive',
      normalized_status: 'NOT_AFFECTED',
      author: 'Supplier A',
      source_document_id: 'doc-a',
      source_document_version: '1',
      asserted_at: '2026-09-01T00:00:00Z',
      justification: 'vulnerable_code_not_present',
      impact_statement: null,
      action_statement: null,
      mitigation: null,
      fixed_version: null,
      evidence_url: null,
      mapping_confidence: 'EXACT',
      match_strategy: 'PURL',
      version_applicable: true,
      is_effective: true,
      superseded: false,
    },
  ],
  internal_decision: {
    effective_status: null,
    reviewer: null,
    assigned_to: null,
    reason: null,
    justification: null,
    impact_statement: null,
    action_statement: null,
    evidence_url: null,
    updated_at: null,
  },
  reconciliation_status: 'VEX_ONLY',
  effective_status: 'NOT_AFFECTED',
  history: [],
  row_version: 1,
};
let qc: QueryClient;
const summaryKey = ['dashboard-summary', 'tenant-1', 2, 3, 5];
const tripleKey = ['vex-investigation-by-triple', 5, '11', 'CVE-2026-4001'];
function Summary() {
  const query = useQuery({ queryKey: summaryKey, queryFn: () => api.summary() });
  return <output>Backend count: {query.data?.vex.affected_count}</output>;
}
function Resolver() {
  const query = useQuery({ queryKey: tripleKey, queryFn: () => api.resolver() });
  return <output>Row version: {query.data?.row_version}</output>;
}
function Imports({ discover = false }: { discover?: boolean }) {
  const mutation = useMutation({ mutationFn: async () => { if (discover) await discoverSbomVexDocuments(5, true); else await uploadSbomVexDocument(5, { document: {}, source_name: 'test' }); }, onSuccess: () => invalidateVexSurfaces(qc, 5) });
  return <button onClick={() => mutation.mutate()}>Import evidence</button>;
}
const wrap = (node: React.ReactNode) => <QueryClientProvider client={qc}>{node}</QueryClientProvider>;
function editor(saved = vi.fn(), conflict = vi.fn()) { return <VexDecisionEditor sbomId={5} componentId={11} vulnerabilityId="CVE-2026-4001" investigation={detail} canWrite onSaved={saved} onConflict={conflict} />; }
async function saveDecision() {
  const user = userEvent.setup(); await user.selectOptions(screen.getByLabelText(/Status/), 'UNDER_INVESTIGATION');
  fireEvent.change(screen.getByLabelText(/Reason for this decision/), { target: { value: 'Review current evidence' } });
  await user.click(screen.getByRole('button', { name: 'Save decision' }));
}
beforeEach(() => {
  vi.clearAllMocks(); qc = new QueryClient({ defaultOptions: { queries: { staleTime: 300_000, refetchOnWindowFocus: false, retry: false } } });
  qc.setQueryData(summaryKey, { vex: { affected_count: 7 } }); qc.setQueryData(tripleKey, detail);
  qc.setQueryData(['vex-investigation-by-triple', 6, '11', 'CVE-2026-4001'], detail);
  api.summary.mockResolvedValue({ vex: { affected_count: 2 } }); api.resolver.mockResolvedValue({ ...detail, row_version: 2 });
  api.decision.mockResolvedValue({ ...detail, row_version: 2 }); api.assignment.mockResolvedValue({ ...detail, internal_decision: { ...detail.internal_decision, assigned_to: 'membership:3' } });
  api.import.mockResolvedValue({ statements_imported: 2 }); api.discovery.mockResolvedValue({ statements_imported: 2 }); api.trend.mockResolvedValue({ total: 12 });
});
afterEach(() => qc.clear());
it('decision saves refresh active backend metrics and stale resolver refetches when the editor reopens', async () => {
  const saved = vi.fn(); const mounted = render(wrap(<><Summary />{editor(saved)}</>));
  expect(screen.getByText('Backend count: 7')).toBeInTheDocument(); await saveDecision();
  await screen.findByText('Backend count: 2'); await waitFor(() => expect(saved).toHaveBeenCalledTimes(1));
  expect(api.summary).toHaveBeenCalledTimes(1); expect(qc.getQueryState(tripleKey)?.isInvalidated).toBe(true);
  expect(qc.getQueryState(['vex-investigation-by-triple', 6, '11', 'CVE-2026-4001'])?.isInvalidated).toBe(false);
  mounted.rerender(wrap(<Resolver />)); await screen.findByText('Row version: 2'); expect(api.resolver).toHaveBeenCalledTimes(1);
});
it.each([false, true])('document evidence refreshes active summaries and resolver (discovery=%s)', async discover => {
  render(wrap(<><Summary /><Resolver /><Imports discover={discover} /></>));
  await userEvent.click(screen.getByRole('button', { name: 'Import evidence' }));
  await screen.findByText('Backend count: 2'); await screen.findByText('Row version: 2');
  expect(api.summary).toHaveBeenCalledTimes(1); expect(api.resolver).toHaveBeenCalledTimes(1);
  expect(discover ? api.discovery : api.import).toHaveBeenCalledTimes(1);
});
it('assignment keeps metric caches fresh while refreshing the resolver and retaining onSaved', async () => {
  const saved = vi.fn(); render(wrap(<><Summary /><Resolver /><VexInvestigationPanel detail={detail} onSaved={saved} onConflict={vi.fn()} /></>));
  await userEvent.click(screen.getByRole('button', { name: 'Select analyst' })); await userEvent.click(screen.getByRole('button', { name: 'Save assignment' }));
  await screen.findByText('Row version: 2'); await waitFor(() => expect(saved).toHaveBeenCalledTimes(1));
  expect(api.summary).not.toHaveBeenCalled(); expect(screen.getByText('Backend count: 7')).toBeInTheDocument();
  expect(qc.getQueryState(summaryKey)?.isInvalidated).toBe(false);
});
it.each([500, 409])('failed decision %s retains draft and caches without success', async status => {
  api.decision.mockRejectedValue(Object.assign(new Error('Cannot save'), { status }));
  const saved = vi.fn(), conflict = vi.fn(); render(wrap(<><Summary />{editor(saved, conflict)}</>));
  await saveDecision(); await waitFor(() => expect(api.decision).toHaveBeenCalled());
  if (status === 409) await waitFor(() => expect(conflict).toHaveBeenCalledTimes(1)); else await screen.findByText('Cannot save');
  expect(saved).not.toHaveBeenCalled(); expect(api.summary).not.toHaveBeenCalled(); expect(qc.getQueryState(tripleKey)?.isInvalidated).toBe(false);
  expect(screen.getByLabelText(/Reason for this decision/)).toHaveValue('Review current evidence');
});
it('alternate trend periods refetch scoped backend data after invalidation and cached return', async () => {
  const scope = { projectId: 2, applicationId: 3, sbomId: 5 };
  const key = ['portfolio-trend', 'tenant-1', 2, 3, 5, 90]; qc.setQueryData(key, { total: 7 });
  const mounted = render(wrap(<PortfolioTrend scope={scope} tenantId="tenant-1" />));
  await userEvent.selectOptions(screen.getByLabelText('Observation window'), '90'); expect(screen.getByText('Trend: 7')).toBeInTheDocument();
  mounted.rerender(wrap(null)); await invalidateDashboardTiles(qc); mounted.rerender(wrap(<PortfolioTrend scope={scope} tenantId="tenant-1" />));
  await userEvent.selectOptions(screen.getByLabelText('Observation window'), '90'); await screen.findByText('Trend: 12');
  expect(api.trend).toHaveBeenCalledTimes(1); expect(api.trend.mock.calls[0][0]).toBe(90); expect(api.trend.mock.calls[0][2]).toEqual(scope);
});

it.each([false, true])('failed document evidence does not invalidate caches (discovery=%s)', async discover => {
  (discover ? api.discovery : api.import).mockRejectedValue(new Error('Cannot import'));
  render(wrap(<><Summary /><Resolver /><Imports discover={discover} /></>));
  await userEvent.click(screen.getByRole('button', { name: 'Import evidence' }));
  await waitFor(() => expect(discover ? api.discovery : api.import).toHaveBeenCalledTimes(1));
  expect(api.summary).not.toHaveBeenCalled(); expect(api.resolver).not.toHaveBeenCalled();
  expect(qc.getQueryState(summaryKey)?.isInvalidated).toBe(false); expect(qc.getQueryState(tripleKey)?.isInvalidated).toBe(false);
});

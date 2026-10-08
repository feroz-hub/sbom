// @vitest-environment jsdom

/**
 * PR-5 tests for the portfolio VEX Investigation page.
 *
 * Spec: docs/requirements/vex-dashboard-investigation.md sections 23-24,
 * 27-30 and 46.
 */

import { QueryClient, QueryClientProvider } from '@tanstack/react-query';
import { fireEvent, render, screen, waitFor, within } from '@testing-library/react';
import type { ReactNode } from 'react';
import { beforeEach, describe, expect, it, vi } from 'vitest';
import { ToastProvider } from '@/hooks/useToast';
import type {
  DashboardVex,
  VexInvestigationDetail,
  VexInvestigationListResponse,
  VexInvestigationSummary,
} from '@/types';
import VexInvestigationPage from './page';
import userEvent from '@testing-library/user-event';
import { FULL_DETAIL, PARTIAL_DETAIL } from '@/components/vulnerabilities/CveDetailDialog/__tests__/fixtures';

const api = vi.hoisted(() => ({
  getCveDetail: vi.fn(),
  getDashboardVex: vi.fn(),
  getVexInvestigation: vi.fn(),
  getVexInvestigationSummary: vi.fn(),
  listVexInvestigations: vi.fn(),
  setVexInvestigationDecision: vi.fn(),
  setVexInvestigationAssignment: vi.fn(),
  resolveVexInvestigationComponent: vi.fn(),
  searchVexAssignees: vi.fn(),
}));

const navigation = vi.hoisted(() => ({ replace: vi.fn(), search: '' }));
const permissions = vi.hoisted(() => ({ granted: new Set<string>() }));
const auth = vi.hoisted(() => ({ roles: ['TENANT_ADMIN'] }));
vi.mock('@/hooks/useAuth', () => ({ useAuth: () => ({ user: { userId: 1, roles: auth.roles }, activeTenantId: '1', activeTenant: { roles: auth.roles } }) }));

vi.mock('@/lib/api', () => api);
vi.mock('next/navigation', () => ({
  useRouter: () => ({ replace: navigation.replace }),
  useSearchParams: () => new URLSearchParams(navigation.search),
}));
vi.mock('@/hooks/usePermission', () => ({
  usePermissions: () => ({ can: (p: string) => permissions.granted.has(p), permissionsLoaded: true, effectivePermissions: [...permissions.granted], pendingReason: 'Checking your permissions…' }),
  usePermission: (permission: string) => permissions.granted.has(permission),
  useAnyPermission: (...values: string[]) => values.some((v) => permissions.granted.has(v)),
}));
vi.mock('@/components/layout/TopBar', () => ({
  TopBar: ({ title }: { title: string; action?: ReactNode }) => <h1>{title}</h1>,
}));
// Stubbed like TopBar: the cascading control needs an AuthProvider and has
// its own tests in DashboardFilters.test.tsx. Here we only care that this
// page feeds its selection through to the query.
vi.mock('@/components/dashboard/DashboardFilters', () => ({
  DashboardFilters: ({ scope, onChange }: {
    scope: { projectId: number | null };
    onChange: (s: { projectId: number | null; applicationId: number | null; sbomId: number | null }) => void;
  }) => (
    <button
      type="button"
      onClick={() => onChange({ projectId: 7, applicationId: null, sbomId: null })}
    >
      pick-project-7 (current: {String(scope.projectId)})
    </button>
  ),
}));

const currentView: VexInvestigationSummary = {
  scope: 'filtered',
  total: 13,
  mapped_total: 12,
  affected_count: 1,
  not_affected_count: 2,
  fixed_count: 0,
  under_investigation_count: 9,
  needs_review_count: 3,
  unresolved_mapping_count: 1,
  matched_count: 3,
  analyzer_only_count: 8,
  vex_only_count: 1,
  conflict_review_count: 2,
  revalidation_required_count: 1,
};

const summary: DashboardVex = {
  affected_count: 2,
  not_affected_count: 3,
  fixed_count: 1,
  under_investigation_count: 4,
  unknown_count: 0,
  vulnerabilities_reduced_by_vex: 4,
  vulnerabilities_requiring_action: 6,
  top_affected_components: [],
  total_contexts: 10,
  matched_count: 5,
  analyzer_only_count: 3,
  vex_only_count: 2,
  conflict_review_count: 1,
  revalidation_required_count: 1,
  unresolved_mapping_count: 2,
  needs_review_count: 2,
};

const listResponse: VexInvestigationListResponse = {
  total: 2,
  limit: 50,
  offset: 0,
  items: [
    {
      id: 1,
      canonical_vulnerability_id: 'CVE-2026-4001',
      aliases: ['GHSA-ABCD-1234-5678'],
      severity: 'CRITICAL',
      component_id: 11,
      component_name: 'openssl',
      component_version: '1.1.1',
      project_id: null,
      project_name: null,
      product_id: null,
      product_name: null,
      sbom_id: 5,
      sbom_name: 'rtos-1',
      analyzer_detection_state: 'NOT_DETECTED',
      analyzer_sources: [],
      vex_source: 'Supplier A',
      native_vex_status: 'false_positive',
      effective_status: 'NOT_AFFECTED',
      reconciliation_status: 'VEX_ONLY',
      justification: 'vulnerable_code_not_present',
      assigned_to: null,
      reviewed_by: null,
      last_seen_at: '2026-09-24T00:00:00Z',
      updated_at: null,
      row_version: 1,
      needs_review: false,
    },
    {
      id: 2,
      canonical_vulnerability_id: 'CVE-2026-5001',
      aliases: [],
      severity: 'HIGH',
      component_id: 12,
      component_name: 'zlib',
      component_version: '1.2.11',
      project_id: null,
      project_name: null,
      product_id: null,
      product_name: null,
      sbom_id: 5,
      sbom_name: 'rtos-1',
      analyzer_detection_state: 'DETECTED',
      analyzer_sources: ['NVD'],
      vex_source: null,
      native_vex_status: null,
      effective_status: 'UNDER_INVESTIGATION',
      reconciliation_status: 'CONFLICT_REVIEW_REQUIRED',
      justification: null,
      assigned_to: null,
      reviewed_by: null,
      last_seen_at: '2026-09-24T00:00:00Z',
      updated_at: null,
      row_version: 3,
      needs_review: true,
    },
  ],
};

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

function renderPage() {
  const queryClient = new QueryClient({ defaultOptions: { queries: { retry: false } } });
  return render(
    <QueryClientProvider client={queryClient}>
      <ToastProvider>
        <VexInvestigationPage />
      </ToastProvider>
    </QueryClientProvider>,
  );
}

beforeEach(() => {
  vi.clearAllMocks();
  navigation.search = '';
  auth.roles = ['TENANT_ADMIN'];
  permissions.granted = new Set(['vex:read', 'vex:write']);
  api.getCveDetail.mockResolvedValue({ ...FULL_DETAIL, cve_id: detail.vulnerability.canonical_vulnerability_id });
  api.getDashboardVex.mockResolvedValue(summary);
  api.listVexInvestigations.mockResolvedValue(listResponse);
  api.getVexInvestigationSummary.mockResolvedValue(currentView);
  api.getVexInvestigation.mockResolvedValue(detail);
  api.setVexInvestigationDecision.mockResolvedValue(detail);
  api.setVexInvestigationAssignment.mockResolvedValue(detail);
  api.resolveVexInvestigationComponent.mockResolvedValue(detail);
  api.searchVexAssignees.mockResolvedValue({ items: detail.capabilities!.candidates, total: 2, limit: 50, offset: 0 });
});

describe('summary cards', () => {
  it('renders Current view counts from the filtered summary endpoint__VEX_DASH_004', async () => {
    renderPage();
    const section = await screen.findByRole('region', { name: 'Current view' });
    expect(await within(section).findByText('13')).toBeInTheDocument();
    expect(within(section).getByText('Total investigations')).toBeInTheDocument();
    expect(within(section).getByText('9')).toBeInTheDocument();
    expect(screen.getByText(/1 unresolved component mapping included/)).toBeInTheDocument();
  });

  it('labels the tenant overview separately from the filtered view__VEX_DASH_003', async () => {
    renderPage();
    expect(await screen.findByText(/ignores the filters below/)).toBeInTheDocument();
    expect(await screen.findByText('10')).toBeInTheDocument();
    expect(screen.getByText('Unresolved Mapping')).toBeInTheDocument();
  });

  it('sends the table filters to the metrics, without sort or paging__VEX_DASH_004', async () => {
    renderPage();
    fireEvent.click(await screen.findByRole('button', { name: /pick-project-7/ }));
    await waitFor(() => {
      const list = api.listVexInvestigations.mock.calls.at(-1)?.[0];
      const metrics = api.getVexInvestigationSummary.mock.calls.at(-1)?.[0];
      expect(metrics).toMatchObject({ project_id: 7 });
      const { sort_by: _s, sort_order: _o, limit: _l, offset: _f, ...listFilters } = list;
      expect(metrics).toEqual(listFilters);
    });
  });

  it('clicking a card filters the table__VEX_UI_002', async () => {
    renderPage();
    fireEvent.click(await screen.findByRole('button', { name: /^Affected/ }));
    await waitFor(() => {
      const last = api.listVexInvestigations.mock.calls.at(-1)?.[0];
      expect(last).toMatchObject({ effective_status: 'AFFECTED' });
    });
  });
});

describe('investigation table', () => {
  it('renders the section 27 columns__VEX_UI_001', async () => {
    renderPage();
    expect(await screen.findByText('CVE-2026-4001')).toBeInTheDocument();
    expect(screen.getByText('openssl')).toBeInTheDocument();
    expect(screen.getByText('false_positive')).toBeInTheDocument();
  });

  it('shows severity unchanged by a NOT_AFFECTED decision__VEX_DATA_005', async () => {
    renderPage();
    // The first row is NOT_AFFECTED yet must still read CRITICAL.
    expect(await screen.findByText('CRITICAL')).toBeInTheDocument();
  });

  it('keeps the GHSA alias visible after canonicalisation__VEX_CTX_002', async () => {
    renderPage();
    expect(await screen.findByText('GHSA-ABCD-1234-5678')).toBeInTheDocument();
  });

  it('maps filters to query params__VEX_UI_002', async () => {
    renderPage();
    await screen.findByText('CVE-2026-4001');
    fireEvent.change(screen.getByLabelText('Reconciliation status'), {
      target: { value: 'CONFLICT_REVIEW_REQUIRED' },
    });
    await waitFor(() => {
      const last = api.listVexInvestigations.mock.calls.at(-1)?.[0];
      expect(last).toMatchObject({ reconciliation_status: 'CONFLICT_REVIEW_REQUIRED' });
    });
  });

  it('needs-review toggle is sent to the server__VEX_UI_002', async () => {
    renderPage();
    await screen.findByText('CVE-2026-4001');
    fireEvent.click(screen.getByLabelText('Needs review', { selector: 'input' }));
    await waitFor(() => {
      const last = api.listVexInvestigations.mock.calls.at(-1)?.[0];
      expect(last).toMatchObject({ needs_review: true });
    });
  });
});

describe('decision form', () => {
  async function openDetail() {
    renderPage();
    await screen.findByText('CVE-2026-4001');
    fireEvent.click(screen.getAllByText('Investigate')[0]);
    await screen.findByText('Record a decision');
  }

  it('requires a reason__VEX_AUD_001', async () => {
    await openDetail();
    fireEvent.click(screen.getByRole('button', { name: 'Save decision' }));
    expect(await screen.findByText('A reason is required.')).toBeInTheDocument();
    expect(api.setVexInvestigationDecision).not.toHaveBeenCalled();
  });

  it('requires justification or impact for NOT_AFFECTED__VEX_VAL_001', async () => {
    await openDetail();
    fireEvent.change(screen.getByLabelText(/Reason for this decision/), { target: { value: 'reviewed' } });
    fireEvent.change(screen.getByLabelText(/^Status/), {
      target: { value: 'NOT_AFFECTED' },
    });
    fireEvent.click(screen.getByRole('button', { name: 'Save decision' }));
    expect(
      (await screen.findAllByText('NOT_AFFECTED requires a justification or an impact statement.')).length,
    ).toBeGreaterThan(0);
    expect(api.setVexInvestigationDecision).not.toHaveBeenCalled();
  });

  it('requires a fixed version or evidence for FIXED__VEX_VAL_002', async () => {
    await openDetail();
    fireEvent.change(screen.getByLabelText(/Reason for this decision/), { target: { value: 'patched' } });
    fireEvent.change(screen.getByLabelText(/^Status/), { target: { value: 'FIXED' } });
    fireEvent.click(screen.getByRole('button', { name: 'Save decision' }));
    expect(
      (await screen.findAllByText('FIXED requires a fixed version or evidence.')).length,
    ).toBeGreaterThan(0);
  });

  it('submits the current row_version__VEX_AUD_002', async () => {
    await openDetail();
    fireEvent.change(screen.getByLabelText(/Reason for this decision/), { target: { value: 'reviewed' } });
    fireEvent.change(screen.getByLabelText(/^Status/), { target: { value: 'AFFECTED' } });
    fireEvent.click(screen.getByRole('button', { name: 'Save decision' }));
    await waitFor(() => {
      expect(api.setVexInvestigationDecision).toHaveBeenCalledWith(
        1,
        expect.objectContaining({ status: 'AFFECTED', row_version: 1, reason: 'reviewed' }),
      );
    });
  });

  it('reloads on a 409 conflict__VEX_AUD_002', async () => {
    api.setVexInvestigationDecision.mockRejectedValue(
      Object.assign(new Error('conflict'), { status: 409 }),
    );
    await openDetail();
    fireEvent.change(screen.getByLabelText(/Reason for this decision/), { target: { value: 'reviewed' } });
    fireEvent.change(screen.getByLabelText(/^Status/), { target: { value: 'AFFECTED' } });
    fireEvent.click(screen.getByRole('button', { name: 'Save decision' }));
    await waitFor(() => {
      expect(api.getVexInvestigation).toHaveBeenCalledTimes(2);
    });
  });
});

describe('permissions', () => {
  it('renders read-only without vex:write__VEX_SEC_001', async () => {
    permissions.granted = new Set(['vex:read']);
    api.getVexInvestigation.mockResolvedValue({ ...detail, capabilities: { ...detail.capabilities, can_update: false, can_assign: false, can_map: false, read_only_reason: 'Read-only investigation' } });
    renderPage();
    await screen.findByText('CVE-2026-4001');
    fireEvent.click(screen.getAllByText('Investigate')[0]);
    expect(
      await screen.findByText(/Read-only investigation/),
    ).toBeInTheDocument();
    expect(screen.queryByText('Save decision')).not.toBeInTheDocument();
  });

  it('refuses the page without vex:read__VEX_SEC_001', () => {
    permissions.granted = new Set();
    renderPage();
    expect(
      screen.getByText('You do not have permission to view VEX investigations.'),
    ).toBeInTheDocument();
    expect(api.listVexInvestigations).not.toHaveBeenCalled();
  });
});


describe('scope selector', () => {
  it('sends the selected project to the server__VEX_UI_002', async () => {
    renderPage();
    await screen.findByText('CVE-2026-4001');
    fireEvent.click(screen.getByText(/pick-project-7/));
    await waitFor(() => {
      const last = api.listVexInvestigations.mock.calls.at(-1)?.[0];
      expect(last).toMatchObject({ project_id: 7 });
    });
  });
});

describe('work queue filters', () => {
  it.each(['me', 'unassigned', 'assigned', 'attention', 'all'])('sends My work %s to the paginated API', async value => {
    renderPage();
    await screen.findByText('CVE-2026-4001');
    fireEvent.change(screen.getByLabelText('My work'), { target: { value } });
    await waitFor(() => expect(api.listVexInvestigations.mock.calls.at(-1)?.[0].my_work).toBe(value === 'all' ? undefined : value));
  });

  it('combines personal work, severity, status and scope in the URL and request', async () => {
    navigation.search = 'my_work=me&severity=CRITICAL&effective_status=UNDER_INVESTIGATION&project_id=7&product_id=8&sbom_id=9';
    renderPage();
    await screen.findByText('CVE-2026-4001');
    expect(api.listVexInvestigations.mock.calls.at(-1)?.[0]).toMatchObject({ my_work: 'me', severity: 'CRITICAL', effective_status: 'UNDER_INVESTIGATION', project_id: 7, product_id: 8, sbom_id: 9 });
    expect(screen.getByLabelText('My work')).toHaveValue('me');
    expect(screen.getByLabelText('Severity')).toHaveValue('CRITICAL');
    expect(navigation.replace.mock.calls.at(-1)?.[0]).toContain('my_work=me');
    fireEvent.click(screen.getAllByText('Investigate')[0]);
    await screen.findByText('Record a decision');
    fireEvent.click(screen.getByRole('button', { name: /Close dialog/ }));
    expect(screen.getByLabelText('My work')).toHaveValue('me');
    expect(screen.getByLabelText('Severity')).toHaveValue('CRITICAL');
  });

  it.each(['membership:2', 'membership:3'])('uses the existing searchable selector for %s', async selected => {
    renderPage();
    await screen.findByText('CVE-2026-4001');
    fireEvent.focus(screen.getByRole('combobox', { name: 'Filter by assignee' }));
    const name = selected === 'membership:2' ? /Alice/ : /Analyst/;
    fireEvent.click(await screen.findByRole('option', { name }));
    await waitFor(() => expect(api.listVexInvestigations.mock.calls.at(-1)?.[0]).toMatchObject({ assignee: selected }));
    expect(navigation.replace.mock.calls.at(-1)?.[0]).toContain(`assignee=${encodeURIComponent(selected)}`);
  });

  it('debounces assignee email search and preserves investigations on metadata failure', async () => {
    api.searchVexAssignees.mockRejectedValue(new Error('offline'));
    renderPage();
    await screen.findByText('CVE-2026-4001');
    const input = screen.getByRole('combobox', { name: 'Filter by assignee' });
    fireEvent.focus(input);
    expect(await screen.findByText(/Unable to load assignees/)).toBeInTheDocument();
    expect(screen.getByText('CVE-2026-4001')).toBeInTheDocument();
    api.searchVexAssignees.mockResolvedValue({ items: detail.capabilities!.candidates, total: 2, limit: 50, offset: 0 });
    fireEvent.change(input, { target: { value: 'developer@example.com' } });
    await waitFor(() => expect(api.searchVexAssignees.mock.calls.at(-1)?.[0]).toBe('developer@example.com'));
  });

  it.each(['TENANT_ADMIN', 'SECURITY_ANALYST', 'DEVELOPER'])('shows quick personal work for %s while preserving All as default', async role => {
    auth.roles = [role];
    renderPage();
    await screen.findByText('CVE-2026-4001');
    expect(screen.getByLabelText('My work')).toHaveValue('all');
    fireEvent.click(screen.getByRole('button', { name: 'Assigned to me' }));
    await waitFor(() => expect(api.listVexInvestigations.mock.calls.at(-1)?.[0]).toMatchObject({ my_work: 'me' }));
  });

  it('keeps Viewer discovery read-only without personal work navigation', async () => {
    auth.roles = ['VIEWER'];
    renderPage();
    await screen.findByText('CVE-2026-4001');
    expect(screen.queryByLabelText('My work')).not.toBeInTheDocument();
    expect(screen.queryByRole('button', { name: 'Assigned to me' })).not.toBeInTheDocument();
    expect(screen.getByLabelText('Severity')).toBeInTheDocument();
    expect(screen.getByRole('combobox', { name: 'Filter by assignee' })).toBeInTheDocument();
  });

  it('synchronizes quick filters, removable chips and Clear all', async () => {
    navigation.search = 'project_id=7&product_id=8&sbom_id=9&q=CVE&component=openssl&my_work=me&assignee=membership%3A2&severity=HIGH&effective_status=AFFECTED&reconciliation_status=MATCHED&needs_review=true&unresolved_component=true';
    renderPage();
    await screen.findByText('CVE-2026-4001');
    fireEvent.click(screen.getByRole('button', { name: 'Critical' }));
    await waitFor(() => expect(screen.getByLabelText('Severity')).toHaveValue('CRITICAL'));
    fireEvent.click(screen.getByRole('button', { name: 'Remove Severity: Critical filter' }));
    expect(screen.getByLabelText('Severity')).toHaveValue('');
    fireEvent.click(screen.getByRole('button', { name: 'Clear all filters' }));
    await waitFor(() => expect(navigation.replace.mock.calls.at(-1)?.[0]).toBe('/vex-investigation'));
    expect(screen.getByLabelText('My work')).toHaveValue('all');
    expect(screen.getByLabelText('Component')).toHaveValue('');
    expect(screen.getByLabelText('Needs review', { selector: 'input' })).not.toBeChecked();
  });

  it('distinguishes filtered empty results from an empty queue and request failure', async () => {
    api.listVexInvestigations.mockResolvedValue({ ...listResponse, total: 0, items: [] });
    navigation.search = 'my_work=me&severity=HIGH';
    renderPage();
    expect(await screen.findByText('No matching investigations')).toBeInTheDocument();
    expect(screen.queryByText("You're all caught up")).not.toBeInTheDocument();
    fireEvent.click(screen.getByRole('button', { name: 'Clear all filters' }));
    expect(await screen.findByText('No investigations exist')).toBeInTheDocument();
    api.listVexInvestigations.mockRejectedValue(new Error('offline'));
    fireEvent.click(screen.getByRole('button', { name: 'Critical' }));
    expect(await screen.findByText(/Unable to load investigations/)).toBeInTheDocument();
    expect(screen.queryByText('No matching investigations')).not.toBeInTheDocument();
  });

  it('shows You in the Owner column from the server identity comparison', async () => {
    api.listVexInvestigations.mockResolvedValue({ ...listResponse, items: [{ ...listResponse.items[0], assigned_to: 'membership:2', assigned_to_label: 'Alice', assigned_to_is_self: true, assigned_to_active: true }] });
    renderPage();
    expect(await screen.findByText('You')).toBeInTheDocument();
  });

  it('restores changed URL state on browser navigation', async () => {
    renderPage();
    await screen.findByText('CVE-2026-4001');
    navigation.search = 'my_work=unassigned&severity=HIGH';
    // A rerender represents useSearchParams receiving browser navigation.
    fireEvent.click(screen.getByRole('button', { name: 'Critical' }));
    await waitFor(() => expect(screen.getByLabelText('My work')).toHaveValue('unassigned'));
    expect(screen.getByLabelText('Severity')).toHaveValue('HIGH');
    expect(api.listVexInvestigations.mock.calls.at(-1)?.[0]).toMatchObject({ my_work: 'unassigned', severity: 'HIGH' });
  });

  it('opens the mobile filters sheet and applies the same filter state', async () => {
    renderPage();
    await screen.findByText('CVE-2026-4001');
    fireEvent.click(screen.getByRole('button', { name: /^Filters \(/ }));
    const sheet = screen.getByRole('dialog', { name: 'Investigation filters' });
    fireEvent.change(within(sheet).getByLabelText('Severity'), { target: { value: 'HIGH' } });
    fireEvent.click(within(sheet).getByText('Show investigations'));
    expect(screen.queryByRole('dialog', { name: 'Investigation filters' })).not.toBeInTheDocument();
    expect(screen.getByLabelText('Severity')).toHaveValue('HIGH');
  });

  it('keeps the same query filters when saving an investigation refreshes the queue', async () => {
    navigation.search = 'my_work=me&severity=CRITICAL';
    renderPage();
    await screen.findByText('CVE-2026-4001');
    fireEvent.click(screen.getAllByText('Investigate')[0]);
    await screen.findByText('Record a decision');
    const requests = api.listVexInvestigations.mock.calls.length;
    fireEvent.change(screen.getByLabelText(/Reason for this decision/), { target: { value: 'Reviewed my case' } });
    fireEvent.change(screen.getByLabelText(/^Status/), { target: { value: 'AFFECTED' } });
    fireEvent.click(screen.getByRole('button', { name: 'Save decision' }));
    await waitFor(() => expect(api.listVexInvestigations.mock.calls.length).toBeGreaterThan(requests));
    expect(api.listVexInvestigations.mock.calls.at(-1)?.[0]).toMatchObject({ my_work: 'me', severity: 'CRITICAL' });
  });

  it('preserves bookmarked pagination on initial load', async () => {
    navigation.search = 'my_work=me&page=2&limit=25';
    api.listVexInvestigations.mockResolvedValue({ ...listResponse, total: 100, limit: 25, offset: 25 });
    renderPage();
    await screen.findByText('CVE-2026-4001');
    await new Promise(resolve => setTimeout(resolve, 400));
    expect(api.listVexInvestigations.mock.calls.at(-1)?.[0]).toMatchObject({ my_work: 'me', limit: 25, offset: 25 });
  });
});

describe('ownership and mapping', () => {
  async function openDetail() {
    renderPage();
    await screen.findByText('CVE-2026-4001');
    fireEvent.click(screen.getAllByText('Investigate')[0]);
    await screen.findByText('Ownership & assignment');
  }

  it('assigns an owner with the current row_version__VEX_AUD_002', async () => {
    await openDetail();
    expect(screen.getByText('Save assignment')).toBeDisabled();
    fireEvent.focus(screen.getByRole('combobox', { name: 'Assignee' }));
    fireEvent.click(screen.getByRole('option', { name: /Analyst/ }));
    fireEvent.click(screen.getByText('Save assignment'));
    await waitFor(() => {
      expect(api.setVexInvestigationAssignment).toHaveBeenCalledWith(
        1,
        expect.objectContaining({ assigned_to: 'membership:3', row_version: 1 }),
      );
    });
  });

  it('unassigns through the explicit action', async () => {
    await openDetail();
    fireEvent.click(screen.getByText('Unassign'));
    await waitFor(() => {
      expect(api.setVexInvestigationAssignment).toHaveBeenCalledWith(
        1,
        expect.objectContaining({ assigned_to: null }),
      );
    });
  });

  it('updates current ownership from the saved response', async () => {
    api.setVexInvestigationAssignment.mockResolvedValue({
      ...detail, row_version: 2,
      internal_decision: { ...detail.internal_decision, assigned_to: 'membership:3' },
      capabilities: { ...detail.capabilities!, owner: { id: 'membership:3', label: 'Analyst', email: 'analyst@example.com', roles: ['SECURITY_ANALYST'], active: true, is_self: false } },
    });
    await openDetail();
    fireEvent.focus(screen.getByRole('combobox', { name: 'Assignee' }));
    fireEvent.click(screen.getByRole('option', { name: /Analyst/ }));
    fireEvent.click(screen.getByText('Save assignment'));
    expect(await screen.findByText('Assignment updated successfully.')).toBeInTheDocument();
    expect(screen.getByText('analyst@example.com')).toBeInTheDocument();
    expect(screen.getByText('Save assignment')).toBeDisabled();
  });

  it('keeps current ownership when saving fails', async () => {
    api.setVexInvestigationAssignment.mockRejectedValue(new Error('offline'));
    await openDetail();
    fireEvent.focus(screen.getByRole('combobox', { name: 'Assignee' }));
    fireEvent.click(screen.getByRole('option', { name: /Analyst/ }));
    fireEvent.click(screen.getByText('Save assignment'));
    expect(await screen.findByText(/The current assignment was not changed/)).toBeInTheDocument();
    expect(screen.getAllByText('Alice').length).toBeGreaterThan(0);
  });

  it('offers component binding only for an unresolved mapping__VEX_MAP_001', async () => {
    await openDetail();
    // The fixture is VEX_ONLY, so the binding control must not appear.
    expect(screen.queryByLabelText('Component ID')).not.toBeInTheDocument();
  });

  it('binds an unresolved mapping to a component__VEX_MAP_001', async () => {
    api.getVexInvestigation.mockResolvedValue({
      ...detail,
      reconciliation_status: 'UNRESOLVED_MAPPING',
    });
    await openDetail();
    fireEvent.change(screen.getByLabelText('Component ID'), { target: { value: '42' } });
    fireEvent.click(screen.getByText('Bind to component'));
    await waitFor(() => {
      expect(api.resolveVexInvestigationComponent).toHaveBeenCalledWith(
        1,
        expect.objectContaining({ component_id: 42, row_version: 1 }),
      );
    });
  });
});


describe('server-authoritative investigation capabilities', () => {
  async function openWith(capabilities: VexInvestigationDetail['capabilities']) {
    permissions.granted = new Set(['vex:read']);
    api.getVexInvestigation.mockResolvedValue({ ...detail, capabilities });
    renderPage();
    await screen.findByText('CVE-2026-4001');
    fireEvent.click(screen.getAllByText('Investigate')[0]);
    await screen.findByText('Record a decision');
  }

  it('shows only eligible analyst and developer candidates for an administrator', async () => {
    await openWith(detail.capabilities);
    fireEvent.focus(screen.getByRole('combobox', { name: 'Assignee' }));
    expect(screen.getByRole('option', { name: /Alice/ })).toBeInTheDocument();
    expect(screen.getByRole('option', { name: /Analyst/ })).toBeInTheDocument();
    expect(screen.queryByRole('option', { name: /Viewer|Tenant Admin/ })).not.toBeInTheDocument();
    fireEvent.change(screen.getByLabelText('Assignee'), { target: { value: 'Alice' } });
    expect(screen.queryByRole('option', { name: /Analyst/ })).not.toBeInTheDocument();
  });

  it('shows only developer candidates for a security analyst', async () => {
    await openWith({ ...detail.capabilities!, eligible_roles: ['DEVELOPER'], candidates: detail.capabilities!.candidates.slice(0, 1) });
    fireEvent.focus(screen.getByRole('combobox', { name: 'Assignee' }));
    expect(screen.getByRole('option', { name: /Alice/ })).toBeInTheDocument();
    expect(screen.queryByRole('option', { name: /Analyst/ })).not.toBeInTheDocument();
    expect(screen.getByText('Delegate this investigation to a Developer in this tenant.')).toBeInTheDocument();
  });

  it('allows the assigned developer to save without broad vex:write', async () => {
    await openWith({ ...detail.capabilities!, can_assign: false, can_unassign: false, can_map: false, candidates: [], owner: { ...detail.capabilities!.owner, is_self: true } });
    expect(screen.getAllByText('Alice (You)').length).toBeGreaterThan(0);
    expect(screen.queryByLabelText('Assignee')).not.toBeInTheDocument();
    expect(screen.queryByText('Unassign')).not.toBeInTheDocument();
    fireEvent.change(screen.getByLabelText(/Reason for this decision/), { target: { value: 'Verified evidence' } });
    fireEvent.change(screen.getByLabelText(/^Status/), { target: { value: 'AFFECTED' } });
    fireEvent.click(screen.getByText('Save decision'));
    await waitFor(() => expect(api.setVexInvestigationDecision).toHaveBeenCalled());
    expect(api.setVexInvestigationAssignment).not.toHaveBeenCalled();
  });

  it.each(['unassigned developer', 'other developer', 'viewer'])('keeps %s read-only', async () => {
    await openWith({ ...detail.capabilities!, can_assign: false, can_unassign: false, can_map: false, can_update: false, candidates: [], read_only_reason: 'This investigation must be assigned to you before you can update it.' });
    expect(screen.queryByLabelText('Assignee')).not.toBeInTheDocument();
    expect(screen.queryByText('Save decision')).not.toBeInTheDocument();
    expect(screen.queryByLabelText(/^Status/)).not.toBeInTheDocument();
    expect(screen.getByText('This investigation must be assigned to you before you can update it.')).toBeInTheDocument();
  });
});


describe('shared CVE detail workflow', () => {
  it('opens the Run Analysis details content from the CVE link and retains exact VEX context', async () => {
    renderPage();
    const trigger = await screen.findByRole('button', { name: 'View vulnerability CVE-2026-4001' });
    await userEvent.click(trigger);
    const dialog = await screen.findByRole('dialog');
    expect(within(dialog).getByRole('tab', { name: 'Vulnerability Details' })).toHaveAttribute('aria-selected', 'true');
    expect(await within(dialog).findByText(FULL_DETAIL.summary)).toBeVisible();
    expect(within(dialog).getByText('What is this CVE?')).toBeVisible();
    expect(within(dialog).getByText('How is it exploited?')).toBeVisible();
    expect(within(dialog).getByText('How do I fix it?')).toBeVisible();
    expect(within(dialog).getByRole('link', { name: 'Open in NVD' })).toHaveAttribute('rel', 'noopener noreferrer');
    const context = within(dialog).getByRole('region', { name: 'Selected investigation context' });
    expect(within(context).getByText('rtos-1')).toBeVisible();
    expect(within(context).getByText('openssl 1.1.1')).toBeVisible();
    expect(within(context).getByText('NOT_DETECTED')).toBeVisible();
    expect(within(context).getByText('false_positive')).toBeVisible();
    expect(within(context).getByText('NOT_AFFECTED')).toBeVisible();
    expect(within(context).getByText('VEX ONLY')).toBeVisible();
    await waitFor(() => expect(api.getCveDetail).toHaveBeenCalledWith(
      { cveId: 'CVE-2026-4001', scanId: 7, componentId: 11 }, expect.any(AbortSignal),
    ));
    const detailsTab = within(dialog).getByRole('tab', { name: 'Vulnerability Details' });
    detailsTab.focus();
    await userEvent.keyboard('{ArrowRight}');
    expect(within(dialog).getByRole('tab', { name: 'VEX Investigation' })).toHaveFocus();
    expect(within(dialog).getByText('Record a decision')).toBeVisible();
    expect(within(dialog).getByText('Supplier A')).toBeVisible();
    await userEvent.keyboard('{Home}');
    expect(detailsTab).toHaveFocus();
    await userEvent.keyboard('{Escape}');
    await waitFor(() => expect(screen.queryByRole('dialog')).not.toBeInTheDocument());
    expect(trigger).toHaveFocus();
  });

  it('Investigate opens the same dialog directly on the VEX tab', async () => {
    renderPage();
    await screen.findByText('CVE-2026-4001');
    await userEvent.click(screen.getAllByRole('button', { name: 'Investigate' })[0]);
    expect(await screen.findByRole('tab', { name: 'VEX Investigation' })).toHaveAttribute('aria-selected', 'true');
    await userEvent.click(screen.getByRole('tab', { name: 'Vulnerability Details' }));
    expect(await screen.findByText(FULL_DETAIL.summary)).toBeVisible();
    expect(screen.getAllByRole('dialog')).toHaveLength(1);
    expect(api.getCveDetail).toHaveBeenCalledTimes(1);
  });

  it('keeps row context and investigation usable when enrichment fails, with retry', async () => {
    api.getCveDetail.mockRejectedValueOnce(Object.assign(new Error('offline'), { status: 400 }));
    renderPage();
    await userEvent.click(await screen.findByRole('button', { name: 'View vulnerability CVE-2026-4001' }));
    expect(await screen.findByText('Unable to load vulnerability details. Showing the known context.')).toBeVisible();
    expect(within(screen.getByRole('region', { name: 'Selected investigation context' })).getByText('rtos-1')).toBeVisible();
    await userEvent.click(screen.getByRole('button', { name: 'Retry CVE enrichment' }));
    expect(await screen.findByText(FULL_DETAIL.summary)).toBeVisible();
    await userEvent.click(screen.getByRole('tab', { name: 'VEX Investigation' }));
    expect(screen.getByRole('button', { name: 'Save decision' })).toBeVisible();
  });

  it('retains known row context when investigation details fail and supports retry', async () => {
    api.getVexInvestigation.mockRejectedValue(new Error('offline'));
    renderPage();
    await screen.findByText('CVE-2026-4001');
    await userEvent.click(screen.getAllByRole('button', { name: 'Investigate' })[0]);
    expect(await screen.findByText('Unable to load investigation details.')).toBeVisible();
    expect(screen.queryByRole('button', { name: 'Save decision' })).not.toBeInTheDocument();
    api.getVexInvestigation.mockResolvedValue(detail);
    await userEvent.click(screen.getByRole('button', { name: 'Retry investigation' }));
    expect(await screen.findByRole('button', { name: 'Save decision' })).toBeVisible();
  });

  it('shows partial enrichment without blocking investigation', async () => {
    api.getCveDetail.mockResolvedValue(PARTIAL_DETAIL);
    renderPage();
    await userEvent.click(await screen.findByRole('button', { name: 'View vulnerability CVE-2026-4001' }));
    expect(await screen.findByText('Some sources were unavailable')).toBeVisible();
    expect(screen.getByText(PARTIAL_DETAIL.summary)).toBeVisible();
    await userEvent.click(screen.getByRole('tab', { name: 'VEX Investigation' }));
    expect(screen.getByRole('button', { name: 'Save decision' })).toBeVisible();
  });

  it('does not use another component or allow a decision for unresolved mapping', async () => {
    api.getVexInvestigation.mockResolvedValue({ ...detail, component: { ...detail.component, component_id: null, name: null }, reconciliation_status: 'UNRESOLVED_MAPPING' });
    renderPage();
    await screen.findByText('CVE-2026-4001');
    await userEvent.click(screen.getAllByRole('button', { name: 'Investigate' })[0]);
    expect(await screen.findByText(/Component mapping unresolved\./)).toBeVisible();
    expect(screen.queryByRole('button', { name: 'Save decision' })).not.toBeInTheDocument();
    expect(screen.getByRole('button', { name: 'Bind to component' })).toBeVisible();
    await waitFor(() => expect(api.getCveDetail).toHaveBeenCalledWith(
      { cveId: 'CVE-2026-4001', scanId: null }, expect.any(AbortSignal),
    ));
  });

  it('preserves filters and URL state across opening, tab changes and closing', async () => {
    navigation.search = 'q=CVE-2026&project_id=7&product_id=8&sbom_id=9&effective_status=NOT_AFFECTED&reconciliation_status=VEX_ONLY&component=openssl&needs_review=true&sort_by=component&sort_order=asc&limit=25';
    renderPage();
    await screen.findByRole('button', { name: 'View vulnerability CVE-2026-4001' });
    await new Promise(resolve => setTimeout(resolve, 400));
    const urlBefore = navigation.replace.mock.calls.at(-1)?.[0];
    const filtersBefore = api.listVexInvestigations.mock.calls.at(-1)?.[0];
    await userEvent.click(screen.getByRole('button', { name: 'View vulnerability CVE-2026-4001' }));
    await userEvent.click(screen.getByRole('tab', { name: 'VEX Investigation' }));
    await userEvent.click(screen.getByRole('button', { name: 'Close dialog' }));
    expect(navigation.replace.mock.calls.at(-1)?.[0]).toBe(urlBefore);
    expect(api.listVexInvestigations.mock.calls.at(-1)?.[0]).toEqual(filtersBefore);
  });

  it('refreshes the selected context, rows and dashboard after saving, without changing identity', async () => {
    renderPage();
    await screen.findByText('CVE-2026-4001');
    await userEvent.click(screen.getAllByRole('button', { name: 'Investigate' })[0]);
    await screen.findByRole('button', { name: 'Save decision' });
    const counts = [api.getVexInvestigation.mock.calls.length, api.listVexInvestigations.mock.calls.length, api.getDashboardVex.mock.calls.length];
    api.getVexInvestigation.mockResolvedValue({ ...detail, effective_status: 'AFFECTED', row_version: 2 });
    api.listVexInvestigations.mockResolvedValue({ ...listResponse, items: listResponse.items.map(row => row.id === 1 ? { ...row, effective_status: 'AFFECTED' } : row) });
    fireEvent.change(screen.getByLabelText(/^Status/), { target: { value: 'AFFECTED' } });
    fireEvent.change(screen.getByLabelText(/Reason for this decision/), { target: { value: 'Confirmed' } });
    await userEvent.click(screen.getByRole('button', { name: 'Save decision' }));
    await waitFor(() => {
      expect(api.getVexInvestigation.mock.calls.length).toBeGreaterThan(counts[0]);
      expect(api.listVexInvestigations.mock.calls.length).toBeGreaterThan(counts[1]);
      expect(api.getDashboardVex.mock.calls.length).toBeGreaterThan(counts[2]);
    });
    expect(api.setVexInvestigationDecision).toHaveBeenCalledWith(1, expect.objectContaining({ status: 'AFFECTED', row_version: 1 }));
    expect(within(screen.getByRole('region', { name: 'Selected investigation context' })).getByText('AFFECTED')).toBeVisible();
    expect(screen.getByRole('dialog')).toBeVisible();
  });
  it('retains saved fixed-version and mitigation fields when editing a decision', async () => {
    api.getVexInvestigation.mockResolvedValue({ ...detail, internal_decision: {
      ...detail.internal_decision, effective_status: 'FIXED', reason: 'Patched',
      fixed_version: '3.2.1', mitigation: 'Updated deployment',
    } });
    renderPage();
    await screen.findByText('CVE-2026-4001');
    await userEvent.click(screen.getAllByRole('button', { name: 'Investigate' })[0]);
    expect(await screen.findByLabelText(/^Fixed version/)).toHaveValue('3.2.1');
    expect(screen.getByLabelText('Mitigation')).toHaveValue('Updated deployment');
  });

});

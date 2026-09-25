// @vitest-environment jsdom

/**
 * PR-5 tests for the portfolio VEX Investigation page.
 *
 * Spec: docs/requirements/vex-dashboard-investigation.md sections 23-24,
 * 27-30 and 46.
 */

import { QueryClient, QueryClientProvider } from '@tanstack/react-query';
import { fireEvent, render, screen, waitFor } from '@testing-library/react';
import type { ReactNode } from 'react';
import { beforeEach, describe, expect, it, vi } from 'vitest';
import { ToastProvider } from '@/hooks/useToast';
import type {
  DashboardVex,
  VexInvestigationDetail,
  VexInvestigationListResponse,
} from '@/types';
import VexInvestigationPage from './page';

const api = vi.hoisted(() => ({
  getDashboardVex: vi.fn(),
  getVexInvestigation: vi.fn(),
  listVexInvestigations: vi.fn(),
  setVexInvestigationDecision: vi.fn(),
  setVexInvestigationAssignment: vi.fn(),
  resolveVexInvestigationComponent: vi.fn(),
}));

const navigation = vi.hoisted(() => ({ replace: vi.fn(), search: '' }));
const permissions = vi.hoisted(() => ({ granted: new Set<string>() }));

vi.mock('@/lib/api', () => api);
vi.mock('next/navigation', () => ({
  useRouter: () => ({ replace: navigation.replace }),
  useSearchParams: () => new URLSearchParams(navigation.search),
}));
vi.mock('@/hooks/usePermission', () => ({
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
  permissions.granted = new Set(['vex:read', 'vex:write']);
  api.getDashboardVex.mockResolvedValue(summary);
  api.listVexInvestigations.mockResolvedValue(listResponse);
  api.getVexInvestigation.mockResolvedValue(detail);
  api.setVexInvestigationDecision.mockResolvedValue(detail);
  api.setVexInvestigationAssignment.mockResolvedValue(detail);
  api.resolveVexInvestigationComponent.mockResolvedValue(detail);
});

describe('summary cards', () => {
  it('renders counts from the dashboard endpoint__VEX_DASH_003', async () => {
    renderPage();
    expect(await screen.findByText('Total Contexts')).toBeInTheDocument();
    expect(await screen.findByText('10')).toBeInTheDocument();
    expect(screen.getByText('Needs Review')).toBeInTheDocument();
    expect(screen.getByText('Unresolved Mapping')).toBeInTheDocument();
  });

  it('clicking a card filters the table__VEX_UI_002', async () => {
    renderPage();
    fireEvent.click(await screen.findByText('Affected'));
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
    fireEvent.click(screen.getAllByText('Open')[0]);
    await screen.findByText('Record a decision');
  }

  it('requires a reason__VEX_AUD_001', async () => {
    await openDetail();
    fireEvent.click(screen.getByText('Save decision'));
    expect(await screen.findByText('A reason is required.')).toBeInTheDocument();
    expect(api.setVexInvestigationDecision).not.toHaveBeenCalled();
  });

  it('requires justification or impact for NOT_AFFECTED__VEX_VAL_001', async () => {
    await openDetail();
    fireEvent.change(screen.getByLabelText('Reason'), { target: { value: 'reviewed' } });
    fireEvent.change(screen.getByLabelText('Decision status'), {
      target: { value: 'NOT_AFFECTED' },
    });
    fireEvent.click(screen.getByText('Save decision'));
    expect(
      await screen.findByText('NOT_AFFECTED requires a justification or an impact statement.'),
    ).toBeInTheDocument();
    expect(api.setVexInvestigationDecision).not.toHaveBeenCalled();
  });

  it('requires a fixed version or evidence for FIXED__VEX_VAL_002', async () => {
    await openDetail();
    fireEvent.change(screen.getByLabelText('Reason'), { target: { value: 'patched' } });
    fireEvent.change(screen.getByLabelText('Decision status'), { target: { value: 'FIXED' } });
    fireEvent.click(screen.getByText('Save decision'));
    expect(
      await screen.findByText('FIXED requires a fixed version or evidence.'),
    ).toBeInTheDocument();
  });

  it('submits the current row_version__VEX_AUD_002', async () => {
    await openDetail();
    fireEvent.change(screen.getByLabelText('Reason'), { target: { value: 'reviewed' } });
    fireEvent.change(screen.getByLabelText('Decision status'), { target: { value: 'AFFECTED' } });
    fireEvent.click(screen.getByText('Save decision'));
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
    fireEvent.change(screen.getByLabelText('Reason'), { target: { value: 'reviewed' } });
    fireEvent.change(screen.getByLabelText('Decision status'), { target: { value: 'AFFECTED' } });
    fireEvent.click(screen.getByText('Save decision'));
    await waitFor(() => {
      expect(api.getVexInvestigation).toHaveBeenCalledTimes(2);
    });
  });
});

describe('permissions', () => {
  it('renders read-only without vex:write__VEX_SEC_001', async () => {
    permissions.granted = new Set(['vex:read']);
    renderPage();
    await screen.findByText('CVE-2026-4001');
    fireEvent.click(screen.getAllByText('Open')[0]);
    expect(
      await screen.findByText(/Read-only: recording a decision requires the vex:write permission/),
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

describe('ownership and mapping', () => {
  async function openDetail() {
    renderPage();
    await screen.findByText('CVE-2026-4001');
    fireEvent.click(screen.getAllByText('Open')[0]);
    await screen.findByText('Ownership and mapping');
  }

  it('assigns an owner with the current row_version__VEX_AUD_002', async () => {
    await openDetail();
    fireEvent.change(screen.getByLabelText('Assign to'), { target: { value: 'alice' } });
    fireEvent.click(screen.getByText('Save assignment'));
    await waitFor(() => {
      expect(api.setVexInvestigationAssignment).toHaveBeenCalledWith(
        1,
        expect.objectContaining({ assigned_to: 'alice', row_version: 1 }),
      );
    });
  });

  it('unassigns by clearing the field', async () => {
    await openDetail();
    fireEvent.click(screen.getByText('Save assignment'));
    await waitFor(() => {
      expect(api.setVexInvestigationAssignment).toHaveBeenCalledWith(
        1,
        expect.objectContaining({ assigned_to: null }),
      );
    });
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

// @vitest-environment jsdom

/**
 * Secure Component Advisor frontend (spec Step 9). Prompt §10 T35–T43 run as
 * page-level integration tests (decision D-9: Vitest, no browser E2E harness
 * exists): the backend contract is mocked at @/lib/api exactly as the real
 * responses are shaped (see tests/test_component_advisor_*_api.py).
 */

import { QueryClient, QueryClientProvider } from '@tanstack/react-query';
import { act, fireEvent, render, screen, waitFor, within, type RenderResult } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { Suspense, type ReactNode } from 'react';
import { beforeEach, describe, expect, it, vi } from 'vitest';
import { axe } from 'vitest-axe';
import { ToastProvider } from '@/hooks/useToast';
import { ADVISOR_NOTICE_KINDS, AdvisorNotice } from '@/components/component-advisor/AdvisorNotice';
import * as labels from '@/components/component-advisor/labels';
import type {
  AdvisorComponent,
  AdvisorComponentDetail,
  AdvisorComponentList,
  AdvisorMeta,
  AdvisorRecommendation,
  AdvisorSummary,
} from '@/types/componentAdvisor';
import ComponentAdvisorPage from './page';
import ComponentDetailPage from './components/[key]/page';
import RecommendationPage from './recommendations/[id]/page';

class TestApiError extends Error {
  constructor(public status: number) { super(`HTTP ${status}`); }
}

const api = vi.hoisted(() => ({
  ApiError: class {} as unknown,
  getAdvisorSummary: vi.fn(),
  listAdvisorComponents: vi.fn(),
  getAdvisorComponent: vi.fn(),
  createAdvisorRecommendation: vi.fn(),
  getAdvisorRecommendation: vi.fn(),
  evaluateAdvisorRecommendation: vi.fn(),
  decideAdvisorRecommendation: vi.fn(),
  getAdvisorCandidateEvidence: vi.fn(),
  getAdvisorCandidateCompatibility: vi.fn(),
}));
api.ApiError = TestApiError;

const navigation = vi.hoisted(() => ({ replace: vi.fn(), push: vi.fn(), search: '' }));
const permissions = vi.hoisted(() => ({ granted: new Set<string>() }));
vi.mock('@/lib/api', () => api);
vi.mock('@/hooks/useAuth', () => ({ useAuth: () => ({ activeTenantId: '1', user: { userId: 1, roles: ['TENANT_ADMIN'] } }) }));
vi.mock('next/navigation', () => ({
  useRouter: () => ({ replace: navigation.replace, push: navigation.push }),
  useSearchParams: () => new URLSearchParams(navigation.search),
}));
vi.mock('next/link', () => ({ default: ({ href, children, ...rest }: { href: string; children: ReactNode }) => <a href={href} {...rest}>{children}</a> }));
vi.mock('@/hooks/usePermission', () => ({
  usePermission: (permission: string) => permissions.granted.has(permission),
  useAnyPermission: (...values: string[]) => values.some((v) => permissions.granted.has(v)),
}));
vi.mock('@/components/layout/TopBar', () => ({ TopBar: ({ title }: { title: string }) => <h1>{title}</h1> }));
vi.mock('@/components/dashboard/DashboardFilters', () => ({
  DashboardFilters: ({ onChange }: { onChange: (s: { projectId: number | null; applicationId: number | null; sbomId: number | null }) => void }) => (
    <button type="button" onClick={() => onChange({ projectId: 7, applicationId: null, sbomId: null })}>pick-project-7</button>
  ),
}));

const META: AdvisorMeta = {
  applied_filters: { risk: [], lifecycle: [], needs_review: null, frequently_adopted: null, trusted: null, q: null, facet: 'all' },
  unsupported_filters: [],
  scope: { level: 'TENANT', tenant: { id: 1, name: 'Acme' }, project: null, application: null, sbom: null },
  as_of: '2026-10-02T00:00:00Z',
  generated_at: '2026-10-02T00:00:00Z',
  historical_view: false,
  freshness: {
    latest_analysis_at: '2026-10-01T00:00:00Z', lifecycle_checked_at: null, vulnerability_source_refreshed_at: null,
    package_metadata_refreshed_at: null, coverage: { eligible_sboms: 3, analysed_sboms: 3, unattributed_actionable_findings: 0 },
    stale_flags: [],
  },
  policy_versions: { accepted_risk: null, trust: null },
  thresholds: { frequently_adopted_min_products: 3 },
  capabilities: { informational_severity_supported: false },
};

function summary(overrides: Partial<AdvisorSummary> = {}): AdvisorSummary {
  return {
    kpis: [
      { key: 'unique_component_versions', label: 'Unique Component Versions', value: 5, status: 'OK', render: true, filter: {} },
      { key: 'no_known_actionable_vulnerabilities', label: 'No Known Actionable Vulnerabilities', value: 2, status: 'OK', render: true, filter: { risk: ['NO_KNOWN_ACTIONABLE_VULNERABILITIES'] } },
      { key: 'within_accepted_risk', label: 'Components Within Accepted Risk', value: null, status: 'POLICY_NOT_CONFIGURED', render: true, filter: { risk: ['ACCEPTED_RISK'] } },
      { key: 'critical', label: 'Critical-Risk Components', value: 1, status: 'OK', render: true, filter: { risk: ['CRITICAL'] } },
      { key: 'trusted_by_policy', label: 'Trusted-by-Policy Components', value: null, status: 'POLICY_NOT_CONFIGURED', render: false, filter: { trusted: true } },
    ],
    by_classification: {} as AdvisorSummary['by_classification'],
    by_lifecycle: {} as AdvisorSummary['by_lifecycle'],
    meta: META,
    ...overrides,
  };
}

function component(overrides: Partial<AdvisorComponent> = {}): AdvisorComponent {
  return {
    canonical_key: 'k-log4j', identity: { basis: 'purl', confidence: 'HIGH' }, family_key: 'maven:log4j-core',
    name: 'log4j-core', version: '2.14.1', purl: 'pkg:maven/log4j-core@2.14.1', cpe: null, supplier: 'Apache',
    component_type: 'library', ecosystem: 'maven', licenses: ['Apache-2.0'],
    purpose: { status: 'NOT_AVAILABLE', ai_assisted: false, functional_description: null, primary_use_case: null, technology_category: null },
    trust: { status: 'POLICY_NOT_CONFIGURED', policy_version_id: null, criteria: [] },
    usage: { active_sbom_occurrences: 2, sbom_count: 2, project_count: 1, product_count: 2, references: [] },
    risk: {
      classification: 'CRITICAL', review_reasons: [], accepted_risk_policy_version_id: null, accepted_risk: null,
      actionable_vulnerability_count: 1, non_actionable_vulnerability_count: 0,
      actionable_severity_counts: { critical: 1, high: 0, medium: 0, low: 0, unknown: 0 },
      highest_actionable_severity: 'CRITICAL', cvss: { max_score: 10, vector: null, version: null, scored_vulnerability_count: 1 },
      vex_only_context_count: 0,
    },
    lifecycle: { bucket: 'EOL', status: 'EOL', effective_date: '2025-01-01', source: 'endoflife.date', manual_override: false },
    freshness: { latest_analysis_at: '2026-10-01T00:00:00Z', analysed_occurrences: 2, total_occurrences: 2, lifecycle_checked_at: '2026-09-30T00:00:00Z', lifecycle_is_stale: false },
    evidence: [{ sbom_id: 1, analysis_run_id: 9 }],
    recommendation: { status: 'NOT_EVALUATED' },
    ...overrides,
  };
}

function list(items: AdvisorComponent[], meta = META): AdvisorComponentList {
  return { total: items.length, limit: 50, offset: 0, sort_by: 'risk', sort_order: 'desc', items, meta };
}

/**
 * Pages that unwrap ``params`` with React 19 ``use()`` suspend on first mount;
 * rendering inside an awaited ``act`` lets that suspension resolve.
 */
async function renderPage(node: ReactNode): Promise<RenderResult> {
  const client = new QueryClient({ defaultOptions: { queries: { retry: false } } });
  let result: RenderResult | undefined;
  await act(async () => {
    result = render(
      <QueryClientProvider client={client}>
        <ToastProvider><Suspense fallback={<p>suspended</p>}>{node}</Suspense></ToastProvider>
      </QueryClientProvider>,
    );
  });
  return result!;
}

beforeEach(() => {
  Object.values(api).forEach((fn) => typeof fn === 'function' && 'mockReset' in fn && (fn as ReturnType<typeof vi.fn>).mockReset());
  navigation.replace.mockReset();
  navigation.push.mockReset();
  navigation.search = '';
  permissions.granted = new Set(['component_advisor:read', 'component_advisor:recommendation:create']);
  api.getAdvisorSummary.mockResolvedValue(summary());
  api.listAdvisorComponents.mockResolvedValue(list([component()]));
});

describe('Secure Component Advisor dashboard', () => {
  it('T35 loads the tenant-default dashboard and filters by risk (FR-SCA-002/007)', async () => {
    await renderPage(<ComponentAdvisorPage />);
    expect(await screen.findByText('log4j-core')).toBeInTheDocument();
    expect(screen.getByTestId('applied-filters')).toHaveTextContent('Scope: tenant');
    expect(api.listAdvisorComponents.mock.calls[0][0]).toMatchObject({ project_id: null, product_id: null, sbom_id: null });

    fireEvent.click(screen.getByRole('button', { name: 'Critical' }));
    await waitFor(() => expect(api.listAdvisorComponents).toHaveBeenLastCalledWith(
      expect.objectContaining({ risk: ['CRITICAL'] }), expect.anything()));
    expect(api.getAdvisorSummary).toHaveBeenLastCalledWith(expect.objectContaining({ risk: ['CRITICAL'] }), expect.anything());

    fireEvent.click(screen.getByRole('button', { name: 'pick-project-7' }));
    await waitFor(() => expect(api.listAdvisorComponents).toHaveBeenLastCalledWith(
      expect.objectContaining({ project_id: 7 }), expect.anything()));
  });

  it('T36 the No Known Actionable Vulnerabilities card drills down with its own filter (FR-SCA-003)', async () => {
    await renderPage(<ComponentAdvisorPage />);
    const card = await screen.findByRole('button', { name: /No Known Actionable Vulnerabilities: 2/ });
    fireEvent.click(card);
    await waitFor(() => expect(api.listAdvisorComponents).toHaveBeenLastCalledWith(
      expect.objectContaining({ risk: ['NO_KNOWN_ACTIONABLE_VULNERABILITIES'] }), expect.anything()));
    // Focus moves to the results heading after a filter change (WCAG 2.2).
    await waitFor(() => expect(screen.getByRole('heading', { name: 'Components' })).toHaveFocus());
  });

  it('T37 Accepted Risk card follows policy configuration (FR-SCA-004)', async () => {
    await renderPage(<ComponentAdvisorPage />);
    expect(await screen.findByRole('button', { name: /Components Within Accepted Risk: policy not configured/ })).toBeInTheDocument();
    // Trusted renders only when a trust policy is configured (FR-SCA-005).
    expect(screen.queryByText('Trusted-by-Policy Components')).not.toBeInTheDocument();
  });

  it('T37 configured accepted-risk policy shows the count and filters ACCEPTED_RISK', async () => {
    const configured = summary();
    configured.kpis[2] = { ...configured.kpis[2], value: 3, status: 'OK' };
    api.getAdvisorSummary.mockResolvedValue(configured);
    await renderPage(<ComponentAdvisorPage />);
    fireEvent.click(await screen.findByRole('button', { name: /Components Within Accepted Risk: 3/ }));
    await waitFor(() => expect(api.listAdvisorComponents).toHaveBeenLastCalledWith(
      expect.objectContaining({ risk: ['ACCEPTED_RISK'] }), expect.anything()));
  });

  it('T38 purpose search sends the facet and explains missing purpose evidence (FR-SCA-008/009)', async () => {
    await renderPage(<ComponentAdvisorPage />);
    await screen.findByText('log4j-core');
    api.listAdvisorComponents.mockResolvedValue(list([]));
    fireEvent.change(screen.getByLabelText('Search in'), { target: { value: 'purpose' } });
    await userEvent.type(screen.getByLabelText('Search components'), 'logging');
    await waitFor(() => expect(api.listAdvisorComponents).toHaveBeenLastCalledWith(
      expect.objectContaining({ q: 'logging', facet: 'purpose' }), expect.anything()));
    expect(await screen.findByText('Insufficient purpose evidence')).toBeInTheDocument();
  });

  it('shows the table column groups and an unsupported Informational filter (FR-SCA-001, D-4)', async () => {
    await renderPage(<ComponentAdvisorPage />);
    await screen.findByText('log4j-core');
    for (const group of ['Identity', 'Risk', 'Usage', 'Lifecycle', 'Decision support']) {
      expect(screen.getAllByRole('columnheader', { name: group }).length).toBeGreaterThan(0);
    }
    expect(screen.getByRole('button', { name: 'Informational (not supported)' })).toBeDisabled();
    expect(screen.getByLabelText('Risk: Critical')).toBeInTheDocument();
  });

  it('T42 a foreign or unknown scope shows the unauthorized-scope state (FR-SCA-023)', async () => {
    api.getAdvisorSummary.mockRejectedValue(new TestApiError(404));
    api.listAdvisorComponents.mockRejectedValue(new TestApiError(404));
    await renderPage(<ComponentAdvisorPage />);
    expect(await screen.findByText('Scope not available')).toBeInTheDocument();
    expect(screen.queryByText('log4j-core')).not.toBeInTheDocument();
  });

  it('refuses without component_advisor:read and never calls the API (NFR-SCA-001)', async () => {
    permissions.granted = new Set();
    await renderPage(<ComponentAdvisorPage />);
    expect(await screen.findByText(/do not have permission/)).toBeInTheDocument();
    expect(api.getAdvisorSummary).not.toHaveBeenCalled();
  });

  it('T43 dashboard has zero axe violations (NFR-SCA-008)', async () => {
    const { container } = await renderPage(<ComponentAdvisorPage />);
    await screen.findByText('log4j-core');
    const results = await axe(container, { rules: { 'heading-order': { enabled: false } } });
    expect(results.violations).toEqual([]);
  }, 15_000);
});

function detail(overrides: Partial<AdvisorComponentDetail> = {}): AdvisorComponentDetail {
  return {
    ...component({
      purpose: {
        status: 'AVAILABLE', ai_assisted: true,
        functional_description: { value: 'Logging library', source: 'SBOM', confidence: 'HIGH', ai_assisted: false, provenance: {} },
        primary_use_case: null,
        technology_category: { value: 'logging', source: 'AI', confidence: 'MEDIUM', ai_assisted: true, provenance: { model: 'm' } },
      },
    }),
    eligible_triggers: ['CRITICAL_FINDING', 'EOL', 'MANUAL'],
    adoption: {
      interpretation: 'CONTEXTUAL_EVIDENCE_NOT_PROOF', active_sbom_occurrences: 2,
      projects: [{ id: 1, name: 'Platform' }], products: [{ id: 2, name: 'Checkout' }],
      observed_versions: [
        { canonical_key: 'k-log4j', version: '2.14.1', classification: 'CRITICAL', lifecycle_bucket: 'EOL', licenses: ['Apache-2.0'], active_sbom_occurrences: 2, product_count: 2, latest_analysis_at: null, is_this_version: true },
        { canonical_key: 'k-log4j-2171', version: '2.17.1', classification: 'NO_KNOWN_ACTIONABLE_VULNERABILITIES', lifecycle_bucket: 'SUPPORTED', licenses: ['Apache-2.0'], active_sbom_occurrences: 1, product_count: 1, latest_analysis_at: null, is_this_version: false },
      ],
      latest_evidence_at: null,
    },
    meta: META,
    ...overrides,
  };
}

describe('Component detail', () => {
  it('T39 shows adoption, lifecycle, freshness and AI-provenanced purpose (FR-SCA-009/010)', async () => {
    api.getAdvisorComponent.mockResolvedValue(detail());
    await renderPage(<ComponentDetailPage params={Promise.resolve({ key: 'k-log4j' })} />);
    expect(await screen.findByText('Adoption in this tenant')).toBeInTheDocument();
    expect(screen.getByText(/Products: Checkout/)).toBeInTheDocument();
    expect(screen.getByText('2.17.1')).toBeInTheDocument();
    expect(screen.getByText(/contextual evidence only/)).toBeInTheDocument();
    expect(screen.getAllByLabelText('Lifecycle: End of life').length).toBeGreaterThan(0);
    expect(screen.getByText(/Latest analysis:/)).toBeInTheDocument();
    expect(screen.getByLabelText(/AI-assisted metadata, medium confidence; not authoritative/)).toBeInTheDocument();
    expect(screen.getByLabelText('Source: From SBOM')).toBeInTheDocument();
  });

  it('Find safer options creates a recommendation with an evidenced trigger and opens it (FR-SCA-011)', async () => {
    api.getAdvisorComponent.mockResolvedValue(detail());
    api.createAdvisorRecommendation.mockResolvedValue({ id: 41, created: true });
    await renderPage(<ComponentDetailPage params={Promise.resolve({ key: 'k-log4j' })} />);
    fireEvent.click(await screen.findByRole('button', { name: 'Find safer options' }));
    await waitFor(() => expect(api.createAdvisorRecommendation).toHaveBeenCalledWith(
      { canonical_key: 'k-log4j', trigger_type: 'CRITICAL_FINDING' }, expect.anything()));
    await waitFor(() => expect(navigation.push).toHaveBeenCalledWith('/component-advisor/recommendations/41'));
  });

  it('an open recommendation is linked instead of offering a duplicate', async () => {
    api.getAdvisorComponent.mockResolvedValue(detail({ recommendation: { status: 'REVIEW_REQUIRED', id: 9, trigger_type: 'CRITICAL_FINDING' } }));
    await renderPage(<ComponentDetailPage params={Promise.resolve({ key: 'k-log4j' })} />);
    expect(await screen.findByText('Recommendation already open')).toBeInTheDocument();
    expect(screen.getByRole('link', { name: /Open recommendation #9/ })).toHaveAttribute('href', '/component-advisor/recommendations/9');
    expect(screen.queryByRole('button', { name: 'Find safer options' })).not.toBeInTheDocument();
  });

  it('hides Find safer options without the create permission (spec §9)', async () => {
    permissions.granted = new Set(['component_advisor:read']);
    api.getAdvisorComponent.mockResolvedValue(detail());
    await renderPage(<ComponentDetailPage params={Promise.resolve({ key: 'k-log4j' })} />);
    await screen.findByText('Adoption in this tenant');
    expect(screen.queryByRole('button', { name: 'Find safer options' })).not.toBeInTheDocument();
  });

  it('T42 another tenant\'s component key shows the unauthorized-scope state', async () => {
    api.getAdvisorComponent.mockRejectedValue(new TestApiError(404));
    await renderPage(<ComponentDetailPage params={Promise.resolve({ key: 'foreign' })} />);
    expect(await screen.findByText('Scope not available')).toBeInTheDocument();
  });
});

function recommendation(overrides: Partial<AdvisorRecommendation> = {}): AdvisorRecommendation {
  return {
    id: 41, status: 'REVIEW_REQUIRED', trigger_type: 'CRITICAL_FINDING', trigger_evidence: {},
    source: { canonical_key: 'k-log4j', family_key: 'maven:log4j-core', name: 'log4j-core', version: '2.14.1', ecosystem: 'maven', component_id: 1 },
    context: { project_id: null, product_id: null, sbom_id: null, level: 'TENANT' },
    discovery: {
      status: 'CANDIDATES_FOUND', alternatives_status: 'INSUFFICIENT_PURPOSE_EVIDENCE',
      source_posture: { classification: 'CRITICAL', highest_actionable_severity: 'CRITICAL', lifecycle_bucket: 'EOL', actionable_vulnerability_ids: ['CVE-2021-44228'] },
    },
    evaluation_error: null, correlation_id: 'c', created_by: 'a', created_at: null, updated_at: null, evaluated_at: null,
    row_version: 3,
    review: { recommended_candidate_id: null, accepted_candidate_id: null, last_decision: null, last_decision_reason: null, decided_by: null, decided_at: null },
    advisory_only: true,
    candidates: [
      {
        id: 7, candidate_kind: 'SAME_FAMILY_VERSION', source_type: 'TENANT_OBSERVED', canonical_key: 'k-2171', name: 'log4j-core', version: '2.17.1',
        purl: null, ecosystem: 'maven', rank: 1, evidence_sources: ['TENANT_OBSERVED'],
        reasons: [{ code: 'SAME_ECOSYSTEM' }], limitations: [{ code: 'MIGRATION_REGRESSION_TESTING_REQUIRED' }],
        evaluation: { current_posture: { status: 'OBSERVED', classification: 'NO_KNOWN_ACTIONABLE_VULNERABILITIES' }, lifecycle: { bucket: 'SUPPORTED' }, adoption: { active_sbom_occurrences: 1, product_count: 1 }, license: { source: ['Apache-2.0'], candidate: ['Apache-2.0'], changed: false } },
        score: 81.5, confidence: 'MEDIUM',
        explanation: { summary: 'log4j-core 2.17.1 is proposed because it:', reasons: ['Uses the same package ecosystem as the current component.'], limitations: ['Regression testing is required before any change.'], confidence: 'Confidence is medium' },
        history: null, freshness: null, blocked: false,
        compatibility: { status: 'REVIEW_REQUIRED', counts: { PASS: 8, FAIL: 0, REVIEW_REQUIRED: 2, UNKNOWN: 4 }, blocking_checks: [], blocked: false },
        approved_replacement: false, recommended: false,
      },
      {
        id: 8, candidate_kind: 'SAME_FAMILY_VERSION', source_type: 'TENANT_OBSERVED', canonical_key: 'k-2160', name: 'log4j-core', version: '2.16.0',
        purl: null, ecosystem: 'maven', rank: 2, evidence_sources: ['TENANT_OBSERVED'], reasons: [], limitations: [],
        evaluation: { current_posture: { status: 'OBSERVED', classification: 'HIGH' } },
        score: 50, confidence: 'LOW', explanation: null, history: null, freshness: null, blocked: true,
        compatibility: { status: 'BLOCKED', counts: { PASS: 10, FAIL: 1, REVIEW_REQUIRED: 1, UNKNOWN: 2 }, blocking_checks: ['LICENSE'], blocked: true },
        approved_replacement: false, recommended: false,
      },
    ],
    capabilities: {
      can_evaluate: true, can_recommend: true, can_accept: false, can_reject: true, can_defer: true, can_request_evidence: true,
      can_close: false, can_add_candidate: true, can_view_audit: true, can_decide: true, read_only_reason: null,
    },
    ...overrides,
  };
}

describe('Recommendation view', () => {
  it('T40 shows reasons, limitations, confidence and evidence (FR-SCA-018/019)', async () => {
    api.getAdvisorRecommendation.mockResolvedValue(recommendation());
    api.getAdvisorCandidateEvidence.mockResolvedValue({
      candidate_id: 7, name: 'log4j-core', version: '2.17.1', score: 81.5, score_semantics: 'ORDERS_CANDIDATES_ONLY', confidence: 'MEDIUM',
      confidence_basis: { level: 'MEDIUM', completeness: 0.77, unknown_material_checks: ['LICENSE'], stale_flags: [], reasons: [], drop_in_representable: false },
      scoring_policy: { policy_version_id: null, label: 'builtin-default-2026-10-01' },
      factors: [{ factor: 'current_risk', raw_value: 'NO_KNOWN_ACTIONABLE_VULNERABILITIES', normalized_value: 1, weight: 0.3, contribution: 0.3, missing_data_treatment: null, evidence_source: 'TENANT_ANALYSIS', evidence_at: null, policy_version_label: 'builtin-default-2026-10-01' }],
      reasons: [], limitations: [], history: null, freshness: null, compatibility: null, explanation: null, blocked: false, approved_replacement: false,
    });
    api.getAdvisorCandidateCompatibility.mockResolvedValue({ candidate_id: 7, summary: { status: 'REVIEW_REQUIRED' }, items: [
      { id: 1, check_type: 'LICENSE', result: 'UNKNOWN', blocking: false, reason: 'Candidate license unknown', limitation: 'LICENSE_EVIDENCE_UNAVAILABLE', evidence: {}, evaluated_at: null },
    ] });
    await renderPage(<RecommendationPage params={Promise.resolve({ id: '41' })} />);
    expect(await screen.findByText('Uses the same package ecosystem as the current component.')).toBeInTheDocument();
    expect(screen.getByText('Regression testing is required before any change.')).toBeInTheDocument();
    expect(screen.getAllByLabelText('Confidence: Medium confidence').length).toBeGreaterThan(0);
    expect(screen.getAllByText(/orders candidates only/).length).toBe(2);  // on every candidate
    expect(screen.getByText('Insufficient compatibility evidence')).toBeInTheDocument();
    expect(screen.getByText(/Blocked by a compatibility check/)).toBeInTheDocument();

    fireEvent.click(screen.getByRole('button', { name: 'View evidence for log4j-core 2.17.1' }));
    const dialog = await screen.findByRole('dialog');
    expect(await within(dialog).findByText('Current risk')).toBeInTheDocument();
    expect(await within(dialog).findByText('Candidate license unknown')).toBeInTheDocument();
    expect(within(dialog).getByText(/Scoring policy builtin-default-2026-10-01/)).toBeInTheDocument();
  });

  it('T41 decision actions follow backend capabilities (FR-SCA-021)', async () => {
    api.getAdvisorRecommendation.mockResolvedValue(recommendation());
    await renderPage(<RecommendationPage params={Promise.resolve({ id: '41' })} />);
    await screen.findByText('Safer versions of the same component');
    const actions = screen.getByRole('group', { name: 'Recommendation decisions' });
    expect(within(actions).queryByRole('button', { name: 'Accept' })).not.toBeInTheDocument();
    expect(within(actions).getByRole('button', { name: 'Reject' })).toBeInTheDocument();
    // A blocked candidate never offers Recommend.
    expect(screen.getByRole('button', { name: 'Recommend log4j-core 2.17.1' })).toBeInTheDocument();
    expect(screen.queryByRole('button', { name: 'Recommend log4j-core 2.16.0' })).not.toBeInTheDocument();
  });

  it('T41 read-only users see no decision controls', async () => {
    const readOnly = recommendation();
    readOnly.capabilities = { ...readOnly.capabilities!, can_recommend: false, can_reject: false, can_defer: false, can_request_evidence: false, can_decide: false, read_only_reason: 'Your role cannot act on this recommendation in its current state' };
    api.getAdvisorRecommendation.mockResolvedValue(readOnly);
    await renderPage(<RecommendationPage params={Promise.resolve({ id: '41' })} />);
    expect(await screen.findByText(/Your role cannot act/)).toBeInTheDocument();
    expect(screen.queryByRole('button', { name: /^Recommend / })).not.toBeInTheDocument();
  });

  it('a decision requires a reason and sends the row version (FR-SCA-021)', async () => {
    api.getAdvisorRecommendation.mockResolvedValue(recommendation());
    api.decideAdvisorRecommendation.mockResolvedValue(recommendation({ status: 'RECOMMENDED' }));
    await renderPage(<RecommendationPage params={Promise.resolve({ id: '41' })} />);
    fireEvent.click(await screen.findByRole('button', { name: 'Recommend log4j-core 2.17.1' }));
    const dialog = await screen.findByRole('dialog');
    const confirm = within(dialog).getByRole('button', { name: 'Confirm' });
    expect(confirm).toBeDisabled();
    await userEvent.type(within(dialog).getByRole('textbox'), 'lowest current risk');
    fireEvent.click(confirm);
    await waitFor(() => expect(api.decideAdvisorRecommendation).toHaveBeenCalledWith(41, {
      decision: 'RECOMMEND', reason: 'lowest current risk', row_version: 3, candidate_id: 7,
    }));
  });

  it('T43 recommendation view has zero axe violations (NFR-SCA-008)', async () => {
    api.getAdvisorRecommendation.mockResolvedValue(recommendation());
    const { container } = await renderPage(<RecommendationPage params={Promise.resolve({ id: '41' })} />);
    await screen.findByText('Safer versions of the same component');
    const results = await axe(container, { rules: { 'heading-order': { enabled: false } } });
    expect(results.violations).toEqual([]);
  }, 15_000);
});

describe('States and vocabulary', () => {
  it.each(ADVISOR_NOTICE_KINDS)('T43 %s is an explicit, announced state', async (kind) => {
    await renderPage(<AdvisorNotice kind={kind} />);
    // role="status" is an implicit polite live region; errors use role="alert".
    const region = screen.getByRole(kind === 'UNAUTHORIZED_SCOPE' ? 'alert' : 'status');
    expect(region.textContent?.length).toBeGreaterThan(20);
  });

  it('covers every degraded state the spec lists', () => {
    expect(ADVISOR_NOTICE_KINDS).toHaveLength(11);
  });

  it('never claims safety in user-facing labels (spec §1.2)', () => {
    const maps = [labels.RISK_LABELS, labels.LIFECYCLE_LABELS, labels.CONFIDENCE_LABELS, labels.CHECK_LABELS,
      labels.TRIGGER_LABELS, labels.STATUS_LABELS, labels.DECISION_LABELS, labels.FACET_LABELS];
    for (const map of maps) {
      for (const text of Object.values(map) as string[]) {
        expect(text.toLowerCase()).not.toMatch(/\bsafe\b|\bsecure\b|vulnerability free|safety score/);
      }
    }
  });
});

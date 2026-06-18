// @vitest-environment jsdom

import { QueryClient, QueryClientProvider } from '@tanstack/react-query';
import { fireEvent, render, screen, waitFor } from '@testing-library/react';
import type { ReactNode } from 'react';
import { beforeEach, describe, expect, it, vi } from 'vitest';

const back = vi.fn();
const push = vi.fn();
vi.mock('next/navigation', () => ({
  useRouter: () => ({ back, push, replace: vi.fn() }),
}));

vi.mock('@/hooks/useAnalysisStream', () => ({
  useAnalysisStream: () => ({
    state: { phase: 'idle' },
    startAnalysis: vi.fn(),
    cancel: vi.fn(),
    reset: vi.fn(),
  }),
}));

vi.mock('@/components/schedules/ScheduleCard', () => ({
  ScheduleCard: () => null,
}));

vi.mock('@/components/sboms/ValidationReportSection', () => ({
  ValidationReportSection: () => null,
}));

const showToast = vi.fn();
vi.mock('@/hooks/useToast', () => ({
  useToast: () => ({ showToast, updateToast: vi.fn() }),
}));

const getSbomComponents = vi.fn();
const getRuns = vi.fn();
const getSbomInfo = vi.fn();
const getSbomRiskSummary = vi.fn();
const getSbomValidationReport = vi.fn();
const editSbom = vi.fn();
const getSbomVersions = vi.fn();
const compareSbomVersions = vi.fn();
const restoreSbomVersion = vi.fn();
const refreshSbomLifecycle = vi.fn();
const refreshComponentLifecycle = vi.fn();
const discoverSbomVexDocuments = vi.fn();
const exportSbomLifecycleReportCsv = vi.fn();
const exportSbomLifecycleReportPack = vi.fn();
const exportSbomVexReportCsv = vi.fn();
const exportSbomVexReportJson = vi.fn();
const exportSbomVexReportPack = vi.fn();
const getVexOverrideHistory = vi.fn();
const getSbomVexStatements = vi.fn();
const overrideVexStatement = vi.fn();
const uploadSbomVexDocument = vi.fn();
const overrideComponentLifecycle = vi.fn();

vi.mock('@/lib/api', async () => {
  const actual = await vi.importActual<typeof import('@/lib/api')>('@/lib/api');
  return {
    ...actual,
    BASE_URL: 'http://test.local',
    getSbomComponents: (...args: unknown[]) => getSbomComponents(...args),
    getRuns: (...args: unknown[]) => getRuns(...args),
    getSbomInfo: (...args: unknown[]) => getSbomInfo(...args),
    getSbomRiskSummary: (...args: unknown[]) => getSbomRiskSummary(...args),
    getSbomValidationReport: (...args: unknown[]) => getSbomValidationReport(...args),
    editSbom: (...args: unknown[]) => editSbom(...args),
    getSbomVersions: (...args: unknown[]) => getSbomVersions(...args),
    compareSbomVersions: (...args: unknown[]) => compareSbomVersions(...args),
    restoreSbomVersion: (...args: unknown[]) => restoreSbomVersion(...args),
    refreshSbomLifecycle: (...args: unknown[]) => refreshSbomLifecycle(...args),
    refreshComponentLifecycle: (...args: unknown[]) => refreshComponentLifecycle(...args),
    discoverSbomVexDocuments: (...args: unknown[]) => discoverSbomVexDocuments(...args),
    exportSbomLifecycleReportCsv: (...args: unknown[]) => exportSbomLifecycleReportCsv(...args),
    exportSbomLifecycleReportPack: (...args: unknown[]) => exportSbomLifecycleReportPack(...args),
    exportSbomVexReportCsv: (...args: unknown[]) => exportSbomVexReportCsv(...args),
    exportSbomVexReportJson: (...args: unknown[]) => exportSbomVexReportJson(...args),
    exportSbomVexReportPack: (...args: unknown[]) => exportSbomVexReportPack(...args),
    getVexOverrideHistory: (...args: unknown[]) => getVexOverrideHistory(...args),
    getSbomVexStatements: (...args: unknown[]) => getSbomVexStatements(...args),
    overrideVexStatement: (...args: unknown[]) => overrideVexStatement(...args),
    uploadSbomVexDocument: (...args: unknown[]) => uploadSbomVexDocument(...args),
    overrideComponentLifecycle: (...args: unknown[]) => overrideComponentLifecycle(...args),
  };
});

import { SbomDetail } from '@/components/sboms/SbomDetail';
import type { SBOMComponent, SBOMSource } from '@/types';

const SBOM: SBOMSource = {
  id: 42,
  sbom_name: 'demo-sbom',
  sbom_type: null,
  sbom_version: '1.0.0',
  projectid: null,
  created_by: 'alice',
  created_on: '2026-06-01T00:00:00Z',
  modified_by: null,
  modified_on: null,
  productver: null,
  status: 'validated',
};

const COMPONENT: SBOMComponent = {
  id: 99,
  sbom_id: 42,
  bom_ref: 'pkg:npm/demo@1.0.0',
  name: 'demo',
  version: '1.0.0',
  cpe: null,
  purl: 'pkg:npm/demo@1.0.0',
  component_type: 'library',
  component_group: null,
  supplier: 'Demo Org',
  scope: null,
  ecosystem: 'npm',
  license: 'MIT',
  hashes: 'abc123',
  lifecycle_status: 'EOL',
  eol_date: '2025-01-01',
  eos_date: '2024-06-01',
  eof_date: '2024-01-01',
  deprecated: false,
  is_deprecated: false,
  maintenance_status: 'End of life',
  recommended_version: '2.0.0',
  lifecycle_recommendation: 'Upgrade to supported version 2.0.0.',
  lifecycle_source: 'endoflife.date',
  lifecycle_source_url: 'https://endoflife.date/demo',
  lifecycle_confidence: 'High',
  lifecycle_checked_at: '2026-06-11T00:00:00Z',
  lifecycle_evidence_json: { cycle: '1' },
  lifecycle_is_stale: true,
  lifecycle_manual_override: true,
  created_on: null,
};

function wrap(children: ReactNode) {
  const client = new QueryClient({
    defaultOptions: { queries: { retry: false, gcTime: 0, staleTime: 0 } },
  });
  return <QueryClientProvider client={client}>{children}</QueryClientProvider>;
}

beforeEach(() => {
  window.localStorage.clear();
  Object.defineProperty(URL, 'createObjectURL', {
    configurable: true,
    value: vi.fn(() => 'blob:test-download'),
  });
  Object.defineProperty(URL, 'revokeObjectURL', {
    configurable: true,
    value: vi.fn(),
  });
  Object.defineProperty(HTMLAnchorElement.prototype, 'click', {
    configurable: true,
    value: vi.fn(),
  });
  back.mockReset();
  push.mockReset();
  discoverSbomVexDocuments.mockResolvedValue({
    sbom_id: 42,
    discovered_documents: 1,
    statements_imported: 2,
    matched_statements: 1,
    unmatched_statements: 1,
    errors: [],
  });
  exportSbomLifecycleReportCsv.mockResolvedValue({ blob: new Blob(['lifecycle']), filename: 'lifecycle.csv' });
  exportSbomLifecycleReportPack.mockResolvedValue({ blob: new Blob(['zip']), filename: 'lifecycle.zip' });
  exportSbomVexReportCsv.mockResolvedValue({ blob: new Blob(['vex']), filename: 'vex.csv' });
  exportSbomVexReportJson.mockResolvedValue({ blob: new Blob(['{}']), filename: 'vex.json' });
  exportSbomVexReportPack.mockResolvedValue({ blob: new Blob(['zip']), filename: 'vex.zip' });
  getVexOverrideHistory.mockResolvedValue({
    component_id: 99,
    vulnerability_id: 'CVE-2026-0001',
    history: [
      {
        id: 8,
        old_value: null,
        new_value: { status: 'affected' },
        reason: 'Prior risk review',
        evidence_url: 'https://vendor.example/evidence',
        changed_by: 'security@example.test',
        changed_at: '2026-06-10T00:00:00Z',
      },
    ],
  });
  overrideVexStatement.mockResolvedValue({
    id: 2,
    sbom_id: 42,
    component_id: 99,
    vulnerability_id: 'CVE-2026-0001',
    status: 'affected',
    created_at: '2026-06-12T00:00:00Z',
  });
  getSbomComponents.mockResolvedValue([COMPONENT]);
  getRuns.mockResolvedValue([]);
  getSbomInfo.mockResolvedValue(null);
  getSbomRiskSummary.mockResolvedValue(null);
  getSbomValidationReport.mockResolvedValue(null);
  getSbomVersions.mockResolvedValue([]);
  compareSbomVersions.mockResolvedValue({ added: [], removed: [], changed: [] });
  restoreSbomVersion.mockResolvedValue(SBOM);
  refreshSbomLifecycle.mockResolvedValue({ sbom_id: 42, components_enriched: 1, stale_components: 0 });
  refreshComponentLifecycle.mockResolvedValue(COMPONENT);
  getSbomVexStatements.mockResolvedValue({
    sbom_id: 42,
    statements: [
      {
        id: 1,
        sbom_id: 42,
        component_id: 99,
        component_name: 'demo',
        component_version: '1.0.0',
        vulnerability_id: 'CVE-2026-0001',
        status: 'not_affected',
        justification: 'vulnerable_code_not_present',
        impact_statement: 'Demo build does not load the vulnerable code path.',
        source_name: 'Uploaded VEX',
        source_url: 'https://vendor.example/vex.json',
        confidence: 'Medium',
        evidence_json: { mapping: 'matched', provider: 'CSAF VEX Discovery' },
        created_at: '2026-06-11T00:00:00Z',
      },
    ],
  });
  uploadSbomVexDocument.mockResolvedValue({
    document_id: 1,
    sbom_id: 42,
    statements_imported: 1,
    validation_status: 'accepted',
  });
  editSbom.mockResolvedValue({ ...SBOM, id: 43, parent_id: 42, sbom_version: '1.0.1' });
  overrideComponentLifecycle.mockResolvedValue(COMPONENT);
  showToast.mockReset();
});

describe('SbomDetail lifecycle management', () => {
  it('renders lifecycle details, refresh actions, and manual override form fields', async () => {
    render(wrap(<SbomDetail sbom={SBOM} />));

    expect(await screen.findByText('VEX Statements')).toBeInTheDocument();
    expect(await screen.findByText('CVE-2026-0001')).toBeInTheDocument();

    fireEvent.click(screen.getByRole('button', { name: /Components List/i }));

    expect(await screen.findByText('demo')).toBeInTheDocument();
    expect(screen.getByText('npm')).toBeInTheDocument();
    expect(screen.getByText('EOL')).toBeInTheDocument();
    expect(screen.getByText(/EOL 2025-01-01/)).toBeInTheDocument();
    expect(screen.getByText(/endoflife.date · High/)).toBeInTheDocument();
    expect(screen.getByText('Upgrade 2.0.0')).toBeInTheDocument();
    expect(screen.getByText('Stale data')).toBeInTheDocument();
    expect(screen.getByText('Manual override')).toBeInTheDocument();

    fireEvent.click(screen.getByRole('button', { name: /Refresh Lifecycle/i }));
    await waitFor(() => expect(refreshSbomLifecycle).toHaveBeenCalledWith(42, true));

    fireEvent.click(screen.getByRole('button', { name: /^Refresh$/i }));
    await waitFor(() => expect(refreshComponentLifecycle).toHaveBeenCalledWith(99, true));

    fireEvent.click(screen.getByRole('button', { name: /Edit/i }));
    expect(await screen.findByText('Lifecycle Management Parameters')).toBeInTheDocument();
    expect(screen.getByText('Lifecycle Status')).toBeInTheDocument();
    expect(screen.getByText('End of Fix (EOF)')).toBeInTheDocument();
    expect(screen.getByText('Recommended Version')).toBeInTheDocument();
    expect(screen.getByText('Evidence URL')).toBeInTheDocument();
    expect(screen.getByText('Override Reason')).toBeInTheDocument();
  }, 15000);

  it('opens the manual VEX override form and validates required evidence', async () => {
    render(wrap(<SbomDetail sbom={SBOM} />));

    expect(await screen.findByText('VEX Statements')).toBeInTheDocument();
    expect(await screen.findByText('CVE-2026-0001')).toBeInTheDocument();
    fireEvent.click(screen.getAllByRole('button', { name: /^Override$/i })[1]);

    expect(await screen.findByRole('dialog', { name: /Manual VEX Override/i })).toBeInTheDocument();
    expect(screen.getByLabelText('Component')).toHaveValue('99');
    expect(screen.getByLabelText('Vulnerability or CVE')).toHaveValue('CVE-2026-0001');
    fireEvent.click(screen.getByRole('button', { name: /Save Override/i }));
    expect(await screen.findByText('Override reason is required.')).toBeInTheDocument();

    fireEvent.change(screen.getByLabelText('VEX Status'), { target: { value: 'fixed' } });
    fireEvent.change(screen.getByLabelText('Evidence URL'), { target: { value: '' } });
    fireEvent.change(screen.getByLabelText('Reason for Override'), { target: { value: 'vendor advisory review' } });
    fireEvent.click(screen.getByRole('button', { name: /Save Override/i }));
    expect(await screen.findByText('fixed requires fixed version or evidence URL.')).toBeInTheDocument();
  }, 15000);

  it('submits a manual VEX override and shows audit history', async () => {
    render(wrap(<SbomDetail sbom={SBOM} />));

    expect(await screen.findByText('CVE-2026-0001')).toBeInTheDocument();
    fireEvent.click(screen.getAllByRole('button', { name: /^Override$/i })[1]);
    expect(await screen.findByText('Prior risk review')).toBeInTheDocument();
    fireEvent.change(screen.getByLabelText('VEX Status'), { target: { value: 'affected' } });
    fireEvent.change(screen.getByLabelText('Action Statement'), { target: { value: 'Upgrade immediately' } });
    fireEvent.change(screen.getByLabelText('Reason for Override'), { target: { value: 'confirmed reachable in deployment' } });
    fireEvent.click(screen.getByRole('button', { name: /Save Override/i }));

    await waitFor(() => {
      expect(overrideVexStatement).toHaveBeenCalledWith(
        99,
        'CVE-2026-0001',
        expect.objectContaining({
          status: 'affected',
          action_statement: 'Upgrade immediately',
          reason: 'confirmed reachable in deployment',
        }),
      );
    });
    expect(await screen.findByText(/Manual VEX override saved/i)).toBeInTheDocument();
  }, 15000);

  it('shows VEX and lifecycle evidence modals', async () => {
    render(wrap(<SbomDetail sbom={SBOM} />));

    expect(await screen.findByText('CVE-2026-0001')).toBeInTheDocument();
    fireEvent.click(screen.getByRole('button', { name: /Evidence/i }));
    expect(await screen.findByRole('dialog', { name: /VEX Evidence/i })).toBeInTheDocument();
    expect(screen.getAllByText((_, node) => Boolean(node?.textContent?.includes('CSAF VEX Discovery'))).length).toBeGreaterThan(0);
    expect(screen.getByText('Raw Evidence Summary')).toBeInTheDocument();
    fireEvent.click(screen.getByRole('button', { name: /Close dialog/i }));

    fireEvent.click(screen.getByRole('button', { name: /Components List/i }));
    expect(await screen.findByText('demo')).toBeInTheDocument();
    fireEvent.click(screen.getByRole('button', { name: /^Evidence$/i }));
    expect(await screen.findByRole('dialog', { name: /Lifecycle Evidence/i })).toBeInTheDocument();
    expect(screen.getAllByText('endoflife.date').length).toBeGreaterThan(0);
    expect(screen.getAllByText(/No raw evidence stored|cycle/i).length).toBeGreaterThan(0);
  }, 15000);

  it('downloads VEX and lifecycle CSV reports', async () => {
    render(wrap(<SbomDetail sbom={SBOM} />));

    expect(await screen.findByText('VEX Statements')).toBeInTheDocument();
    fireEvent.click(screen.getByRole('button', { name: /^CSV$/i }));
    await waitFor(() => expect(exportSbomVexReportCsv).toHaveBeenCalledWith(42));
    expect(await screen.findByText('Downloaded vex.csv.')).toBeInTheDocument();

    fireEvent.click(screen.getByRole('button', { name: /Components List/i }));
    fireEvent.click(await screen.findByRole('button', { name: /Lifecycle CSV/i }));
    await waitFor(() => expect(exportSbomLifecycleReportCsv).toHaveBeenCalledWith(42));
    expect(await screen.findByText('Downloaded lifecycle.csv.')).toBeInTheDocument();
  }, 15000);

  it('runs VEX discovery refresh and renders stale lifecycle warning', async () => {
    render(wrap(<SbomDetail sbom={SBOM} />));

    expect(await screen.findByText('VEX Statements')).toBeInTheDocument();
    fireEvent.click(screen.getByRole('button', { name: /Discover/i }));
    await waitFor(() => expect(discoverSbomVexDocuments).toHaveBeenCalledWith(42, true));
    expect(await screen.findByText(/Discovery imported 2 statements/i)).toBeInTheDocument();

    fireEvent.click(screen.getByRole('button', { name: /Components List/i }));
    expect(await screen.findByText(/1 lifecycle evidence record is stale/i)).toBeInTheDocument();
  }, 15000);

  it('hides sensitive VEX controls for viewer role', async () => {
    window.localStorage.setItem('sbom-role', 'viewer');
    render(wrap(<SbomDetail sbom={SBOM} />));

    expect(await screen.findByText('VEX Statements')).toBeInTheDocument();
    expect(screen.queryByRole('button', { name: /^Override$/i })).not.toBeInTheDocument();
    expect(screen.queryByRole('button', { name: /Discover/i })).not.toBeInTheDocument();
  }, 15000);

  describe('manual lifecycle override saving', () => {
    it('submits manual lifecycle override successfully with correct payload and closes modal', async () => {
      const invalidateSpy = vi.spyOn(QueryClient.prototype, 'invalidateQueries');
      render(wrap(<SbomDetail sbom={SBOM} />));

      fireEvent.click(screen.getByRole('button', { name: /Components List/i }));
      expect(await screen.findByText('demo')).toBeInTheDocument();

      fireEvent.click(screen.getByRole('button', { name: /Edit/i }));
      expect(await screen.findByText('Lifecycle Management Parameters')).toBeInTheDocument();

      // Change input fields
      fireEvent.change(screen.getByLabelText('Lifecycle Status'), { target: { value: 'EOL' } });
      fireEvent.change(screen.getByLabelText('Maintenance Status'), { target: { value: 'Unmaintained' } });
      fireEvent.change(screen.getByLabelText('EOS Date'), { target: { value: '2026-06-30' } });
      fireEvent.change(screen.getByLabelText('EOL Date'), { target: { value: '2026-12-31' } });
      fireEvent.change(screen.getByLabelText('EOF Date'), { target: { value: '2026-06-30' } });
      fireEvent.change(screen.getByLabelText('Recommended Version'), { target: { value: '2.1.0' } });
      fireEvent.change(screen.getByLabelText('Evidence URL'), { target: { value: 'https://example.com/evidence' } });
      fireEvent.change(screen.getByLabelText('Override Reason'), { target: { value: 'Manual override reason' } });

      const deprecateCheckbox = screen.getByLabelText('Mark component as Deprecated') as HTMLInputElement;
      if (!deprecateCheckbox.checked) {
        fireEvent.click(deprecateCheckbox);
      }

      fireEvent.click(screen.getByRole('button', { name: /Save Override/i }));

      await waitFor(() => {
        expect(overrideComponentLifecycle).toHaveBeenCalledWith(
          99,
          expect.objectContaining({
            lifecycle_status: 'EOL',
            eos_date: '2026-06-30',
            eol_date: '2026-12-31',
            eof_date: '2026-06-30',
            deprecated: true,
            is_deprecated: true,
            maintenance_status: 'Unmaintained',
            recommended_version: '2.1.0',
            evidence_url: 'https://example.com/evidence',
            reason: 'Manual override reason',
            updated_by: 'alice',
          })
        );
      });

      // Assert modal closes
      await waitFor(() => {
        expect(screen.queryByText('Lifecycle Management Parameters')).not.toBeInTheDocument();
      });

      // Assert success toast is shown
      expect(showToast).toHaveBeenCalledWith('Manual override saved successfully.', 'success');

      // Assert query invalidate queries called
      await waitFor(() => {
        expect(invalidateSpy).toHaveBeenCalledWith(expect.objectContaining({ queryKey: ['sbom-components', 42] }));
        expect(invalidateSpy).toHaveBeenCalledWith(expect.objectContaining({ queryKey: ['dashboard-lifecycle'] }));
        expect(invalidateSpy).toHaveBeenCalledWith(expect.objectContaining({ queryKey: ['dashboard-health'] }));
      });

      invalidateSpy.mockRestore();
    }, 15000);

    it('handles errors and timeouts correctly', async () => {
      render(wrap(<SbomDetail sbom={SBOM} />));

      fireEvent.click(screen.getByRole('button', { name: /Components List/i }));
      expect(await screen.findByText('demo')).toBeInTheDocument();

      // Case 1: Timeout error
      fireEvent.click(screen.getByRole('button', { name: /Edit/i }));
      const timeoutError = new Error('Request timed out after 2000ms');
      timeoutError.name = 'AbortError';
      overrideComponentLifecycle.mockRejectedValueOnce(timeoutError);

      fireEvent.change(screen.getByLabelText('Override Reason'), { target: { value: 'Reason' } });
      fireEvent.click(screen.getByRole('button', { name: /Save Override/i }));
      expect(await screen.findByText('Save took too long. Please check backend logs.')).toBeInTheDocument();
      fireEvent.click(screen.getByRole('button', { name: /Cancel/i }));

      // Case 2: Validation error (422)
      fireEvent.click(screen.getByRole('button', { name: /Edit/i }));
      const valError = { status: 422, message: 'Invalid eol_date format' };
      overrideComponentLifecycle.mockRejectedValueOnce(valError);
      fireEvent.click(screen.getByRole('button', { name: /Save Override/i }));
      expect(await screen.findByText('Validation Error: Invalid eol_date format')).toBeInTheDocument();
      fireEvent.click(screen.getByRole('button', { name: /Cancel/i }));

      // Case 3: Component Not Found error (404)
      fireEvent.click(screen.getByRole('button', { name: /Edit/i }));
      const notFoundError = { status: 404, message: 'Not Found' };
      overrideComponentLifecycle.mockRejectedValueOnce(notFoundError);
      fireEvent.click(screen.getByRole('button', { name: /Save Override/i }));
      expect(await screen.findByText('Component not found. It may have been removed or renamed.')).toBeInTheDocument();
      fireEvent.click(screen.getByRole('button', { name: /Cancel/i }));

      // Case 4: Backend error (500)
      fireEvent.click(screen.getByRole('button', { name: /Edit/i }));
      const serverError = { status: 500, message: 'Internal Server Error' };
      overrideComponentLifecycle.mockRejectedValueOnce(serverError);
      fireEvent.click(screen.getByRole('button', { name: /Save Override/i }));
      expect(await screen.findByText('Backend Error: Internal Server Error')).toBeInTheDocument();
      fireEvent.click(screen.getByRole('button', { name: /Cancel/i }));
    }, 15000);
  });
});

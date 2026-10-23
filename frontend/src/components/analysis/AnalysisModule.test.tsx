// @vitest-environment jsdom
import { useState, type ReactNode } from 'react';
import { QueryClient, QueryClientProvider } from '@tanstack/react-query';
import { fireEvent, render, screen, waitFor } from '@testing-library/react';
import { beforeEach, describe, expect, it, vi } from 'vitest';
import { AnalysisRunsHistory } from './AnalysisRunsHistory';
import { ConsolidatedAnalysisPanel } from './ConsolidatedAnalysisPanel';
import { LiveAnalysisCard } from './LiveAnalysisCard';
import { SelectedSbomContext } from './SelectedSbomContext';
import type { AnalysisRun, SBOMSource } from '@/types';
import * as api from '@/lib/api';

const mocks = vi.hoisted(() => ({ start: vi.fn(), push: vi.fn(), toast: vi.fn() }));
vi.mock('next/navigation', () => ({ useRouter: () => ({ push: mocks.push }) }));
vi.mock('@/hooks/useAuth', () => ({ useAuth: () => ({ activeTenantId: 'tenant-a', activeTenant: { name: 'Example tenant' } }) }));
vi.mock('@/hooks/useToast', () => ({ useToast: () => ({ showToast: mocks.toast }) }));
vi.mock('@/hooks/useAnalysisStream', () => ({ useAnalysisStream: () => ({ state: { phase: 'idle' }, startAnalysis: mocks.start }) }));
// The permission primitive is covered separately; these cases exercise scan eligibility.
// eslint-disable-next-line @typescript-eslint/no-unused-vars
vi.mock('@/components/ui/PermissionButton', () => ({ PermissionButton: ({ children, permission: _permission, disabledReason: _reason, glow: _glow, size: _size, ...props }: {children: ReactNode; permission?: string; disabledReason?: string; glow?: boolean; size?: string}) => <button {...props}>{children}</button> }));
vi.mock('@/components/ui/PinButton', () => ({ PinButton: () => null }));
vi.mock('@/lib/api', () => ({ getRunsPage: vi.fn(), getRunsAggregate: vi.fn(), exportRunsJson: vi.fn(), getSbom: vi.fn(), getDashboardPostureVersions: vi.fn(), getRun: vi.fn(), getSbomInfo: vi.fn() }));

const run = { id: 'ec417fa1-3fc0-4cdd-889f-2c301159290a', display_id: 101, sbom_id: 'sbom-a', sbom_name: 'Gateway SBOM', sbom_version: '2.0', project_name: 'Gateway project', product_name: 'Gateway',
  run_status: 'PARTIAL', source: 'OSV,NVD', total_findings: 8, critical_count: 1, high_count: 2, medium_count: 3, low_count: 1, unknown_count: 1,
  completed_on: '2026-10-22T10:20:00Z', duration_ms: 1000, processing_eligibility: { eligible: true } } as AnalysisRun;
const sbom = { id: 'sbom-a', display_id: 1, sbom_name: 'Gateway SBOM', sbom_version: '2.0', projectid: 'project-a', product_id: 'product-a', processing_eligibility: { eligible: true } } as SBOMSource;
function wrap(children: ReactNode) {
  const qc = new QueryClient({ defaultOptions: { queries: { retry: false, gcTime: 0 } } });
  return <QueryClientProvider client={qc}>{children}</QueryClientProvider>;
}
beforeEach(() => {
  vi.clearAllMocks();
  vi.mocked(api.getRunsAggregate).mockResolvedValue({ total_runs: 107, total_findings: 8, by_outcome: { with_findings: 1, failed: 0, source_errors: 1, no_issues: 105, other: 0 } });
  vi.mocked(api.getRunsPage).mockResolvedValue({ items: [run], total: 107 });
  vi.mocked(api.getSbom).mockResolvedValue(sbom);
  vi.mocked(api.getDashboardPostureVersions).mockResolvedValue({ items: [] });
});
function History() { const [status, setStatus] = useState(''); return <AnalysisRunsHistory scope={{ project_id: 'project-a' }} status={status} onStatusChange={setStatus} />; }

describe('analysis history', () => {
  it('pages, searches, sorts and filters on the server, with full export filters', async () => {
    render(wrap(<History />));
    expect(await screen.findByText('#101')).toHaveAttribute('href', `/analysis/${run.id}`);
    expect(screen.getByText('Gateway project')).toBeVisible();
    expect(screen.getByLabelText('Unknown: 1')).toBeVisible();
    fireEvent.click(screen.getByRole('button', { name: 'Next page' }));
    await waitFor(() => expect(api.getRunsPage).toHaveBeenLastCalledWith(expect.objectContaining({ page: 2, page_size: 25, summary_only: true }), expect.any(AbortSignal)));
    fireEvent.change(screen.getByRole('searchbox', { name: 'Search runs' }), { target: { value: 'beyond page one' } });
    await waitFor(() => expect(api.getRunsPage).toHaveBeenLastCalledWith(expect.objectContaining({ page: 1, q: 'beyond page one' }), expect.any(AbortSignal)));
    fireEvent.change(screen.getByLabelText('Status'), { target: { value: 'PARTIAL' } });
    await waitFor(() => expect(api.getRunsPage).toHaveBeenLastCalledWith(expect.objectContaining({ run_status: 'PARTIAL' }), expect.any(AbortSignal)));
    fireEvent.click(screen.getByRole('button', { name: /Sort by Findings/ }));
    await waitFor(() => expect(api.getRunsPage).toHaveBeenLastCalledWith(expect.objectContaining({ sort_by: 'total_findings', page: 1 }), expect.any(AbortSignal)));
    fireEvent.click(screen.getByRole('button', { name: 'Export JSON' }));
    await waitFor(() => expect(api.exportRunsJson).toHaveBeenCalledWith(expect.objectContaining({ q: 'beyond page one', run_status: 'PARTIAL', project_id: 'project-a' })));
  });
  it('shows failures and allows retry without inventing an empty success', async () => {
    vi.mocked(api.getRunsPage).mockRejectedValueOnce(new Error('History service unavailable'));
    render(wrap(<History />));
    expect(await screen.findByText('History service unavailable')).toBeVisible();
    fireEvent.click(screen.getByRole('button', { name: 'Retry' }));
    expect(await screen.findByText('#101')).toBeVisible();
  });
  it('keeps filters available when no records match', async () => {
    vi.mocked(api.getRunsPage).mockResolvedValue({ items: [], total: 0 });
    render(wrap(<History />));
    expect(await screen.findByText(/No analysis runs match/)).toBeVisible();
    expect(screen.getByRole('searchbox', { name: 'Search runs' })).toBeEnabled();
  });
});

describe('selected SBOM and scan configuration', () => {
  const props = { analysisConfig: { github_configured: false, nvd_key_configured: true, max_concurrency: 3 }, sboms: [sbom], consolidatedSbomId: 'sbom-a', onConsolidatedSbomIdChange: vi.fn(), selectedSources: ['NVD', 'OSV', 'GITHUB'] as const, onSelectedSourcesChange: vi.fn() };
  it('accepts UUID selections, loads their metadata, and sends only configured sources', async () => {
    render(wrap(<ConsolidatedAnalysisPanel {...props} selectedSources={[...props.selectedSources]} />));
    const start = screen.getByRole('button', { name: 'Run analysis' });
    await waitFor(() => expect(start).toBeEnabled());
    expect(screen.queryByRole('spinbutton')).not.toBeInTheDocument();
    expect(api.getSbom).toHaveBeenCalledWith('sbom-a', expect.any(AbortSignal));
    expect(screen.getByText('2.0')).toBeVisible();
    fireEvent.click(start);
    expect(mocks.start).toHaveBeenCalledWith({ sources: ['NVD', 'OSV'] });
  });
  it('blocks ineligible SBOMs with the backend reason', async () => {
    vi.mocked(api.getSbom).mockResolvedValue({ ...sbom, processing_eligibility: { eligible: false, reason_code: 'SBOM_INACTIVE', reason: 'This SBOM is inactive.' } });
    render(wrap(<ConsolidatedAnalysisPanel {...props} selectedSources={['OSV']} />));
    expect(await screen.findByText('This SBOM is inactive.')).toBeVisible();
    expect(screen.getByRole('button', { name: 'Run analysis' })).toBeDisabled();
  });
  it('monitors an existing queued or running attempt without starting a duplicate', async () => {
    vi.mocked(api.getSbom).mockResolvedValue({ ...sbom, latest_analysis: { status: 'RUNNING', run_id: run.id } });
    render(wrap(<ConsolidatedAnalysisPanel {...props} selectedSources={['OSV']} />));
    expect(await screen.findByRole('link', { name: 'View latest attempt' })).toHaveAttribute('href', `/analysis/${run.id}`);
    expect(screen.getByRole('button', { name: 'Run analysis' })).toBeDisabled();
    expect(mocks.start).not.toHaveBeenCalled();
  });
  it('maps version provenance separately from actual run counts and timestamp', async () => {
    vi.mocked(api.getDashboardPostureVersions).mockResolvedValue({ items: [{ target_sbom_id: sbom.id, analysis_run_id: run.id,
      current_sbom: { id: sbom.id, name: 'Current gateway', version: '2.0' }, latest_uploaded: { id: sbom.id, name: 'Uploaded gateway', version: '2.1' },
      latest_analyzed: { id: sbom.id, name: 'Analyzed gateway', version: '2.0' }, posture_sbom: { id: sbom.id, name: 'Evidence gateway', version: '2.0' },
      coverage_incomplete: true, warning: null } as never] });
    vi.mocked(api.getRun).mockResolvedValue(run);
    render(wrap(<SelectedSbomContext sbom={sbom} />));
    expect(await screen.findByText('Total findings')).toBeVisible();
    expect(screen.getByText('8')).toBeVisible();
    expect(screen.getByText(/Last successful analysis:/)).not.toHaveTextContent('finding records');
    expect(screen.getByText(/Zero reported findings/)).toBeVisible();
    expect(api.getDashboardPostureVersions).toHaveBeenCalledWith({ projectId: 'project-a', applicationId: 'product-a', sbomId: 'sbom-a' }, expect.any(AbortSignal));
  });
  it('shows partial completion and accessible progress without a security guarantee', () => {
    const state = { phase: 'done' as const, runStatus: 'PARTIAL', components: 3, sources: {}, elapsedMs: 1000, runId: run.id, summary: { total: 8, critical: 1, high: 2, medium: 3, low: 1, unknown: 1 }, error: null };
    const view = render(wrap(<LiveAnalysisCard state={state} />));
    expect(screen.getByText('Incomplete coverage')).toBeVisible();
    expect(screen.getByText(/Findings may be incomplete/)).toBeVisible();
    view.rerender(wrap(<LiveAnalysisCard state={{ ...state, phase: 'running', sources: { OSV: { name: 'OSV', status: 'running', findings: 0, errors: 0, elapsedMs: 0, sourceMs: 0 } } }} />));
    expect(screen.getByRole('progressbar', { name: 'Vulnerability sources finished' })).toHaveAttribute('aria-valuenow', '0');
  });
});

// @vitest-environment jsdom
import { QueryClient, QueryClientProvider } from '@tanstack/react-query';
import { render, screen, fireEvent, waitFor } from '@testing-library/react';
import { beforeEach, describe, it, expect, vi } from 'vitest';
import { SbomAutoRepairPanel } from './SbomAutoRepairPanel';
import { analyzeSbomRepair, getLatestSbomRepair, runSbomRepair, decideSbomRepair } from '@/lib/api';

vi.mock('@/lib/api', () => ({ analyzeSbomRepair: vi.fn(), getLatestSbomRepair: vi.fn(), runSbomRepair: vi.fn(),
  decideSbomRepair: vi.fn(), downloadSbomRepair: vi.fn(), downloadValidationSessionOriginal: vi.fn() }));
vi.mock('@/lib/queryInvalidation', () => ({ invalidateSbomSurfaces: vi.fn(), invalidateDashboardTiles: vi.fn(), invalidateProjectSurfaces: vi.fn(), invalidateProductSurfaces: vi.fn() }));
const caps = { can_repair: true, can_approve: true, can_reject: true, can_download: true };
const analysis = { source_sha256: 'b'.repeat(64), enabled: true, validation_status: 'FAILED' as const, total_errors: 4, auto_fixable: 2, suggested: 1,
  manual_only: 1, truncated: false, capabilities: caps, issues: [{ code: 'E051', path: '/components/1/bom-ref', message: 'Duplicate', classification: 'AUTO_FIX' as const }] };
const job = { source_sha256: 'b'.repeat(64), candidate_sha256: 'a'.repeat(64), repair_job_id: 'job', status: 'REPAIRED', approval_status: 'PENDING' as const,
  errors_before: 4, errors_after: 0, repairs_applied: 4, validation_status: 'PASSED' as const, imported_sbom_id: null, capabilities: caps,
  changes: [{ repair_id: 'change', error_code: 'E051', path: '/components/1/bom-ref', old_value: '<script>data</script>',
    new_value: 'unique', operation: 'replace', rule_name: 'duplicate_bom_ref', reason: 'Unambiguous', confidence: 1, method: 'DETERMINISTIC' as const }] };
function show() { render(<QueryClientProvider client={new QueryClient({ defaultOptions: { queries: { retry: false } } })}><SbomAutoRepairPanel sessionId="session" /></QueryClientProvider>); }
beforeEach(() => {
  vi.clearAllMocks();
  vi.mocked(analyzeSbomRepair).mockResolvedValue(analysis);
  vi.mocked(getLatestSbomRepair).mockResolvedValue(null);
  vi.mocked(runSbomRepair).mockResolvedValue(job);
  vi.mocked(decideSbomRepair).mockResolvedValue({ ...job, approval_status: 'APPROVED', imported_sbom_id: 42 });
});
describe('deterministic repair review', () => {
  it('shows classification and requires an explicit repair action', async () => {
    show();
    expect(await screen.findByText(/2 can be safely repaired/)).toBeInTheDocument();
    expect(runSbomRepair).not.toHaveBeenCalled();
    fireEvent.click(screen.getByRole('button', { name: 'Auto-Repair Safe Issues' }));
    expect(await screen.findByText('Auto-Repair Completed')).toBeInTheDocument();
    expect(decideSbomRepair).not.toHaveBeenCalled();
  });
  it('displays a safe escaped diff and its reasons', async () => {
    vi.mocked(getLatestSbomRepair).mockResolvedValue(job);
    show();
    fireEvent.click(await screen.findByRole('button', { name: 'View Changes' }));
    expect(screen.getByText('Unambiguous')).toBeInTheDocument();
    expect(screen.getByText(/<script>data<\/script>/)).toBeInTheDocument();
    expect(document.querySelector('script')).toBeNull();
    expect(screen.getByText('100%')).toBeInTheDocument();
  });
  it('blocks approval when validation still fails', async () => {
    vi.mocked(getLatestSbomRepair).mockResolvedValue({ ...job, status: 'PARTIALLY_REPAIRED', errors_after: 1, validation_status: 'FAILED' });
    show();
    expect(await screen.findByRole('button', { name: 'Accept Repairs' })).toBeDisabled();
  });
  it('explicit acceptance records approval and links the imported SBOM', async () => {
    vi.mocked(getLatestSbomRepair).mockResolvedValue(job);
    show();
    fireEvent.click(await screen.findByRole('button', { name: 'Accept Repairs' }));
    await waitFor(() => expect(decideSbomRepair).toHaveBeenCalledWith('session', 'job', 'approve', 'a'.repeat(64)));
    expect(await screen.findByRole('link', { name: 'Open Accepted SBOM' })).toHaveAttribute('href', '/sboms/42');
  });
  it('rejects without importing', async () => {
    vi.mocked(getLatestSbomRepair).mockResolvedValue(job);
    vi.mocked(decideSbomRepair).mockResolvedValue({ ...job, approval_status: 'REJECTED', status: 'REJECTED' });
    show();
    fireEvent.click(await screen.findByRole('button', { name: 'Reject Repairs' }));
    await waitFor(() => expect(decideSbomRepair).toHaveBeenCalledWith('session', 'job', 'reject'));
    expect(screen.queryByRole('link', { name: 'Open Accepted SBOM' })).not.toBeInTheDocument();
  });
  it('hides unauthorized actions', async () => {
    vi.mocked(analyzeSbomRepair).mockResolvedValue({ ...analysis, capabilities: { ...caps, can_repair: false } });
    show();
    await screen.findByText(/2 can be safely repaired/);
    expect(screen.queryByRole('button', { name: 'Auto-Repair Safe Issues' })).not.toBeInTheDocument();
  });
  it('keeps validation accessible if classification fails', async () => {
    vi.mocked(analyzeSbomRepair).mockRejectedValue(new Error('offline'));
    show();
    expect(await screen.findByText(/Repair classification unavailable/)).toBeInTheDocument();
  });
});


describe('repair release state integrity', () => {
  it('blocks stale approval and offers repair for the current draft', async () => {
    vi.mocked(getLatestSbomRepair).mockResolvedValue({ ...job, source_sha256: 'c'.repeat(64) });
    show();
    expect(await screen.findByRole('button', { name: 'Accept Repairs' })).toBeDisabled();
    expect(screen.getByText(/Source draft changed/)).toBeInTheDocument();
    expect(screen.getByRole('button', { name: 'Auto-Repair Safe Issues' })).toBeEnabled();
  });
  it('uses remaining errors from the candidate instead of repaired original errors', async () => {
    vi.mocked(getLatestSbomRepair).mockResolvedValue({ ...job, status: 'PARTIALLY_REPAIRED',
      validation_status: 'FAILED', manual_errors: 1, suggested_repairs: 0,
      analysis: { ...analysis, issues: [{ code: 'MANUAL', path: '/components/0/version', message: 'Missing version', classification: 'MANUAL_ONLY' }] } });
    show();
    fireEvent.click(await screen.findByRole('button', { name: 'View Errors' }));
    expect(screen.getByText(/Missing version/)).toBeInTheDocument();
    expect(screen.queryByText(/E051.*Duplicate/)).not.toBeInTheDocument();
    expect(screen.getByText('Partial Repair — Manual Review Required')).toBeInTheDocument();
  });
  it('does not force repair controls for a valid SBOM', async () => {
    vi.mocked(analyzeSbomRepair).mockResolvedValue({ ...analysis, validation_status: 'PASSED', total_errors: 0, auto_fixable: 0, issues: [] });
    show();
    await waitFor(() => expect(screen.queryByRole('status')).not.toBeInTheDocument());
    expect(screen.queryByRole('region', { name: 'Deterministic SBOM auto-repair' })).not.toBeInTheDocument();
  });
  it('explains signed-document manual handling', async () => {
    vi.mocked(analyzeSbomRepair).mockResolvedValue({ ...analysis, auto_fixable: 0, manual_review_reason: 'Signed documents require manual handling.' });
    show();
    expect(await screen.findByText('Signed documents require manual handling.')).toBeInTheDocument();
    expect(screen.queryByRole('button', { name: 'Auto-Repair Safe Issues' })).not.toBeInTheDocument();
  });
});

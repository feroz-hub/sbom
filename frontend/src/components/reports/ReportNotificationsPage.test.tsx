// @vitest-environment jsdom
import { beforeEach, describe, expect, it, vi } from 'vitest';
import { fireEvent, render, screen, waitFor, cleanup } from '@testing-library/react';
import { QueryClient, QueryClientProvider } from '@tanstack/react-query';
import { ReportNotificationsPage, ReportPreferencesEditor, defaultReportPreferences } from './ReportNotificationsPage';
import * as api from '@/lib/reportApi';

let searchParams = new URLSearchParams();
vi.mock('next/navigation', () => ({ useSearchParams: () => searchParams }));
vi.mock('@/hooks/useToast', () => ({ useToast: () => ({ showToast: vi.fn() }) }));
vi.mock('@/lib/reportApi', () => ({
  getReportConfig: vi.fn().mockResolvedValue({ enabled: false, delivery_enabled: false, diagnostics: [], tenant_id: 1, is_tenant_admin: false, retention_days: 90 }),
  getReportSubscriptions: vi.fn().mockResolvedValue([]),
  getReportDeliveries: vi.fn().mockResolvedValue([]),
  deleteReportSubscription: vi.fn(),
  sendReportNow: vi.fn(),
  getReportTargets: vi.fn().mockResolvedValue([{ id: 3, label: 'Production' }]),
  createReportSubscription: vi.fn().mockResolvedValue({ id: 1 }),
  updateReportSubscription: vi.fn().mockResolvedValue({ id: 1 }),
  previewReport: vi.fn().mockResolvedValue({ html_body: '<p>Preview</p>', report: { sboms: [] } }),
}));

function setup(initial = defaultReportPreferences('PROJECT', 3), allowed = false) {
  const client = new QueryClient({ defaultOptions: { queries: { retry: false }, mutations: { retry: false } } });
  const invalidate = vi.spyOn(client, 'invalidateQueries');
  render(<QueryClientProvider client={client}><ReportPreferencesEditor initial={initial} tenantScopeAllowed={allowed} onClose={vi.fn()} /></QueryClientProvider>);
  return { invalidate };
}

beforeEach(() => { cleanup(); vi.clearAllMocks(); searchParams = new URLSearchParams(); });
describe('Notification preferences', () => {
  it('opens the exact emailed delivery and lets the user return to recent history', async () => {
    searchParams = new URLSearchParams('delivery=52');
    const client = new QueryClient({ defaultOptions: { queries: { retry: false } } });
    render(<QueryClientProvider client={client}><ReportNotificationsPage /></QueryClientProvider>);
    await waitFor(() => expect(api.getReportDeliveries).toHaveBeenCalledWith(false, '', 52));
    fireEvent.click(await screen.findByRole('button', { name: 'Show recent deliveries' }));
    await waitFor(() => expect(api.getReportDeliveries).toHaveBeenCalledWith(false, '', undefined));
  });
  it('keeps Part A mandatory and no free-text recipient', async () => {
    setup();
    expect(screen.getByLabelText('Part A: Latest state (required)')).toBeDisabled();
    expect(screen.queryByLabelText(/recipient email/i)).not.toBeInTheDocument();
    expect(screen.queryByRole('option', { name: 'TENANT' })).not.toBeInTheDocument();
    await screen.findByRole('option', { name: 'Production · #3' });
  });
  it('allows tenant scope only when backend grants it', () => {
    setup(defaultReportPreferences('TENANT'), true);
    expect(screen.getByRole('option', { name: 'TENANT' })).toBeInTheDocument();
  });
  it('previews without saving and uses a sandboxed iframe', async () => {
    setup();
    fireEvent.click(screen.getByRole('button', { name: 'Preview' }));
    await waitFor(() => expect(api.previewReport).toHaveBeenCalledOnce());
    expect(api.createReportSubscription).not.toHaveBeenCalled();
    expect(await screen.findByTitle('Security digest email preview')).toHaveAttribute('sandbox', '');
  });
  it('saves preferences and invalidates report surfaces', async () => {
    const { invalidate } = setup();
    fireEvent.change(screen.getByLabelText('Cadence'), { target: { value: 'ON_EVERY_RUN' } });
    fireEvent.click(screen.getByRole('button', { name: 'Save subscription' }));
    await waitFor(() => expect(api.createReportSubscription).toHaveBeenCalledWith(expect.objectContaining({ cadence: 'ON_EVERY_RUN', project_id: 3 })));
    expect(invalidate).toHaveBeenCalledWith({ queryKey: ['reports'] });
  });
  it('blocks an empty target and unchanged filtering without a delta', () => {
    setup({ ...defaultReportPreferences(), parts: ['A'] });
    expect(screen.getByRole('button', { name: 'Save subscription' })).toBeDisabled();
    expect(screen.getByLabelText('Skip when selected comparisons are unchanged')).toBeDisabled();
  });
  it('surfaces save failures and leaves the editor open', async () => {
    vi.mocked(api.createReportSubscription).mockRejectedValueOnce(new Error('private backend details'));
    setup();
    fireEvent.click(screen.getByRole('button', { name: 'Save subscription' }));
    expect(await screen.findByRole('alert')).toHaveTextContent('Could not save this subscription.');
    expect(screen.getByRole('button', { name: 'Save subscription' })).toBeInTheDocument();
  });
});

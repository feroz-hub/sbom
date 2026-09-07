// @vitest-environment jsdom
import { beforeEach, describe, expect, it, vi } from 'vitest';
import { fireEvent, render, screen, waitFor, cleanup } from '@testing-library/react';
import { QueryClient, QueryClientProvider } from '@tanstack/react-query';
import { ReportPreferencesEditor, defaultReportPreferences } from './ReportNotificationsPage';
import * as api from '@/lib/reportApi';

vi.mock('next/navigation', () => ({ useSearchParams: () => new URLSearchParams() }));
vi.mock('@/hooks/useToast', () => ({ useToast: () => ({ showToast: vi.fn() }) }));
vi.mock('@/lib/reportApi', () => ({
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

beforeEach(() => { cleanup(); vi.clearAllMocks(); });
describe('Notification preferences', () => {
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

// @vitest-environment jsdom
import { QueryClient, QueryClientProvider, QueryObserver } from '@tanstack/react-query';
import { fireEvent, render, screen, waitFor, within } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { axe } from 'vitest-axe';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import { setActiveTenantId, clearActiveTenantId } from '@/lib/auth';
import { ToastProvider } from '@/hooks/useToast';
import { makeProvider, successfulProbe, visualProviders } from '@/test/lifecycle-provider-fixtures';
import type { LifecycleProviderConfig } from '@/types';
import { LifecycleProviderSettings } from './LifecycleProviderSettings';
import { LifecycleVendorRecordsPage } from './LifecycleVendorRecordsPage';

const api = vi.hoisted(() => ({ listLifecycleProviders: vi.fn(), resetLifecycleProviderOverride: vi.fn(), updateLifecycleProvider: vi.fn(), setLifecycleProviderSecret: vi.fn(), deleteLifecycleProviderSecret: vi.fn(), testLifecycleProvider: vi.fn(), syncLifecycleProvider: vi.fn(), listLifecycleVendorRecords: vi.fn(), createLifecycleVendorRecord: vi.fn(), updateLifecycleVendorRecord: vi.fn(), deleteLifecycleVendorRecord: vi.fn(), importLifecycleVendorRecords: vi.fn(), exportLifecycleVendorRecords: vi.fn() }));
vi.mock('@/lib/api', () => api);
vi.mock('@/hooks/useAuth', async () => ({ useAuth: (await import('@/test/authorizedAuth')).authorizedAuth }));
function renderWithProviders(ui: React.ReactElement) { return render(<QueryClientProvider client={new QueryClient({ defaultOptions: { queries: { retry: false }, mutations: { retry: false } } })}><ToastProvider>{ui}</ToastProvider></QueryClientProvider>); }
let rows: LifecycleProviderConfig[];
beforeEach(() => {
  vi.clearAllMocks(); rows = [makeProvider()]; api.listLifecycleProviders.mockImplementation(async () => rows);
  api.updateLifecycleProvider.mockImplementation(async (key, payload) => { const row = { ...rows.find(p => p.provider_key === key)!, ...payload, last_probe: null, override_enabled: true }; rows = rows.map(p => p.provider_key === key ? row : p); return row; });
  api.testLifecycleProvider.mockResolvedValue(successfulProbe);
  api.setLifecycleProviderSecret.mockResolvedValue({}); api.deleteLifecycleProviderSecret.mockResolvedValue(undefined);
  api.resetLifecycleProviderOverride.mockImplementation(async key => { rows = rows.map(p => p.provider_key === key ? { ...p, override_enabled: false } : p); });
  api.syncLifecycleProvider.mockResolvedValue({ status: 'completed', job_id: null, message: 'Local source cache reloaded.' });
});
afterEach(() => clearActiveTenantId());
function setup(props: React.ComponentProps<typeof LifecycleProviderSettings> = {}, observe = false) {
  const qc = new QueryClient({ defaultOptions: { queries: { retry: false, staleTime: 300_000 }, mutations: { retry: false } } });
  const statusFetch = vi.fn().mockResolvedValue({ overall_status: 'healthy' });
  qc.setQueryData(['lifecycle-provider-status'], { overall_status: 'unknown' }); qc.setQueryData(['lifecycle-providers', 'tenant:99'], [makeProvider()]); qc.setQueryData(['sbom-components-canonical', 5], 'existing evidence');
  const observer = observe ? new QueryObserver(qc, { queryKey: ['lifecycle-provider-status'], queryFn: statusFetch }).subscribe(() => {}) : () => {};
  const view = render(<QueryClientProvider client={qc}><ToastProvider><LifecycleProviderSettings scopeKey="tenant:1" {...props} /></ToastProvider></QueryClientProvider>);
  return { ...view, qc, statusFetch, stop: () => { observer(); view.unmount(); qc.clear(); } };
}
async function manage(name = 'endoflife.date') { await userEvent.click(await screen.findByRole('button', { name: `Manage ${name}` })); }
async function section(name: string) { await userEvent.click(screen.getByRole('button', { name })); }
function priority(value = '27') { fireEvent.change(screen.getByLabelText('Priority'), { target: { value } }); }

describe('LifecycleProviderSettings enterprise directory', () => {
  it('has no automated accessibility violations in the directory and configuration drawer', async () => {
    const h = setup(); await screen.findByRole('button', { name: 'Manage endoflife.date' });
    expect((await axe(h.container)).violations).toEqual([]);
    await manage(); await section('Configuration');
    expect((await axe(screen.getByRole('dialog'))).violations).toEqual([]);
  });
  it('shows compact columns and computes metrics using stored proof only', async () => {
    rows = [makeProvider({ last_probe: successfulProbe, health_status: 'healthy' }), makeProvider({ provider_key: 'legacy', display_name: 'Legacy', health_status: 'healthy', last_success_at: '2026-10-01' }), makeProvider({ provider_key: 'off', display_name: 'Off', enabled: false }), makeProvider({ provider_key: 'unsupported', display_name: 'Unsupported source' }, { implemented: false })];
    setup(); const summary = await screen.findByRole('region', { name: 'Provider summary' });
    await screen.findByRole('button', { name: 'Manage Legacy' });
    expect(within(summary).getByText('Total providers').parentElement).toHaveTextContent('4');
    expect(within(summary).getByText('Verified operational').parentElement).toHaveTextContent('1');
    expect(within(summary).getByText('Needs attention').parentElement).toHaveTextContent('1');
    expect(within(summary).getByText('Disabled providers').parentElement).toHaveTextContent('1');
    expect(screen.getAllByRole('columnheader')).toHaveLength(6);
    expect(screen.queryByText('https://endoflife.date/api')).not.toBeInTheDocument();
    expect(screen.queryByText('legacy')).not.toBeInTheDocument();
  });
  it('searches, filters, clears empty results and sorts by actual priority/name', async () => {
    rows = [makeProvider({ display_name: 'Zulu', priority: 80 }), makeProvider({ provider_key: 'a', display_name: 'Alpha', priority: 10, enabled: false })]; setup();
    await screen.findByRole('button', { name: 'Manage Zulu' });
    expect(screen.getAllByRole('row')[1]).toHaveTextContent('Alpha');
    await userEvent.selectOptions(screen.getByLabelText('Sort providers'), 'name'); expect(screen.getAllByRole('row')[1]).toHaveTextContent('Alpha');
    await userEvent.click(screen.getByRole('button', { name: 'Enabled' })); expect(screen.queryByRole('button', { name: 'Manage Alpha' })).not.toBeInTheDocument();
    fireEvent.change(screen.getByLabelText('Search providers'), { target: { value: 'missing' } }); expect(screen.getByText('No providers match your search')).toBeInTheDocument();
    await userEvent.click(screen.getByRole('button', { name: 'Clear filters' })); expect(screen.getByRole('button', { name: 'Manage Alpha' })).toBeInTheDocument();
  });
  it('opens details for read-only users and returns focus when closed', async () => {
    setup({ canUpdate: false }); await manage(); expect(screen.getByRole('dialog', { name: 'endoflife.date' })).toBeInTheDocument();
    await section('Configuration'); expect(screen.getByLabelText('Priority')).toBeDisabled(); expect(screen.queryByRole('button', { name: 'Save changes' })).not.toBeInTheDocument();
    await userEvent.click(screen.getByRole('button', { name: 'Close dialog' })); expect(screen.queryByRole('dialog')).not.toBeInTheDocument(); expect(screen.getByRole('button', { name: 'Manage endoflife.date' })).toHaveFocus();
  });
  it('supports keyboard opening and Escape dismissal', async () => {
    setup(); const manageButton = await screen.findByRole('button', { name: 'Manage endoflife.date' }); manageButton.focus(); await userEvent.keyboard('{Enter}');
    expect(screen.getByRole('dialog')).toBeInTheDocument(); await userEvent.keyboard('{Escape}'); expect(screen.queryByRole('dialog')).not.toBeInTheDocument(); expect(manageButton).toHaveFocus();
  });
  it('confirms discard and retains drafts when continuing to edit', async () => {
    setup(); await manage(); await section('Configuration'); priority(); await userEvent.click(screen.getByRole('button', { name: 'Close dialog' }));
    expect(screen.getByRole('alert', { name: 'Unsaved changes' })).toBeInTheDocument(); await userEvent.click(screen.getByRole('button', { name: 'Keep editing' })); expect(screen.getByLabelText('Priority')).toHaveValue(27);
    await userEvent.click(screen.getByRole('button', { name: 'Close dialog' })); await userEvent.click(screen.getByRole('button', { name: 'Discard changes' })); expect(screen.queryByRole('dialog')).not.toBeInTheDocument();
  });
  it('preserves an edited draft when switching sections', async () => {
    setup(); await manage(); await section('Configuration'); priority(); await section('Verification'); expect(screen.getByRole('button', { name: 'Verify connection' })).toBeDisabled();
    await section('Configuration'); expect(screen.getByLabelText('Priority')).toHaveValue(27);
  });
  it('saves without closing details, refreshes authoritative health and preserves unrelated caches', async () => {
    const h = setup({}, true); await manage(); await section('Configuration'); priority(); await userEvent.click(screen.getByRole('button', { name: 'Save changes' }));
    await waitFor(() => expect(h.statusFetch).toHaveBeenCalledTimes(1)); expect(api.updateLifecycleProvider).toHaveBeenCalledWith('endoflife_date', expect.objectContaining({ priority: 27 }), undefined, 'tenant');
    expect(screen.getByRole('dialog')).toBeInTheDocument(); expect(h.qc.getQueryData(['sbom-components-canonical', 5])).toBe('existing evidence'); expect(h.qc.getQueryState(['lifecycle-providers', 'tenant:99'])?.isInvalidated).toBe(false); h.stop();
  });
  it('keeps failed save drafts and does not falsely update readiness', async () => {
    api.updateLifecycleProvider.mockRejectedValue(new Error('Denied')); const h = setup({}, true); await manage(); await section('Configuration'); priority(); await userEvent.click(screen.getByRole('button', { name: 'Save changes' }));
    await screen.findByText('Provider configuration update failed.'); expect(screen.getByLabelText('Priority')).toHaveValue(27); expect(h.statusFetch).not.toHaveBeenCalled(); h.stop();
  });
  it('offers explicit tenant customization before any inherited write', async () => {
    rows = [makeProvider({ source: 'PLATFORM_DEFAULT', override_enabled: false, has_secret: true }, { secret_name: 'api_key' })]; setup({ tenantName: 'Olympus' }); await manage(); await section('Configuration');
    expect(screen.getByLabelText('Priority')).toBeDisabled(); expect(screen.getByText('Credential managed by platform')).toBeInTheDocument(); expect(screen.queryByLabelText('Provider credential')).not.toBeInTheDocument();
    await userEvent.click(screen.getByRole('button', { name: 'Customize for Olympus' })); expect(screen.getByLabelText('Priority')).toBeEnabled(); expect(api.updateLifecycleProvider).not.toHaveBeenCalled();
    await userEvent.click(screen.getByRole('button', { name: 'Save tenant override' })); await waitFor(() => expect(api.updateLifecycleProvider).toHaveBeenCalled());
  });
  it('confirms resetting an override before using the existing endpoint', async () => {
    setup(); await manage(); await section('Configuration'); await userEvent.click(screen.getByRole('button', { name: 'Reset to platform defaults' })); expect(api.resetLifecycleProviderOverride).not.toHaveBeenCalled();
    await userEvent.click(screen.getByRole('button', { name: 'Reset to platform defaults' })); await waitFor(() => expect(api.resetLifecycleProviderOverride).toHaveBeenCalledWith('endoflife_date', expect.anything()));
  });
  it('renders real operation, auth, sample, coverage and error separately', async () => {
    api.testLifecycleProvider.mockResolvedValue({ ...successfulProbe, success: false, status: 'degraded', authentication_verified: false, response_valid: false, lifecycle_evidence_found: false, http_status: 401, error_code: 'http_401', message: 'Authentication failed' });
    const h = setup({}, true); await manage(); await section('Verification'); await userEvent.click(screen.getByRole('button', { name: 'Verify connection' }));
    expect(await screen.findByText('http_401')).toBeInTheDocument(); expect(screen.getByText('401')).toBeInTheDocument(); expect(screen.getByText('debian · 12')).toBeInTheDocument(); expect(screen.getByText('Not found for this sample')).toBeInTheDocument(); await waitFor(() => expect(h.statusFetch).toHaveBeenCalledTimes(1)); h.stop();
  });
  it('locks editing and closing while a verification is running', async () => {
    let finish!: (result: typeof successfulProbe) => void;
    api.testLifecycleProvider.mockImplementation(() => new Promise(resolve => { finish = resolve; }));
    setup(); await manage(); await section('Verification'); await userEvent.click(screen.getByRole('button', { name: 'Verify connection' }));
    await section('Configuration'); expect(screen.getByLabelText('Priority')).toBeDisabled();
    await userEvent.click(screen.getByRole('button', { name: 'Close dialog' })); expect(screen.getByRole('dialog')).toBeInTheDocument();
    finish(successfulProbe); await waitFor(() => expect(screen.getByLabelText('Priority')).toBeEnabled());
  });
  it('shows a failed verification request without inventing a provider result', async () => {
    api.testLifecycleProvider.mockRejectedValue(new Error('Service unavailable')); setup(); await manage(); await section('Verification');
    await userEvent.click(screen.getByRole('button', { name: 'Verify connection' }));
    expect(await within(screen.getByRole('dialog')).findByRole('alert')).toHaveTextContent('No new verification result was recorded');
    expect(screen.getByText(/Not verified yet. Run verification/)).toBeInTheDocument();
  });
  it('uses explicit platform scope when verifying', async () => {
    setup({ scope: 'platform', scopeKey: 'platform' }); await manage(); await section('Verification'); await userEvent.click(screen.getByRole('button', { name: 'Verify connection' }));
    await waitFor(() => expect(api.testLifecycleProvider).toHaveBeenCalledWith('endoflife_date', undefined, 'platform'));
  });
  it('does not turn a transient inherited test into stored verification', async () => {
    rows = [makeProvider({ override_enabled: false })]; const h = setup({}, true); await manage(); await section('Verification'); await userEvent.click(screen.getByRole('button', { name: 'Verify connection' }));
    await screen.findAllByText(successfulProbe.message); expect(h.statusFetch).not.toHaveBeenCalled(); expect(within(screen.getByRole('region', { name: 'Provider summary' })).getByText('Verified operational').parentElement).toHaveTextContent('0'); h.stop();
  });
  it('explains disabled verification and never silently enables runtime', async () => {
    rows = [makeProvider({ enabled: false, health_status: 'disabled' })]; setup(); await manage(); await section('Verification'); expect(screen.getByRole('button', { name: 'Verify connection' })).toBeDisabled(); expect(screen.getByText(/current API skips disabled/)).toBeInTheDocument(); expect(api.updateLifecycleProvider).not.toHaveBeenCalled();
  });
  it('does not advertise activation, verification or sync for unsupported providers', async () => {
    rows = [visualProviders.find(p => p.provider_key === 'official_vendor_lifecycle')!]; setup(); await manage('Official Vendor Lifecycle');
    expect(screen.getByRole('button', { name: 'Configuration' })).toBeDisabled(); await section('Verification'); expect(screen.queryByRole('button', { name: 'Verify connection' })).not.toBeInTheDocument(); expect(screen.queryByRole('button', { name: 'Reload cache' })).not.toBeInTheDocument();
  });
  it('restores stored verification on reload and exposes no invented history', async () => {
    rows = [makeProvider({ last_probe: successfulProbe, health_status: 'healthy' })]; setup(); await manage(); await section('Verification'); expect(screen.getByText(successfulProbe.message)).toBeInTheDocument();
    await section('Activity'); expect(screen.getByText(/not a complete activity history/)).toBeInTheDocument(); expect(screen.getAllByText('Not yet recorded').length).toBeGreaterThan(0);
  });
  it('shows reload only for supported sources and does not claim a queued job', async () => {
    rows = [makeProvider({ provider_key: 'xeol_db', display_name: 'Local Xeol DB' }, { network: false, sync_action: 'reload_cache' })]; const h = setup({}, true); await manage('Local Xeol DB'); await section('Verification');
    await userEvent.click(screen.getByRole('button', { name: 'Reload cache' })); await screen.findByText('Local source cache reloaded.'); await waitFor(() => expect(h.statusFetch).toHaveBeenCalledTimes(1)); expect(api.syncLifecycleProvider).toHaveBeenCalledWith('xeol_db', undefined, 'tenant'); h.stop();
  });
  it('blocks unauthorized test and configuration actions', async () => {
    setup({ canUpdate: false, canTest: false, canSync: false }); await manage(); await section('Verification'); expect(screen.getByRole('button', { name: 'Verify connection' })).toBeDisabled();
    await section('Configuration'); expect(screen.getByLabelText('Priority')).toBeDisabled(); expect(api.updateLifecycleProvider).not.toHaveBeenCalled();
  });
  it('handles empty and failed service responses without fabricated metrics', async () => {
    api.listLifecycleProviders.mockRejectedValue(new Error('Unavailable')); setup(); expect(await screen.findByRole('alert')).toHaveTextContent('Unable to load provider configuration'); expect(screen.getAllByText('Unavailable')).toHaveLength(4);
  });
  it('renders an actual loading state', () => { api.listLifecycleProviders.mockImplementation(() => new Promise(() => {})); setup(); expect(screen.getByText('Loading provider configuration…')).toBeInTheDocument(); });
  it('renders empty source state', async () => { rows = []; setup(); expect(await screen.findByText('No lifecycle providers configured')).toBeInTheDocument(); });
  it('does not restore stale provider data after tenant switches during a write', async () => {
    setActiveTenantId('1'); let finish!: (value: LifecycleProviderConfig) => void; api.updateLifecycleProvider.mockImplementation(() => new Promise(resolve => { finish = resolve; }));
    const h = setup(); await manage(); await section('Configuration'); priority(); await userEvent.click(screen.getByRole('button', { name: 'Save changes' })); await waitFor(() => expect(finish).toBeDefined());
    setActiveTenantId('2'); h.qc.clear(); finish(makeProvider()); await waitFor(() => expect(h.qc.getQueryCache().getAll()).toHaveLength(0)); h.stop();
  });
});
describe('LifecycleVendorRecordsPage', () => {
  beforeEach(() => {
    vi.clearAllMocks();
    api.listLifecycleVendorRecords.mockResolvedValue({
      items: [
        {
          id: 1,
          vendor_name: 'Acme',
          product_name: 'legacy-runtime',
          product_aliases: ['legacy'],
          ecosystem: 'generic',
          version_pattern: '1',
          version_start: null,
          version_end: null,
          lifecycle_status: 'EOL',
          maintenance_status: null,
          eol_date: '2024-01-01',
          eos_date: null,
          eof_date: null,
          deprecated: false,
          unsupported: true,
          latest_supported_version: null,
          recommended_version: null,
          evidence_url: 'https://example.com/lifecycle',
          evidence: {},
          confidence: 'High',
          enabled: true,
          created_at: '2026-06-27T00:00:00Z',
          updated_at: '2026-06-27T00:00:00Z',
        },
      ],
      total: 1,
      limit: 100,
      offset: 0,
    });
    api.createLifecycleVendorRecord.mockResolvedValue({});
    api.exportLifecycleVendorRecords.mockResolvedValue({ records: [] });
  });

  it('renders custom vendor records', async () => {
    renderWithProviders(<LifecycleVendorRecordsPage />);
    expect(await screen.findByText('legacy-runtime')).toBeInTheDocument();
    expect(screen.getByText('Acme')).toBeInTheDocument();
  });

  it('opens create form', async () => {
    renderWithProviders(<LifecycleVendorRecordsPage />);
    await userEvent.click(await screen.findByRole('button', { name: /add/i }));
    expect(await screen.findByText('Add Vendor Record')).toBeInTheDocument();
  });
});

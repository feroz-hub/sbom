// @vitest-environment jsdom

import { QueryClient, QueryClientProvider, QueryObserver } from '@tanstack/react-query';
import { render, screen, waitFor } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { describe, expect, it, vi, beforeEach } from 'vitest';
import { setActiveTenantId, clearActiveTenantId } from '@/lib/auth';
import { ToastProvider } from '@/hooks/useToast';
import { LifecycleProviderSettings } from './LifecycleProviderSettings';
import { LifecycleVendorRecordsPage } from './LifecycleVendorRecordsPage';

const api = vi.hoisted(() => ({
  listLifecycleProviders: vi.fn(),
  resetLifecycleProviderOverride: vi.fn(),
  updateLifecycleProvider: vi.fn(),
  setLifecycleProviderSecret: vi.fn(),
  deleteLifecycleProviderSecret: vi.fn(),
  testLifecycleProvider: vi.fn(),
  syncLifecycleProvider: vi.fn(),
  listLifecycleVendorRecords: vi.fn(),
  createLifecycleVendorRecord: vi.fn(),
  updateLifecycleVendorRecord: vi.fn(),
  deleteLifecycleVendorRecord: vi.fn(),
  importLifecycleVendorRecords: vi.fn(),
  exportLifecycleVendorRecords: vi.fn(),
}));

vi.mock('@/lib/api', () => api);

const provider = {
  provider_key: 'openeox',
  override_enabled: true,
  source: 'TENANT_OVERRIDE' as const,
  display_name: 'OpenEoX',
  provider_type: 'openeox',
  enabled: false,
  priority: 20,
  base_url: null,
  feed_urls: [],
  config: {},
  timeout_seconds: 10,
  max_retries: 0,
  circuit_breaker_enabled: true,
  cache_ttl: {
    known_days: null,
    unknown_hours: null,
    failure_minutes: null,
    deprecated_days: null,
  },
  health_status: 'disabled' as const,
  last_success_at: null,
  last_failure_at: null,
  last_failure_message: null,
  has_secret: false,
  secret_preview: null,
  updated_at: '2026-06-27T00:00:00Z',
};

function renderWithProviders(ui: React.ReactElement) {
  const client = new QueryClient({ defaultOptions: { queries: { retry: false }, mutations: { retry: false } } });
  return render(
    <QueryClientProvider client={client}>
      <ToastProvider>{ui}</ToastProvider>
    </QueryClientProvider>,
  );
}

describe('LifecycleProviderSettings', () => {
  it('inherited provider offers an explicit tenant override and configured credential marker', async () => {
    api.listLifecycleProviders.mockResolvedValue([{ ...provider, override_enabled: false, source: 'PLATFORM_DEFAULT', has_secret: true }]);
    renderWithProviders(<LifecycleProviderSettings tenantName="Olympus" />);
    expect(await screen.findByRole('button', { name: 'Override for Olympus' })).toBeInTheDocument();
    expect(screen.getByText('Credential managed by platform')).toBeInTheDocument();
    expect(screen.getByLabelText('Toggle OpenEoX')).toBeDisabled();
    expect(screen.queryByRole('button', { name: 'Reset to Platform Default' })).not.toBeInTheDocument();
  });

  it('reset uses the existing provider-specific override endpoint', async () => {
    api.resetLifecycleProviderOverride.mockResolvedValue(undefined);
    renderWithProviders(<LifecycleProviderSettings tenantName="Olympus" />);
    await userEvent.click(await screen.findByRole('button', { name: 'Reset to Platform Default' }));
    await waitFor(() => expect(api.resetLifecycleProviderOverride).toHaveBeenCalledWith('openeox', expect.anything()));
  });

  it('platform provider operations explicitly use platform scope', async () => {
    renderWithProviders(<LifecycleProviderSettings scope="platform" scopeKey="platform" />);
    await userEvent.click(await screen.findByRole('button', { name: 'Test' }));
    await waitFor(() => expect(api.testLifecycleProvider).toHaveBeenCalledWith('openeox', undefined, 'platform'));
    expect(screen.queryByRole('button', { name: 'Reset to Platform Default' })).not.toBeInTheDocument();
  });
  beforeEach(() => {
    vi.clearAllMocks();
    api.listLifecycleProviders.mockResolvedValue([provider]);
    api.updateLifecycleProvider.mockResolvedValue(provider);
    api.testLifecycleProvider.mockResolvedValue({
      success: true,
      status: 'healthy',
      latency_ms: 12,
      message: 'Provider responded',
      checked_at: '2026-06-27T00:00:01Z',
    });
    api.syncLifecycleProvider.mockResolvedValue({
      job_id: null,
      status: 'completed',
      message: 'Synced',
      triggered_at: '2026-06-27T00:00:02Z',
    });
  });

  it('renders configured providers', async () => {
    renderWithProviders(<LifecycleProviderSettings />);
    expect(await screen.findByText('OpenEoX')).toBeInTheDocument();
    expect(screen.getAllByText('openeox').length).toBeGreaterThan(0);
  });

  it('toggle enable calls the backend', async () => {
    renderWithProviders(<LifecycleProviderSettings />);
    const checkbox = await screen.findByLabelText('Toggle OpenEoX');
    await userEvent.click(checkbox);
    await waitFor(() => {
      expect(api.updateLifecycleProvider).toHaveBeenCalledWith('openeox', { enabled: true }, undefined, 'tenant');
    });
  });

  it('renders checked enabled provider with unknown health, not disabled', async () => {
    api.listLifecycleProviders.mockResolvedValue([
      {
        ...provider,
        provider_key: 'xeol_db',
        display_name: 'Local Xeol DB',
        provider_type: 'xeol_db',
        enabled: true,
        health_status: 'unknown',
      },
    ]);

    renderWithProviders(<LifecycleProviderSettings />);

    expect(await screen.findByLabelText('Toggle Local Xeol DB')).toBeChecked();
    expect(screen.getByText('Unknown')).toBeInTheDocument();
    expect(screen.queryByText('Disabled')).not.toBeInTheDocument();
  });

  it('treats null health as unknown', async () => {
    api.listLifecycleProviders.mockResolvedValue([
      {
        ...provider,
        enabled: true,
        health_status: null,
      },
    ]);

    renderWithProviders(<LifecycleProviderSettings />);

    expect(await screen.findByText('Unknown')).toBeInTheDocument();
  });

  it('failed provider update leaves checkbox on backend state', async () => {
    api.updateLifecycleProvider.mockRejectedValue(new Error('Save failed'));

    renderWithProviders(<LifecycleProviderSettings />);
    const checkbox = await screen.findByLabelText('Toggle OpenEoX');
    await userEvent.click(checkbox);

    await waitFor(() => expect(api.updateLifecycleProvider).toHaveBeenCalled());
    expect(checkbox).not.toBeChecked();
    expect(await screen.findByText('Provider configuration update failed.')).toBeInTheDocument();
  });

  it('successful update applies returned provider row and refetches', async () => {
    const updated = { ...provider, enabled: true, health_status: 'unknown' as const };
    api.listLifecycleProviders.mockResolvedValueOnce([provider]).mockResolvedValue([updated]);
    api.updateLifecycleProvider.mockResolvedValue(updated);

    renderWithProviders(<LifecycleProviderSettings />);
    await userEvent.click(await screen.findByLabelText('Toggle OpenEoX'));

    expect(await screen.findByText('Unknown')).toBeInTheDocument();
    await waitFor(() => expect(api.listLifecycleProviders).toHaveBeenCalledTimes(2));
  });

  it('test action shows provider health result', async () => {
    renderWithProviders(<LifecycleProviderSettings />);
    await userEvent.click(await screen.findByRole('button', { name: /test/i }));
    expect((await screen.findAllByText('Provider responded')).length).toBeGreaterThan(0);
  });

  it('test action refreshes row health and timestamps', async () => {
    const healthy = {
      ...provider,
      enabled: true,
      health_status: 'healthy' as const,
      last_success_at: '2026-06-27T00:00:01Z',
    };
    api.listLifecycleProviders.mockResolvedValueOnce([{ ...provider, enabled: true, health_status: 'unknown' }]).mockResolvedValue([
      healthy,
    ]);

    renderWithProviders(<LifecycleProviderSettings />);
    await userEvent.click(await screen.findByRole('button', { name: /test/i }));

    expect((await screen.findAllByText('Healthy')).length).toBeGreaterThan(0);
    await waitFor(() => expect(api.listLifecycleProviders).toHaveBeenCalledTimes(2));
  });

  it('sync action refreshes row health', async () => {
    const healthy = { ...provider, enabled: true, health_status: 'healthy' as const };
    api.listLifecycleProviders.mockResolvedValueOnce([{ ...provider, enabled: true, health_status: 'unknown' }]).mockResolvedValue([
      healthy,
    ]);

    renderWithProviders(<LifecycleProviderSettings />);
    await userEvent.click(await screen.findByRole('button', { name: /sync/i }));

    expect(await screen.findByText('Healthy')).toBeInTheDocument();
    await waitFor(() => expect(api.listLifecycleProviders).toHaveBeenCalledTimes(2));
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

vi.mock('@/hooks/useAuth', async () => ({ useAuth: (await import('@/test/authorizedAuth')).authorizedAuth }));


describe('Batch 6 persisted readiness synchronization', () => {
  function setup(overrides: Partial<typeof provider> = {}, props: React.ComponentProps<typeof LifecycleProviderSettings> = {}) {
    vi.clearAllMocks();
    const row = { ...provider, ...overrides };
    api.listLifecycleProviders.mockResolvedValue([row]);
    api.updateLifecycleProvider.mockResolvedValue(row);
    api.resetLifecycleProviderOverride.mockResolvedValue(undefined);
    api.testLifecycleProvider.mockResolvedValue({ success: true, status: 'healthy', message: 'Connected', checked_at: '2026-10-09', latency_ms: 1 });
    api.syncLifecycleProvider.mockResolvedValue({ status: 'completed', message: 'Finished', job_id: null });
    const qc = new QueryClient({ defaultOptions: { queries: { staleTime: 300_000, refetchOnWindowFocus: false, retry: false }, mutations: { retry: false } } });
    qc.setQueryData(['lifecycle-provider-status'], { overall_status: 'unknown' });
    qc.setQueryData(['lifecycle-providers', 'tenant:99'], [provider]);
    qc.setQueryData(['sbom-components-canonical', 5], 'existing evidence');
    const statusFetch = vi.fn().mockResolvedValue({ overall_status: 'healthy' });
    const off = new QueryObserver(qc, { queryKey: ['lifecycle-provider-status'], queryFn: statusFetch }).subscribe(() => {});
    const view = render(<QueryClientProvider client={qc}><ToastProvider><LifecycleProviderSettings scopeKey="tenant:1" {...props} /></ToastProvider></QueryClientProvider>);
    return { qc, statusFetch, cleanup: () => { view.unmount(); off(); qc.clear(); } };
  }
  it.each(['enable', 'disable', 'reset', 'test', 'sync'])('%s refetches authoritative status and preserves unrelated evidence/configuration', async action => {
    const h = setup({ enabled: action === 'disable' });
    const name = action === 'enable' || action === 'disable' ? 'Toggle OpenEoX' : action === 'reset' ? 'Reset to Platform Default' : action === 'test' ? 'Test' : 'Sync';
    await userEvent.click(await (name.startsWith('Toggle') ? screen.findByLabelText(name) : screen.findByRole('button', { name })));
    await waitFor(() => expect(h.statusFetch).toHaveBeenCalledTimes(1));
    expect(h.qc.getQueryData(['lifecycle-provider-status'])).toEqual({ overall_status: 'healthy' });
    expect(h.qc.getQueryState(['lifecycle-providers', 'tenant:99'])?.isInvalidated).toBe(false);
    expect(h.qc.getQueryState(['sbom-components-canonical', 5])?.isInvalidated).toBe(false);
    h.cleanup();
  });
  it.each(['save configuration', 'save secret', 'delete secret'])('%s refreshes readiness from the server without resetting unrelated form drafts', async action => {
    const h = setup({ provider_key: 'xeol_api', display_name: 'Xeol', has_secret: action === 'delete secret' });
    const secretResponse = (has_secret: boolean) => api.listLifecycleProviders.mockResolvedValue([{ ...provider, provider_key: 'xeol_api', display_name: 'Xeol', has_secret }]);
    api.setLifecycleProviderSecret.mockImplementation(async () => { secretResponse(true); return {}; });
    api.deleteLifecycleProviderSecret.mockImplementation(async () => { secretResponse(false); });
    await userEvent.click(await screen.findByRole('button', { name: 'Edit' }));
    const draft = screen.getByDisplayValue('20');
    await userEvent.clear(draft); await userEvent.type(draft, '27');
    if (action === 'delete secret') await userEvent.click(screen.getByRole('button', { name: 'Delete' }));
    else if (action === 'save secret') {
      await userEvent.type(document.querySelector('input[type="password"]')!, 'synthetic-test-secret');
      await userEvent.click(screen.getAllByRole('button', { name: 'Save' })[0]);
    } else await userEvent.click(screen.getAllByRole('button', { name: 'Save' })[1]);
    await waitFor(() => expect(h.statusFetch).toHaveBeenCalledTimes(1));
    expect(h.qc.getQueryData(['lifecycle-provider-status'])).toEqual({ overall_status: 'healthy' });
    if (action !== 'save configuration') {
      expect(draft).toHaveValue(27);
      if (action === 'save secret') expect(screen.getAllByText('Credential configured ✓')).toHaveLength(2);
      else expect(screen.getByText('No credential saved')).toBeInTheDocument();
    }
    h.cleanup();
  });
  it('failed form save retains the draft and does not invalidate readiness', async () => {
    const h = setup(); api.updateLifecycleProvider.mockRejectedValue(new Error('Denied'));
    await userEvent.click(await screen.findByRole('button', { name: 'Edit' }));
    await userEvent.click(screen.getByRole('button', { name: 'Save' }));
    expect(await screen.findByText('Provider configuration update failed.')).toBeInTheDocument();
    expect(screen.getByRole('button', { name: 'Save' })).toBeInTheDocument(); expect(h.statusFetch).not.toHaveBeenCalled(); h.cleanup();
  });
  it('failed HTTP mutations preserve cached readiness without false success', async () => {
    const h = setup(); api.updateLifecycleProvider.mockRejectedValue(new Error('Denied'));
    await userEvent.click(await screen.findByLabelText('Toggle OpenEoX'));
    expect(await screen.findByText('Provider configuration update failed.')).toBeInTheDocument();
    expect(h.statusFetch).not.toHaveBeenCalled(); expect(h.qc.getQueryData(['lifecycle-provider-status'])).toEqual({ overall_status: 'unknown' }); h.cleanup();
  });
  it('failed persisted probes refresh health but do not remove configuration', async () => {
    const h = setup({ enabled: true });
    api.testLifecycleProvider.mockResolvedValue({ success: false, status: 'degraded', message: 'Probe failed', checked_at: '2026-10-09', latency_ms: 1 });
    h.statusFetch.mockResolvedValue({ overall_status: 'degraded' });
    await userEvent.click(await screen.findByRole('button', { name: 'Test' }));
    await waitFor(() => expect(h.qc.getQueryData(['lifecycle-provider-status'])).toEqual({ overall_status: 'degraded' }));
    expect(api.updateLifecycleProvider).not.toHaveBeenCalled(); h.cleanup();
  });
  it('inherited connection tests are transient and do not refresh persisted readiness', async () => {
    const h = setup({ override_enabled: false });
    await userEvent.click(await screen.findByRole('button', { name: 'Test' }));
    expect((await screen.findAllByText('Connected')).length).toBeGreaterThan(0);
    expect(h.statusFetch).not.toHaveBeenCalled(); h.cleanup();
  });
  it('queued sync acknowledges submission without refreshing terminal readiness', async () => {
    const h = setup(); api.syncLifecycleProvider.mockResolvedValue({ status: 'queued', message: 'Queued', job_id: 'future-job' });
    await userEvent.click(await screen.findByRole('button', { name: 'Sync' }));
    expect(await screen.findByText('Queued')).toBeInTheDocument(); expect(h.statusFetch).not.toHaveBeenCalled(); h.cleanup();
  });
  it('permission-gated actions do not submit unauthorized mutations', async () => {
    const h = setup({}, { canUpdate: false, canTest: false, canSync: false });
    expect(await screen.findByLabelText('Toggle OpenEoX')).toBeDisabled();
    expect(screen.getByRole('button', { name: 'Test' })).toBeDisabled();
    expect(screen.getByRole('button', { name: 'Sync' })).toBeDisabled();
    expect(screen.queryByRole('button', { name: 'Edit' })).not.toBeInTheDocument();
    expect(api.updateLifecycleProvider).not.toHaveBeenCalled(); expect(h.statusFetch).not.toHaveBeenCalled(); h.cleanup();
  });
  it('in-flight mutations cannot restore provider data after tenant switching clears caches', async () => {
    setActiveTenantId('1'); const h = setup(); let finish!: (value: typeof provider) => void;
    api.updateLifecycleProvider.mockImplementation(() => new Promise(resolve => { finish = resolve; }));
    await userEvent.click(await screen.findByLabelText('Toggle OpenEoX'));
    await waitFor(() => expect(finish).toBeDefined()); setActiveTenantId('2'); h.qc.clear(); finish({ ...provider, enabled: true });
    await new Promise(resolve => setTimeout(resolve, 10));
    expect(h.statusFetch).not.toHaveBeenCalled();
    expect(h.qc.getQueryData(['lifecycle-provider-status'])).toBeUndefined();
    expect(h.qc.getQueryData<Array<typeof provider>>(['lifecycle-providers', 'tenant:1'])?.some(row => row.enabled)).not.toBe(true);
    h.cleanup(); clearActiveTenantId();
  });
  it('old callbacks cannot repopulate cleared caches after unmount', async () => {
    const h = setup(); let finish!: (value: typeof provider) => void;
    api.updateLifecycleProvider.mockImplementation(() => new Promise(resolve => { finish = resolve; }));
    await userEvent.click(await screen.findByLabelText('Toggle OpenEoX'));
    await waitFor(() => expect(finish).toBeDefined()); h.cleanup(); finish(provider);
    await new Promise(resolve => setTimeout(resolve, 10)); expect(h.qc.getQueryCache().getAll()).toHaveLength(0);
  });
});

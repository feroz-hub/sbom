// @vitest-environment jsdom

import { QueryClient, QueryClientProvider } from '@tanstack/react-query';
import { render, screen, waitFor } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { describe, expect, it, vi, beforeEach } from 'vitest';
import { ToastProvider } from '@/hooks/useToast';
import { LifecycleProviderSettings } from './LifecycleProviderSettings';
import { LifecycleVendorRecordsPage } from './LifecycleVendorRecordsPage';

const api = vi.hoisted(() => ({
  listLifecycleProviders: vi.fn(),
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
      expect(api.updateLifecycleProvider).toHaveBeenCalledWith('openeox', { enabled: true });
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
    expect(await screen.findByText('Save failed')).toBeInTheDocument();
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

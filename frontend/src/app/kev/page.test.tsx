// @vitest-environment jsdom

import { QueryClient, QueryClientProvider } from '@tanstack/react-query';
import { fireEvent, render, screen, waitFor } from '@testing-library/react';
import type { ReactNode } from 'react';
import { beforeEach, describe, expect, it, vi } from 'vitest';
import { ToastProvider } from '@/hooks/useToast';
import type { KevSyncResult, KevVulnerability } from '@/types';
import KevCatalogPage from './page';

const api = vi.hoisted(() => ({
  getKevVulnerability: vi.fn(),
  listKevVulnerabilities: vi.fn(),
  syncKevCatalog: vi.fn(),
}));

vi.mock('@/lib/api', () => api);

vi.mock('@/components/layout/TopBar', () => ({
  TopBar: ({ title, action }: { title: string; action?: ReactNode }) => (
    <header>
      <h1>{title}</h1>
      {action}
    </header>
  ),
}));

const kevRecord: KevVulnerability = {
  cve_id: 'CVE-2021-44228',
  vendor_project: 'Apache',
  product: 'Log4j',
  vulnerability_name: 'Apache Log4j2 Remote Code Execution',
  date_added: '2021-12-10',
  short_description: 'A remote code execution vulnerability in Log4j2.',
  required_action: 'Apply updates per vendor instructions.',
  due_date: '2021-12-24',
  known_ransomware_campaign_use: 'Known',
  notes: 'Review internet-facing systems first.',
  cwes: ['CWE-502'],
  catalog_version: '2026.07.17',
  catalog_date_released: '2026-07-17',
  refreshed_at: '2026-07-17T10:00:00Z',
  first_seen_at: '2021-12-10T00:00:00Z',
  updated_at: '2026-07-17T10:00:00Z',
};

const syncResult: KevSyncResult = {
  ok: true,
  catalog_version: '2026.07.17',
  catalog_date_released: '2026-07-17',
  total_in_feed: 1400,
  filtered_since: null,
  matched_after_filter: 1400,
  upserted: 1400,
  duration_seconds: 1.25,
};

function renderPage() {
  const client = new QueryClient({
    defaultOptions: {
      queries: { retry: false, gcTime: 0 },
      mutations: { retry: false },
    },
  });
  return render(
    <QueryClientProvider client={client}>
      <ToastProvider>
        <KevCatalogPage />
      </ToastProvider>
    </QueryClientProvider>,
  );
}

describe('CISA KEV catalog page', () => {
  beforeEach(() => {
    vi.clearAllMocks();
    api.listKevVulnerabilities.mockResolvedValue([kevRecord]);
    api.getKevVulnerability.mockResolvedValue(kevRecord);
    api.syncKevCatalog.mockResolvedValue(syncResult);
  });

  it('loads and renders catalog records', async () => {
    renderPage();

    expect(screen.getByRole('heading', { name: 'CISA KEV' })).toBeInTheDocument();
    expect(await screen.findByText('Apache Log4j2 Remote Code Execution')).toBeInTheDocument();
    expect(screen.getByText('Apache')).toBeInTheDocument();
    expect(api.listKevVulnerabilities).toHaveBeenCalledWith(
      { q: undefined, ransomware: undefined, limit: 50, offset: 0 },
      expect.any(AbortSignal),
    );
  });

  it('syncs the catalog and displays the returned summary', async () => {
    renderPage();
    fireEvent.click(screen.getByRole('button', { name: /Sync KEV Catalog/i }));

    await waitFor(() => expect(api.syncKevCatalog).toHaveBeenCalledTimes(1));
    expect(await screen.findByText('KEV catalog synced successfully')).toBeInTheDocument();
    expect(screen.getAllByText('1,400')).toHaveLength(3);
    expect(screen.getByText('1.25s')).toBeInTheDocument();
  });

  it('sends debounced catalog searches to the API', async () => {
    renderPage();
    await screen.findByText('Apache Log4j2 Remote Code Execution');

    fireEvent.change(screen.getByRole('searchbox', { name: 'Search KEV catalog' }), {
      target: { value: 'CVE-2021-44228' },
    });

    await waitFor(
      () =>
        expect(api.listKevVulnerabilities).toHaveBeenCalledWith(
          expect.objectContaining({ q: 'CVE-2021-44228', limit: 50, offset: 0 }),
          expect.any(AbortSignal),
        ),
      { timeout: 1200 },
    );
  });

  it('applies the ransomware-only API filter', async () => {
    renderPage();
    await screen.findByText('Apache Log4j2 Remote Code Execution');

    fireEvent.click(screen.getByRole('checkbox', { name: 'Ransomware only' }));

    await waitFor(() =>
      expect(api.listKevVulnerabilities).toHaveBeenCalledWith(
        expect.objectContaining({ ransomware: true, limit: 50, offset: 0 }),
        expect.any(AbortSignal),
      ),
    );
  });

  it('loads CVE details on demand', async () => {
    renderPage();
    const cve = await screen.findByRole('button', {
      name: 'Open KEV details for CVE-2021-44228',
    });
    fireEvent.click(cve);

    await waitFor(() =>
      expect(api.getKevVulnerability).toHaveBeenCalledWith(
        'CVE-2021-44228',
        expect.any(AbortSignal),
      ),
    );
    expect(await screen.findByText('A remote code execution vulnerability in Log4j2.')).toBeInTheDocument();
    expect(screen.getByText('CWE-502')).toBeInTheDocument();
  });
});

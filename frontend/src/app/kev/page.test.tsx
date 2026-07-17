// @vitest-environment jsdom

import { QueryClient, QueryClientProvider } from '@tanstack/react-query';
import { fireEvent, render, screen, waitFor, within } from '@testing-library/react';
import type { ReactNode } from 'react';
import { beforeEach, describe, expect, it, vi } from 'vitest';
import { ToastProvider } from '@/hooks/useToast';
import type {
  KevFilterOptions,
  KevListResponse,
  KevSyncResult,
  KevVulnerability,
} from '@/types';
import KevCatalogPage from './page';

const api = vi.hoisted(() => ({
  getKevFilterOptions: vi.fn(),
  getKevVulnerability: vi.fn(),
  listKevVulnerabilities: vi.fn(),
  syncKevCatalog: vi.fn(),
}));

const navigation = vi.hoisted(() => ({ replace: vi.fn(), search: '' }));

vi.mock('@/lib/api', () => api);
vi.mock('next/navigation', () => ({
  useRouter: () => ({ replace: navigation.replace }),
  useSearchParams: () => new URLSearchParams(navigation.search),
}));

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
  product: 'Log4j2',
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

const unknownRecord: KevVulnerability = {
  ...kevRecord,
  cve_id: 'CVE-2024-0002',
  vendor_project: 'Microsoft',
  product: 'Windows',
  vulnerability_name: 'Windows Security Feature Bypass',
  known_ransomware_campaign_use: 'Unknown',
};

const options: KevFilterOptions = {
  vendors: ['Apache', 'Microsoft'],
  products: ['Log4j2', 'Windows'],
  catalog_versions: ['2026.07.17'],
  cwes: ['CWE-502'],
  date_added_min: '2021-11-03',
  date_added_max: '2026-07-17',
};

const response: KevListResponse = {
  total: 1,
  limit: 50,
  offset: 0,
  items: [kevRecord],
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

async function waitForCatalog() {
  return screen.findByText('Apache Log4j2 Remote Code Execution');
}

describe('CISA KEV catalog page', () => {
  beforeEach(() => {
    vi.clearAllMocks();
    navigation.search = '';
    api.listKevVulnerabilities.mockResolvedValue(response);
    api.getKevFilterOptions.mockResolvedValue(options);
    api.getKevVulnerability.mockResolvedValue(kevRecord);
    api.syncKevCatalog.mockResolvedValue(syncResult);
  });

  it('loads the existing page with server sorting and pagination defaults', async () => {
    renderPage();

    expect(screen.getByRole('heading', { name: 'CISA KEV' })).toBeInTheDocument();
    await waitForCatalog();
    expect(api.listKevVulnerabilities).toHaveBeenCalledWith(
      expect.objectContaining({
        sort_by: 'date_added',
        sort_order: 'desc',
        limit: 50,
        offset: 0,
      }),
      expect.any(AbortSignal),
    );
    expect(api.getKevFilterOptions).toHaveBeenCalledWith(
      { vendor: undefined },
      expect.any(AbortSignal),
    );
    expect(screen.getByText('Showing', { exact: false })).toBeInTheDocument();
  });

  it('debounces general search and cancels the stale request signal', async () => {
    api.listKevVulnerabilities.mockImplementation((args: { q?: string }) => {
      if (args.q === 'Apache') return new Promise(() => undefined);
      return Promise.resolve(response);
    });
    renderPage();
    await waitForCatalog();

    fireEvent.change(screen.getByRole('searchbox', { name: 'Search KEV catalog' }), {
      target: { value: 'Apache' },
    });
    await waitFor(
      () => expect(api.listKevVulnerabilities).toHaveBeenCalledWith(
        expect.objectContaining({ q: 'Apache', offset: 0 }),
        expect.any(AbortSignal),
      ),
      { timeout: 1200 },
    );
    const apacheCall = api.listKevVulnerabilities.mock.calls.find(
      (call) => (call[0] as { q?: string }).q === 'Apache',
    );

    fireEvent.change(screen.getByRole('searchbox', { name: 'Search KEV catalog' }), {
      target: { value: 'CVE-2021-44228' },
    });
    await waitFor(
      () => expect(api.listKevVulnerabilities).toHaveBeenCalledWith(
        expect.objectContaining({ q: 'CVE-2021-44228', offset: 0 }),
        expect.any(AbortSignal),
      ),
      { timeout: 1200 },
    );
    expect((apacheCall?.[1] as AbortSignal).aborted).toBe(true);
  });

  it('sends vendor, product, known-ransomware, date, version, and CWE filters together', async () => {
    renderPage();
    await waitForCatalog();

    fireEvent.change(screen.getByLabelText('Vendor'), { target: { value: 'Apache' } });
    await waitFor(() => expect(api.getKevFilterOptions).toHaveBeenCalledWith(
      { vendor: 'Apache' },
      expect.any(AbortSignal),
    ));
    await waitFor(() => expect(screen.getByLabelText('Product')).not.toBeDisabled());
    fireEvent.change(screen.getByLabelText('Product'), { target: { value: 'Log4j2' } });
    fireEvent.change(screen.getByLabelText('Ransomware'), { target: { value: 'known' } });
    fireEvent.click(screen.getByRole('button', { name: /^Filters/ }));
    fireEvent.change(screen.getByLabelText('Date added from'), { target: { value: '2021-01-01' } });
    fireEvent.change(screen.getByLabelText('Date added to'), { target: { value: '2024-12-31' } });
    fireEvent.change(screen.getByLabelText('Due date from'), { target: { value: '2021-01-01' } });
    fireEvent.change(screen.getByLabelText('Due date to'), { target: { value: '2025-12-31' } });
    fireEvent.change(screen.getByLabelText('Catalog version'), { target: { value: '2026.07.17' } });
    fireEvent.change(screen.getByLabelText('CWE'), { target: { value: 'CWE-502' } });

    await waitFor(() => expect(api.listKevVulnerabilities).toHaveBeenCalledWith(
      expect.objectContaining({
        vendor: 'Apache',
        product: 'Log4j2',
        ransomware: 'known',
        date_added_from: '2021-01-01',
        date_added_to: '2024-12-31',
        due_date_from: '2021-01-01',
        due_date_to: '2025-12-31',
        catalog_version: '2026.07.17',
        cwe: 'CWE-502',
        offset: 0,
      }),
      expect.any(AbortSignal),
    ));
  });

  it('sends the exact not-known ransomware mode', async () => {
    renderPage();
    await waitForCatalog();

    fireEvent.change(screen.getByLabelText('Ransomware'), { target: { value: 'not-known' } });

    await waitFor(() => expect(api.listKevVulnerabilities).toHaveBeenCalledWith(
      expect.objectContaining({ ransomware: 'not-known', offset: 0 }),
      expect.any(AbortSignal),
    ));
  });

  it('changes allowlisted server sorting from table headers', async () => {
    renderPage();
    await waitForCatalog();

    fireEvent.click(screen.getByRole('button', { name: 'Sort by Vendor' }));
    await waitFor(() => expect(api.listKevVulnerabilities).toHaveBeenCalledWith(
      expect.objectContaining({ sort_by: 'vendor_project', sort_order: 'asc', offset: 0 }),
      expect.any(AbortSignal),
    ));

    fireEvent.click(screen.getByRole('button', { name: 'Sort by Vendor' }));
    await waitFor(() => expect(api.listKevVulnerabilities).toHaveBeenCalledWith(
      expect.objectContaining({ sort_by: 'vendor_project', sort_order: 'desc', offset: 0 }),
      expect.any(AbortSignal),
    ));
  });

  it('paginates by the filtered total and resets to page one after a filter change', async () => {
    api.listKevVulnerabilities.mockResolvedValue({ ...response, total: 120 });
    renderPage();
    await waitForCatalog();

    fireEvent.click(screen.getByRole('button', { name: '2' }));
    await waitFor(() => expect(api.listKevVulnerabilities).toHaveBeenCalledWith(
      expect.objectContaining({ limit: 50, offset: 50 }),
      expect.any(AbortSignal),
    ));

    fireEvent.change(screen.getByLabelText('Vendor'), { target: { value: 'Apache' } });
    await waitFor(() => expect(api.listKevVulnerabilities).toHaveBeenCalledWith(
      expect.objectContaining({ vendor: 'Apache', offset: 0 }),
      expect.any(AbortSignal),
    ));
  });

  it('clears every filter, custom sort, page, and page size', async () => {
    api.listKevVulnerabilities.mockResolvedValue({ ...response, total: 120 });
    renderPage();
    await waitForCatalog();

    fireEvent.change(screen.getByLabelText('Vendor'), { target: { value: 'Apache' } });
    fireEvent.change(screen.getByLabelText('Ransomware'), { target: { value: 'known' } });
    fireEvent.click(screen.getByRole('button', { name: 'Sort by Vendor' }));
    fireEvent.change(screen.getByLabelText('Rows per page'), { target: { value: '25' } });
    fireEvent.click(screen.getByRole('button', { name: /Clear filters/i }));

    expect(screen.getByLabelText('Vendor')).toHaveValue('');
    expect(screen.getByLabelText('Ransomware')).toHaveValue('all');
    expect(screen.getByLabelText('Rows per page')).toHaveValue('50');
    await waitFor(() => expect(api.listKevVulnerabilities).toHaveBeenCalledWith(
      expect.objectContaining({
        vendor: undefined,
        ransomware: undefined,
        sort_by: 'date_added',
        sort_order: 'desc',
        limit: 50,
        offset: 0,
      }),
      expect.any(AbortSignal),
    ));
  });

  it('shows loading and both catalog empty states', async () => {
    let resolveRequest!: (value: KevListResponse) => void;
    api.listKevVulnerabilities.mockReturnValue(new Promise((resolve) => { resolveRequest = resolve; }));
    renderPage();
    expect(await screen.findByText('Loading KEV catalog results')).toBeInTheDocument();
    resolveRequest({ ...response, total: 0, items: [] });
    expect(await screen.findByText('The CISA KEV catalog has not been synchronized yet.')).toBeInTheDocument();

    fireEvent.change(screen.getByRole('searchbox', { name: 'Search KEV catalog' }), {
      target: { value: 'no-match' },
    });
    await waitFor(
      () => expect(screen.getByText('No KEV entries match the selected filters.')).toBeInTheDocument(),
      { timeout: 1200 },
    );
  });

  it('shows a ransomware badge only for exact known status', async () => {
    api.listKevVulnerabilities.mockResolvedValue({
      ...response,
      total: 2,
      items: [kevRecord, unknownRecord],
    });
    renderPage();
    await screen.findByText('Windows Security Feature Bypass');

    const table = within(screen.getByRole('region', { name: 'CISA Known Exploited Vulnerabilities' }));
    expect(table.getAllByText('Known ransomware use')).toHaveLength(1);
    const unknownRow = screen.getByText('Windows Security Feature Bypass').closest('tr');
    expect(within(unknownRow!).getByText('Unknown')).toBeInTheDocument();
    expect(within(unknownRow!).queryByText('Known ransomware use')).not.toBeInTheDocument();
  });

  it('persists filter state in the KEV page URL', async () => {
    renderPage();
    await waitForCatalog();
    fireEvent.change(screen.getByLabelText('Vendor'), { target: { value: 'Apache' } });
    fireEvent.change(screen.getByLabelText('Ransomware'), { target: { value: 'known' } });

    await waitFor(() => expect(navigation.replace).toHaveBeenCalledWith(
      expect.stringContaining('/kev?vendor=Apache&ransomware=known'),
      { scroll: false },
    ));
  });

  it('syncs and refreshes both the filtered table and filter metadata', async () => {
    renderPage();
    await waitForCatalog();
    const listCalls = api.listKevVulnerabilities.mock.calls.length;
    const optionCalls = api.getKevFilterOptions.mock.calls.length;

    fireEvent.click(screen.getByRole('button', { name: /Sync KEV Catalog/i }));

    await waitFor(() => expect(api.syncKevCatalog).toHaveBeenCalledTimes(1));
    expect(await screen.findByText('KEV catalog synced successfully')).toBeInTheDocument();
    await waitFor(() => expect(api.listKevVulnerabilities.mock.calls.length).toBeGreaterThan(listCalls));
    await waitFor(() => expect(api.getKevFilterOptions.mock.calls.length).toBeGreaterThan(optionCalls));
    expect(screen.getAllByText('1,400')).toHaveLength(3);
  });

  it('loads full CVE details on demand', async () => {
    renderPage();
    const cve = await screen.findByRole('button', { name: 'Open KEV details for CVE-2021-44228' });
    fireEvent.click(cve);

    await waitFor(() => expect(api.getKevVulnerability).toHaveBeenCalledWith(
      'CVE-2021-44228',
      expect.any(AbortSignal),
    ));
    expect(await screen.findByText('A remote code execution vulnerability in Log4j2.')).toBeInTheDocument();
    expect(screen.getByText('CWE-502')).toBeInTheDocument();
  });
});

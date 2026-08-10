'use client';

import { Suspense, useEffect, useMemo, useState } from 'react';
import { keepPreviousData, useMutation, useQuery, useQueryClient } from '@tanstack/react-query';
import { RefreshCw, ShieldAlert, SlidersHorizontal } from 'lucide-react';
import { useRouter, useSearchParams } from 'next/navigation';
import { TopBar } from '@/components/layout/TopBar';
import { Alert } from '@/components/ui/Alert';
import { Badge } from '@/components/ui/Badge';
import { Button } from '@/components/ui/Button';
import { Card } from '@/components/ui/Card';
import { Dialog, DialogBody } from '@/components/ui/Dialog';
import { Input } from '@/components/ui/Input';
import { Pagination } from '@/components/ui/Pagination';
import { Select } from '@/components/ui/Select';
import { SkeletonRow } from '@/components/ui/Spinner';
import { EmptyRow, SortableTh, Table, TableBody, TableHead, Td, Th } from '@/components/ui/Table';
import { TableFilterBar, TableSearchInput } from '@/components/ui/TableFilterBar';
import { useToast } from '@/hooks/useToast';
import {
  getKevFilterOptions,
  getKevVulnerability,
  listKevVulnerabilities,
  syncKevCatalog,
} from '@/lib/api';
import { formatDate } from '@/lib/utils';
import type {
  KevRansomwareFilter,
  KevSortField,
  KevSortOrder,
  KevSyncResult,
  KevVulnerability,
} from '@/types';

const DEFAULT_PAGE_SIZE = 50;
const PAGE_SIZE_OPTIONS = [25, 50, 100, 250, 500];
const SORT_FIELDS: KevSortField[] = [
  'cve_id',
  'vendor_project',
  'product',
  'vulnerability_name',
  'date_added',
  'due_date',
  'known_ransomware_campaign_use',
  'catalog_version',
  'updated_at',
];

type KevFilters = {
  search: string;
  vendor: string;
  product: string;
  ransomware: 'all' | KevRansomwareFilter;
  dateAddedFrom: string;
  dateAddedTo: string;
  dueDateFrom: string;
  dueDateTo: string;
  catalogVersion: string;
  cwe: string;
  sortBy: KevSortField;
  sortOrder: KevSortOrder;
};

const DEFAULT_FILTERS: KevFilters = {
  search: '',
  vendor: '',
  product: '',
  ransomware: 'all',
  dateAddedFrom: '',
  dateAddedTo: '',
  dueDateFrom: '',
  dueDateTo: '',
  catalogVersion: '',
  cwe: '',
  sortBy: 'date_added',
  sortOrder: 'desc',
};

function isKnownRansomware(value: string | null | undefined): boolean {
  return value?.trim().toLowerCase() === 'known';
}

function formatCatalogDate(value: string | null | undefined): string {
  if (!value) return '—';
  const dateOnly = /^\d{4}-\d{2}-\d{2}$/.test(value);
  try {
    return new Intl.DateTimeFormat('en-US', {
      year: 'numeric',
      month: 'short',
      day: 'numeric',
    }).format(new Date(dateOnly ? `${value}T00:00:00` : value));
  } catch {
    return value;
  }
}

function errorMessage(error: unknown, fallback: string): string {
  if (error instanceof Error && error.message) return `${fallback}: ${error.message}`;
  return fallback;
}

function positiveInteger(value: string | null, fallback: number, maximum?: number): number {
  const parsed = Number(value);
  if (!Number.isInteger(parsed) || parsed < 1 || (maximum !== undefined && parsed > maximum)) {
    return fallback;
  }
  return parsed;
}

function initialState(searchParams: URLSearchParams | Readonly<URLSearchParams>) {
  const sortBy = searchParams.get('sort_by');
  const sortOrder = searchParams.get('sort_order');
  const ransomware = searchParams.get('ransomware');
  const filters: KevFilters = {
    search: searchParams.get('q')?.trim() ?? '',
    vendor: searchParams.get('vendor')?.trim() ?? '',
    product: searchParams.get('product')?.trim() ?? '',
    ransomware: ransomware === 'known' || ransomware === 'not-known' ? ransomware : 'all',
    dateAddedFrom: searchParams.get('date_added_from') ?? '',
    dateAddedTo: searchParams.get('date_added_to') ?? '',
    dueDateFrom: searchParams.get('due_date_from') ?? '',
    dueDateTo: searchParams.get('due_date_to') ?? '',
    catalogVersion: searchParams.get('catalog_version')?.trim() ?? '',
    cwe: searchParams.get('cwe')?.trim() ?? '',
    sortBy: SORT_FIELDS.includes(sortBy as KevSortField) ? (sortBy as KevSortField) : 'date_added',
    sortOrder: sortOrder === 'asc' || sortOrder === 'desc' ? sortOrder : 'desc',
  };
  return {
    filters,
    page: positiveInteger(searchParams.get('page'), 1),
    pageSize: positiveInteger(searchParams.get('limit'), DEFAULT_PAGE_SIZE, 500),
  };
}

export default function KevCatalogPage() {
  return (
    <Suspense fallback={<p className="p-6 text-sm text-hcl-muted">Loading KEV catalog...</p>}>
      <KevCatalogContent />
    </Suspense>
  );
}

function KevCatalogContent() {
  const router = useRouter();
  const searchParams = useSearchParams();
  const queryClient = useQueryClient();
  const { showToast } = useToast();
  const [initial] = useState(() => initialState(searchParams)); // URL is the initial source of truth.
  const [filters, setFilters] = useState<KevFilters>(initial.filters);
  const [searchInput, setSearchInput] = useState(initial.filters.search);
  const [page, setPage] = useState(initial.page);
  const [pageSize, setPageSize] = useState(initial.pageSize);
  const [advancedOpen, setAdvancedOpen] = useState(
    Boolean(
      initial.filters.dateAddedFrom ||
        initial.filters.dateAddedTo ||
        initial.filters.dueDateFrom ||
        initial.filters.dueDateTo ||
        initial.filters.catalogVersion ||
        initial.filters.cwe,
    ),
  );
  const [selectedCve, setSelectedCve] = useState<string | null>(null);
  const [lastSync, setLastSync] = useState<KevSyncResult | null>(null);

  useEffect(() => {
    const timer = window.setTimeout(() => {
      const search = searchInput.trim();
      setFilters((current) => (current.search === search ? current : { ...current, search }));
      setPage(1);
    }, 350);
    return () => window.clearTimeout(timer);
  }, [searchInput]);

  useEffect(() => {
    const params = new URLSearchParams();
    if (filters.search) params.set('q', filters.search);
    if (filters.vendor) params.set('vendor', filters.vendor);
    if (filters.product) params.set('product', filters.product);
    if (filters.ransomware !== 'all') params.set('ransomware', filters.ransomware);
    if (filters.dateAddedFrom) params.set('date_added_from', filters.dateAddedFrom);
    if (filters.dateAddedTo) params.set('date_added_to', filters.dateAddedTo);
    if (filters.dueDateFrom) params.set('due_date_from', filters.dueDateFrom);
    if (filters.dueDateTo) params.set('due_date_to', filters.dueDateTo);
    if (filters.catalogVersion) params.set('catalog_version', filters.catalogVersion);
    if (filters.cwe) params.set('cwe', filters.cwe);
    if (filters.sortBy !== DEFAULT_FILTERS.sortBy) params.set('sort_by', filters.sortBy);
    if (filters.sortOrder !== DEFAULT_FILTERS.sortOrder) params.set('sort_order', filters.sortOrder);
    if (page !== 1) params.set('page', String(page));
    if (pageSize !== DEFAULT_PAGE_SIZE) params.set('limit', String(pageSize));
    const query = params.toString();
    router.replace(query ? `/kev?${query}` : '/kev', { scroll: false });
  }, [filters, page, pageSize, router]);

  const dateRangeError = useMemo(() => {
    if (filters.dateAddedFrom && filters.dateAddedTo && filters.dateAddedFrom > filters.dateAddedTo) {
      return 'Date added from must be on or before Date added to.';
    }
    if (filters.dueDateFrom && filters.dueDateTo && filters.dueDateFrom > filters.dueDateTo) {
      return 'Due date from must be on or before Due date to.';
    }
    return null;
  }, [filters.dateAddedFrom, filters.dateAddedTo, filters.dueDateFrom, filters.dueDateTo]);

  const offset = (page - 1) * pageSize;
  const catalogQuery = useQuery({
    queryKey: ['kev-catalog', filters, page, pageSize],
    queryFn: ({ signal }) =>
      listKevVulnerabilities(
        {
          q: filters.search || undefined,
          vendor: filters.vendor || undefined,
          product: filters.product || undefined,
          ransomware: filters.ransomware === 'all' ? undefined : filters.ransomware,
          date_added_from: filters.dateAddedFrom || undefined,
          date_added_to: filters.dateAddedTo || undefined,
          due_date_from: filters.dueDateFrom || undefined,
          due_date_to: filters.dueDateTo || undefined,
          catalog_version: filters.catalogVersion || undefined,
          cwe: filters.cwe || undefined,
          sort_by: filters.sortBy,
          sort_order: filters.sortOrder,
          limit: pageSize,
          offset,
        },
        signal,
      ),
    placeholderData: keepPreviousData,
    enabled: dateRangeError === null,
  });

  const optionsQuery = useQuery({
    queryKey: ['kev-filter-options', filters.vendor],
    queryFn: ({ signal }) => getKevFilterOptions({ vendor: filters.vendor || undefined }, signal),
  });

  const detailQuery = useQuery({
    queryKey: ['kev-detail', selectedCve],
    queryFn: ({ signal }) => getKevVulnerability(selectedCve!, signal),
    enabled: selectedCve !== null,
  });

  const syncMutation = useMutation({
    mutationFn: () => syncKevCatalog(),
    onSuccess: (result) => {
      setLastSync(result);
      setPage(1);
      queryClient.invalidateQueries({ queryKey: ['kev-catalog'] });
      queryClient.invalidateQueries({ queryKey: ['kev-filter-options'] });
      queryClient.invalidateQueries({ queryKey: ['kev-detail'] });
      showToast('KEV catalog synced successfully', 'success');
    },
    onError: (error) => showToast(errorMessage(error, 'KEV sync failed'), 'error'),
  });

  const rows = catalogQuery.data?.items ?? [];
  const total = catalogQuery.data?.total ?? 0;
  const totalPages = Math.max(1, Math.ceil(total / pageSize));
  const rangeStart = rows.length ? offset + 1 : 0;
  const rangeEnd = rows.length ? offset + rows.length : 0;

  useEffect(() => {
    if (page > totalPages && catalogQuery.data) setPage(totalPages);
  }, [catalogQuery.data, page, totalPages]);

  const activeFilterCount = [
    searchInput.trim(),
    filters.vendor,
    filters.product,
    filters.ransomware === 'all' ? '' : filters.ransomware,
    filters.dateAddedFrom,
    filters.dateAddedTo,
    filters.dueDateFrom,
    filters.dueDateTo,
    filters.catalogVersion,
    filters.cwe,
  ].filter(Boolean).length;
  const hasNonDefaultState =
    activeFilterCount > 0 ||
    filters.sortBy !== DEFAULT_FILTERS.sortBy ||
    filters.sortOrder !== DEFAULT_FILTERS.sortOrder ||
    page !== 1 ||
    pageSize !== DEFAULT_PAGE_SIZE;

  function updateFilter<K extends keyof KevFilters>(key: K, value: KevFilters[K]) {
    setFilters((current) => ({ ...current, [key]: value }));
    setPage(1);
  }

  function clearFilters() {
    setSearchInput('');
    setFilters(DEFAULT_FILTERS);
    setPage(1);
    setPageSize(DEFAULT_PAGE_SIZE);
  }

  function toggleSort(key: string) {
    const sortBy = key as KevSortField;
    setFilters((current) => ({
      ...current,
      sortBy,
      sortOrder: current.sortBy === sortBy && current.sortOrder === 'asc' ? 'desc' : 'asc',
    }));
    setPage(1);
  }

  return (
    <div className="flex flex-1 flex-col">
      <TopBar
        title="CISA KEV"
        subtitle="Known Exploited Vulnerabilities catalog"
        action={
          <Button
            onClick={() => syncMutation.mutate()}
            loading={syncMutation.isPending}
            loadingLabel="Syncing KEV catalog"
          >
            {!syncMutation.isPending ? <RefreshCw className="h-4 w-4" aria-hidden /> : null}
            <span>{syncMutation.isPending ? 'Syncing...' : 'Sync KEV Catalog'}</span>
          </Button>
        }
      />

      <main className="mx-auto w-full max-w-[96rem] space-y-4 px-4 py-6 md:px-6">
        {lastSync ? <SyncSummary result={lastSync} /> : null}

        {dateRangeError ? (
          <Alert variant="error" title="Invalid date range">{dateRangeError}</Alert>
        ) : catalogQuery.error ? (
          <Alert variant="error" title="Could not load the KEV catalog">
            {errorMessage(catalogQuery.error, 'Request failed')}
          </Alert>
        ) : null}

        <Card className="overflow-hidden">
          <TableFilterBar
            onClear={clearFilters}
            clearDisabled={!hasNonDefaultState}
            resultHint={`${total.toLocaleString()} matching entr${total === 1 ? 'y' : 'ies'}`}
          >
            <TableSearchInput
              id="kev-search"
              value={searchInput}
              onChange={setSearchInput}
              label="Search KEV catalog"
              placeholder="Search CVE, vendor, product, vulnerability..."
            />
            <Select
              id="kev-vendor"
              label="Vendor"
              value={filters.vendor}
              disabled={optionsQuery.isLoading}
              onChange={(event) => {
                setFilters((current) => ({ ...current, vendor: event.target.value, product: '' }));
                setPage(1);
              }}
              className="min-w-44"
            >
              <option value="">All vendors</option>
              {(optionsQuery.data?.vendors ?? []).map((vendor) => <option key={vendor} value={vendor}>{vendor}</option>)}
            </Select>
            <Select
              id="kev-product"
              label="Product"
              value={filters.product}
              disabled={optionsQuery.isLoading}
              onChange={(event) => updateFilter('product', event.target.value)}
              className="min-w-44"
            >
              <option value="">All products</option>
              {(optionsQuery.data?.products ?? []).map((product) => <option key={product} value={product}>{product}</option>)}
            </Select>
            <Select
              id="kev-ransomware"
              label="Ransomware"
              value={filters.ransomware}
              onChange={(event) => updateFilter('ransomware', event.target.value as KevFilters['ransomware'])}
              className="min-w-52"
            >
              <option value="all">All entries</option>
              <option value="known">Known ransomware use</option>
              <option value="not-known">No known ransomware use</option>
            </Select>
            <Button
              variant="secondary"
              onClick={() => setAdvancedOpen((open) => !open)}
              aria-expanded={advancedOpen}
              aria-controls="kev-advanced-filters"
            >
              <SlidersHorizontal className="h-4 w-4" aria-hidden />
              Filters{activeFilterCount > 0 ? ` (${activeFilterCount})` : ''}
            </Button>
          </TableFilterBar>

          {advancedOpen ? (
            <div id="kev-advanced-filters" className="grid gap-3 border-b border-border bg-surface px-4 py-4 sm:grid-cols-2 lg:grid-cols-4 xl:grid-cols-6">
              <Input id="kev-date-added-from" type="date" label="Date added from" value={filters.dateAddedFrom} max={filters.dateAddedTo || optionsQuery.data?.date_added_max || undefined} onChange={(event) => updateFilter('dateAddedFrom', event.target.value)} />
              <Input id="kev-date-added-to" type="date" label="Date added to" value={filters.dateAddedTo} min={filters.dateAddedFrom || optionsQuery.data?.date_added_min || undefined} onChange={(event) => updateFilter('dateAddedTo', event.target.value)} />
              <Input id="kev-due-date-from" type="date" label="Due date from" value={filters.dueDateFrom} max={filters.dueDateTo || undefined} onChange={(event) => updateFilter('dueDateFrom', event.target.value)} />
              <Input id="kev-due-date-to" type="date" label="Due date to" value={filters.dueDateTo} min={filters.dueDateFrom || undefined} onChange={(event) => updateFilter('dueDateTo', event.target.value)} />
              <Select id="kev-catalog-version" label="Catalog version" value={filters.catalogVersion} onChange={(event) => updateFilter('catalogVersion', event.target.value)}>
                <option value="">All versions</option>
                {(optionsQuery.data?.catalog_versions ?? []).map((version) => <option key={version} value={version}>{version}</option>)}
              </Select>
              <Select id="kev-cwe" label="CWE" value={filters.cwe} onChange={(event) => updateFilter('cwe', event.target.value)}>
                <option value="">All CWEs</option>
                {(optionsQuery.data?.cwes ?? []).map((cwe) => <option key={cwe} value={cwe}>{cwe}</option>)}
              </Select>
            </div>
          ) : null}

          <p className="sr-only" aria-live="polite">
            {catalogQuery.isLoading
              ? 'Loading KEV catalog results'
              : catalogQuery.isFetching
                ? 'Updating KEV catalog results'
                : `${total} KEV catalog results`}
          </p>

          <Table ariaLabel="CISA Known Exploited Vulnerabilities" striped>
            <TableHead>
              <tr>
                <SortableTh sortKey="cve_id" activeKey={filters.sortBy} direction={filters.sortOrder} onToggle={toggleSort}>CVE ID</SortableTh>
                <SortableTh sortKey="vendor_project" activeKey={filters.sortBy} direction={filters.sortOrder} onToggle={toggleSort}>Vendor</SortableTh>
                <SortableTh sortKey="product" activeKey={filters.sortBy} direction={filters.sortOrder} onToggle={toggleSort}>Product</SortableTh>
                <SortableTh sortKey="vulnerability_name" activeKey={filters.sortBy} direction={filters.sortOrder} onToggle={toggleSort}>Vulnerability</SortableTh>
                <SortableTh sortKey="date_added" activeKey={filters.sortBy} direction={filters.sortOrder} onToggle={toggleSort}>Date Added</SortableTh>
                <SortableTh sortKey="due_date" activeKey={filters.sortBy} direction={filters.sortOrder} onToggle={toggleSort}>Due Date</SortableTh>
                <SortableTh sortKey="known_ransomware_campaign_use" activeKey={filters.sortBy} direction={filters.sortOrder} onToggle={toggleSort}>Ransomware</SortableTh>
                <Th className="min-w-72">Required Action</Th>
                <SortableTh sortKey="catalog_version" activeKey={filters.sortBy} direction={filters.sortOrder} onToggle={toggleSort}>Catalog Version</SortableTh>
              </tr>
            </TableHead>
            <TableBody>
              {catalogQuery.isLoading ? (
                Array.from({ length: 8 }, (_, index) => <SkeletonRow key={index} cols={9} />)
              ) : rows.length === 0 ? (
                <EmptyRow
                  cols={9}
                  message={
                    catalogQuery.error
                      ? 'KEV catalog data is unavailable.'
                      : activeFilterCount > 0
                      ? 'No KEV entries match the selected filters.'
                      : 'The CISA KEV catalog has not been synchronized yet.'
                  }
                  action={!catalogQuery.error && activeFilterCount > 0 ? <Button variant="secondary" size="sm" onClick={clearFilters}>Clear filters</Button> : undefined}
                />
              ) : (
                rows.map((row) => <KevRow key={row.cve_id} row={row} onOpen={() => setSelectedCve(row.cve_id)} />)
              )}
            </TableBody>
          </Table>

          <Pagination
            page={page}
            pageSize={pageSize}
            total={total}
            totalPages={totalPages}
            rangeStart={rangeStart}
            rangeEnd={rangeEnd}
            hasPrev={page > 1}
            hasNext={page < totalPages}
            onPageChange={setPage}
            onPageSizeChange={(size) => { setPageSize(size); setPage(1); }}
            pageSizeOptions={PAGE_SIZE_OPTIONS}
            itemNoun="entry"
          />
        </Card>
      </main>

      <Dialog open={selectedCve !== null} onClose={() => setSelectedCve(null)} title={selectedCve ?? 'KEV detail'} maxWidth="xl">
        <DialogBody>
          {detailQuery.isLoading ? (
            <p className="py-8 text-center text-sm text-hcl-muted">Loading KEV details...</p>
          ) : detailQuery.error ? (
            <Alert variant="error" title="Could not load KEV details">{errorMessage(detailQuery.error, 'Request failed')}</Alert>
          ) : detailQuery.data ? (
            <KevDetail entry={detailQuery.data} />
          ) : null}
        </DialogBody>
      </Dialog>
    </div>
  );
}

function KevRow({ row, onOpen }: { row: KevVulnerability; onOpen: () => void }) {
  const ransomware = isKnownRansomware(row.known_ransomware_campaign_use);
  return (
    <tr>
      <Td>
        <button type="button" onClick={onOpen} className="rounded font-mono text-xs font-semibold text-hcl-blue hover:underline focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-primary/40" aria-label={`Open KEV details for ${row.cve_id}`}>
          {row.cve_id}
        </button>
      </Td>
      <Td className="font-medium">{row.vendor_project ?? '—'}</Td>
      <Td>{row.product ?? '—'}</Td>
      <Td className="max-w-80"><span className="block truncate" title={row.vulnerability_name ?? undefined}>{row.vulnerability_name ?? '—'}</span></Td>
      <Td className="whitespace-nowrap">{formatCatalogDate(row.date_added)}</Td>
      <Td className="whitespace-nowrap">{formatCatalogDate(row.due_date)}</Td>
      <Td>
        {ransomware ? <Badge variant="error">Known ransomware use</Badge> : <span className="text-xs text-hcl-muted">{row.known_ransomware_campaign_use?.trim() || '—'}</span>}
      </Td>
      <Td className="max-w-lg"><span className="block truncate text-sm" title={row.required_action ?? undefined}>{row.required_action ?? '—'}</span></Td>
      <Td className="whitespace-nowrap">{row.catalog_version ?? '—'}</Td>
    </tr>
  );
}

function SyncSummary({ result }: { result: KevSyncResult }) {
  const values = [
    ['Feed records', result.total_in_feed.toLocaleString()],
    ['Matched', result.matched_after_filter.toLocaleString()],
    ['Upserted', result.upserted.toLocaleString()],
    ['Duration', `${result.duration_seconds.toFixed(2)}s`],
    ['Catalog version', result.catalog_version ?? '—'],
    ['Released', formatCatalogDate(result.catalog_date_released)],
  ];
  return (
    <section aria-label="Latest KEV sync" className="border-y border-border bg-surface px-4 py-4 md:px-6">
      <div className="grid gap-4 sm:grid-cols-2 lg:grid-cols-6">
        {values.map(([label, value]) => (
          <div key={label} className="min-w-0">
            <p className="text-xs font-medium text-hcl-muted">{label}</p>
            <p className="mt-1 truncate text-sm font-semibold tabular-nums text-hcl-navy" title={value}>{value}</p>
          </div>
        ))}
      </div>
    </section>
  );
}

function KevDetail({ entry }: { entry: KevVulnerability }) {
  const ransomware = isKnownRansomware(entry.known_ransomware_campaign_use);
  return (
    <div className="space-y-5 text-sm">
      <div className="flex flex-wrap items-center gap-2">
        <Badge variant="error">CISA KEV</Badge>
        {ransomware ? <Badge variant="error"><ShieldAlert className="mr-1 h-3.5 w-3.5" aria-hidden />Known ransomware use</Badge> : null}
      </div>
      <dl className="grid gap-x-6 gap-y-4 sm:grid-cols-2">
        <DetailItem label="CVE ID" value={entry.cve_id} mono />
        <DetailItem label="Vendor Project" value={entry.vendor_project} />
        <DetailItem label="Product" value={entry.product} />
        <DetailItem label="Date Added" value={formatCatalogDate(entry.date_added)} />
        <DetailItem label="Due Date" value={formatCatalogDate(entry.due_date)} />
        <DetailItem label="Known Ransomware Campaign Use" value={entry.known_ransomware_campaign_use} />
        <DetailItem label="Catalog Version" value={entry.catalog_version} />
        <DetailItem label="Updated At" value={formatDate(entry.updated_at)} />
        <DetailItem label="CWEs" value={entry.cwes.length ? entry.cwes.join(', ') : null} />
      </dl>
      <DetailBlock label="Short Description" value={entry.short_description} />
      <DetailBlock label="Required Action" value={entry.required_action} />
      <DetailBlock label="Notes" value={entry.notes} />
    </div>
  );
}

function DetailItem({ label, value, mono = false }: { label: string; value: string | null; mono?: boolean }) {
  return (
    <div className="min-w-0">
      <dt className="text-xs font-medium text-hcl-muted">{label}</dt>
      <dd className={`mt-1 break-words text-foreground ${mono ? 'font-mono font-semibold' : ''}`}>{value || '—'}</dd>
    </div>
  );
}

function DetailBlock({ label, value }: { label: string; value: string | null }) {
  return (
    <div>
      <h3 className="text-xs font-medium text-hcl-muted">{label}</h3>
      <p className="mt-1 whitespace-pre-wrap leading-relaxed text-foreground">{value || '—'}</p>
    </div>
  );
}

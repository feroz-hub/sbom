'use client';

import { useEffect, useState } from 'react';
import { keepPreviousData, useMutation, useQuery, useQueryClient } from '@tanstack/react-query';
import { ChevronLeft, ChevronRight, RefreshCw, ShieldAlert } from 'lucide-react';
import { TopBar } from '@/components/layout/TopBar';
import { Alert } from '@/components/ui/Alert';
import { Badge } from '@/components/ui/Badge';
import { Button } from '@/components/ui/Button';
import { Card } from '@/components/ui/Card';
import { Dialog, DialogBody } from '@/components/ui/Dialog';
import { SkeletonRow } from '@/components/ui/Spinner';
import { Table, TableBody, TableHead, Td, Th, EmptyRow } from '@/components/ui/Table';
import { TableFilterBar, TableSearchInput } from '@/components/ui/TableFilterBar';
import { useToast } from '@/hooks/useToast';
import {
  getKevVulnerability,
  listKevVulnerabilities,
  syncKevCatalog,
} from '@/lib/api';
import { formatDate } from '@/lib/utils';
import type { KevSyncResult, KevVulnerability } from '@/types';

const PAGE_SIZE = 50;

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

export default function KevCatalogPage() {
  const queryClient = useQueryClient();
  const { showToast } = useToast();
  const [searchInput, setSearchInput] = useState('');
  const [search, setSearch] = useState('');
  const [ransomwareOnly, setRansomwareOnly] = useState(false);
  const [offset, setOffset] = useState(0);
  const [selectedCve, setSelectedCve] = useState<string | null>(null);
  const [lastSync, setLastSync] = useState<KevSyncResult | null>(null);

  useEffect(() => {
    const timer = window.setTimeout(() => {
      setSearch(searchInput.trim());
      setOffset(0);
    }, 300);
    return () => window.clearTimeout(timer);
  }, [searchInput]);

  const catalogQuery = useQuery({
    queryKey: ['kev-catalog', { search, ransomwareOnly, offset, limit: PAGE_SIZE }],
    queryFn: ({ signal }) =>
      listKevVulnerabilities(
        {
          q: search || undefined,
          ransomware: ransomwareOnly ? true : undefined,
          limit: PAGE_SIZE,
          offset,
        },
        signal,
      ),
    placeholderData: keepPreviousData,
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
      queryClient.invalidateQueries({ queryKey: ['kev-catalog'] });
      queryClient.invalidateQueries({ queryKey: ['kev-detail'] });
      showToast('KEV catalog synced successfully', 'success');
    },
    onError: (error) => showToast(errorMessage(error, 'KEV sync failed'), 'error'),
  });

  const rows = catalogQuery.data ?? [];
  const page = Math.floor(offset / PAGE_SIZE) + 1;
  const hasPrevious = offset > 0;
  const hasNext = rows.length === PAGE_SIZE;
  const filtersActive = searchInput.trim() !== '' || ransomwareOnly;

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

        {catalogQuery.error ? (
          <Alert variant="error" title="Could not load the KEV catalog">
            {errorMessage(catalogQuery.error, 'Request failed')}
          </Alert>
        ) : null}

        <Card className="overflow-hidden">
          <TableFilterBar
            onClear={() => {
              setSearchInput('');
              setSearch('');
              setRansomwareOnly(false);
              setOffset(0);
            }}
            clearDisabled={!filtersActive}
            resultHint={`Page ${page} · ${rows.length} record${rows.length === 1 ? '' : 's'}`}
          >
            <TableSearchInput
              id="kev-search"
              value={searchInput}
              onChange={setSearchInput}
              label="Search KEV catalog"
              placeholder="CVE, vendor, product, or name"
            />
            <label className="flex h-10 cursor-pointer items-center gap-2 rounded-lg border border-border bg-surface px-3 text-sm text-foreground">
              <input
                type="checkbox"
                checked={ransomwareOnly}
                onChange={(event) => {
                  setRansomwareOnly(event.target.checked);
                  setOffset(0);
                }}
                className="h-4 w-4 rounded border-border accent-primary"
              />
              Ransomware only
            </label>
          </TableFilterBar>

          <Table ariaLabel="CISA Known Exploited Vulnerabilities" striped>
            <TableHead>
              <tr>
                <Th>CVE ID</Th>
                <Th>Vendor</Th>
                <Th>Product</Th>
                <Th>Vulnerability Name</Th>
                <Th>Date Added</Th>
                <Th>Due Date</Th>
                <Th>Ransomware</Th>
                <Th className="min-w-72">Required Action</Th>
              </tr>
            </TableHead>
            <TableBody>
              {catalogQuery.isLoading ? (
                Array.from({ length: 8 }, (_, index) => <SkeletonRow key={index} cols={8} />)
              ) : rows.length === 0 ? (
                <EmptyRow
                  cols={8}
                  message={
                    filtersActive
                      ? 'No KEV records match the active filters.'
                      : 'The KEV catalog is empty. Sync the catalog to load CISA records.'
                  }
                />
              ) : (
                rows.map((row) => (
                  <KevRow key={row.cve_id} row={row} onOpen={() => setSelectedCve(row.cve_id)} />
                ))
              )}
            </TableBody>
          </Table>

          <div className="flex items-center justify-between gap-3 border-t border-border bg-surface px-4 py-3">
            <p className="text-xs text-hcl-muted tabular-nums">
              Showing {rows.length ? offset + 1 : 0}–{offset + rows.length}
            </p>
            <div className="flex items-center gap-2">
              <Button
                variant="secondary"
                size="sm"
                disabled={!hasPrevious || catalogQuery.isFetching}
                onClick={() => setOffset(Math.max(0, offset - PAGE_SIZE))}
              >
                <ChevronLeft className="h-4 w-4" aria-hidden />
                Previous
              </Button>
              <span className="min-w-16 text-center text-xs font-medium text-hcl-muted">
                Page {page}
              </span>
              <Button
                variant="secondary"
                size="sm"
                disabled={!hasNext || catalogQuery.isFetching}
                onClick={() => setOffset(offset + PAGE_SIZE)}
              >
                Next
                <ChevronRight className="h-4 w-4" aria-hidden />
              </Button>
            </div>
          </div>
        </Card>
      </main>

      <Dialog
        open={selectedCve !== null}
        onClose={() => setSelectedCve(null)}
        title={selectedCve ?? 'KEV detail'}
        maxWidth="xl"
      >
        <DialogBody>
          {detailQuery.isLoading ? (
            <p className="py-8 text-center text-sm text-hcl-muted">Loading KEV details...</p>
          ) : detailQuery.error ? (
            <Alert variant="error" title="Could not load KEV details">
              {errorMessage(detailQuery.error, 'Request failed')}
            </Alert>
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
        <button
          type="button"
          onClick={onOpen}
          className="rounded font-mono text-xs font-semibold text-hcl-blue hover:underline focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-primary/40"
          aria-label={`Open KEV details for ${row.cve_id}`}
        >
          {row.cve_id}
        </button>
      </Td>
      <Td className="font-medium">{row.vendor_project ?? '—'}</Td>
      <Td>{row.product ?? '—'}</Td>
      <Td className="max-w-80">{row.vulnerability_name ?? '—'}</Td>
      <Td className="whitespace-nowrap">{formatCatalogDate(row.date_added)}</Td>
      <Td className="whitespace-nowrap">{formatCatalogDate(row.due_date)}</Td>
      <Td>
        <Badge variant={ransomware ? 'error' : 'gray'}>
          {ransomware ? 'Known' : row.known_ransomware_campaign_use ?? 'Unknown'}
        </Badge>
      </Td>
      <Td className="max-w-lg text-sm leading-relaxed">{row.required_action ?? '—'}</Td>
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
            <p className="mt-1 truncate text-sm font-semibold tabular-nums text-hcl-navy" title={value}>
              {value}
            </p>
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
        {ransomware ? (
          <Badge variant="error">
            <ShieldAlert className="mr-1 h-3.5 w-3.5" aria-hidden />
            Known ransomware use
          </Badge>
        ) : (
          <Badge variant="gray">Ransomware use unknown</Badge>
        )}
      </div>

      <dl className="grid gap-x-6 gap-y-4 sm:grid-cols-2">
        <DetailItem label="CVE ID" value={entry.cve_id} mono />
        <DetailItem label="Vendor Project" value={entry.vendor_project} />
        <DetailItem label="Product" value={entry.product} />
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
      <dd className={`mt-1 break-words text-foreground ${mono ? 'font-mono font-semibold' : ''}`}>
        {value || '—'}
      </dd>
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

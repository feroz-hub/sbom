'use client';

/**
 * Portfolio VEX Investigation queue (VEX-UI-001/002/003).
 *
 * Spec: docs/requirements/vex-dashboard-investigation.md sections 23-24 and
 * 27-30. The component-first "Manage VEX" flow in SbomDetail stays as it is;
 * this is the cross-SBOM view an analyst triages from.
 *
 * Structure follows app/kev/page.tsx, the repo's existing server-paginated
 * page: URL is the initial source of truth, state writes back via
 * router.replace, search is debounced, and keepPreviousData avoids a flash
 * of empty table between pages.
 */

import { Suspense, useEffect, useMemo, useState } from 'react';
import { keepPreviousData, useQuery } from '@tanstack/react-query';
import { AlertTriangle, ShieldQuestion } from 'lucide-react';
import { useRouter, useSearchParams } from 'next/navigation';
import { DashboardFilters } from '@/components/dashboard/DashboardFilters';
import { TopBar } from '@/components/layout/TopBar';
import { VexInvestigationDialog } from '@/components/vex/VexInvestigationDialog';
import { Alert } from '@/components/ui/Alert';
import { Badge, SeverityBadge } from '@/components/ui/Badge';
import { Button } from '@/components/ui/Button';
import { Card } from '@/components/ui/Card';
import { Input } from '@/components/ui/Input';
import { Pagination } from '@/components/ui/Pagination';
import { Select } from '@/components/ui/Select';
import { SkeletonRow } from '@/components/ui/Spinner';
import { EmptyRow, SortableTh, Table, TableBody, TableHead, Td, Th } from '@/components/ui/Table';
import { TableFilterBar, TableSearchInput } from '@/components/ui/TableFilterBar';
import { usePermission } from '@/hooks/usePermission';
import { useToast } from '@/hooks/useToast';
import {
  getDashboardVex,
  listVexInvestigations,
  type DashboardFilterScope,
} from '@/lib/api';
import type {
  DashboardVex,
  VexEffectiveStatus,
  VexInvestigationRow,
  VexInvestigationSortField,
} from '@/types';

const DEFAULT_PAGE_SIZE = 50;
const PAGE_SIZE_OPTIONS = [25, 50, 100, 250];

const SORT_FIELDS: VexInvestigationSortField[] = [
  'vulnerability_id',
  'component',
  'effective_status',
  'reconciliation_status',
  'last_seen_at',
  'first_seen_at',
  'updated_at',
];

const EFFECTIVE_STATUSES: VexEffectiveStatus[] = [
  'AFFECTED',
  'NOT_AFFECTED',
  'FIXED',
  'UNDER_INVESTIGATION',
];

const RECONCILIATION_STATUSES = [
  'MATCHED',
  'ANALYZER_ONLY',
  'VEX_ONLY',
  'CONFLICT_REVIEW_REQUIRED',
  'REVALIDATION_REQUIRED',
  'UNRESOLVED_MAPPING',
];

/** Reconciliation states an analyst must look at (spec section 23). */
const FLAGGED_RECONCILIATION = new Set([
  'CONFLICT_REVIEW_REQUIRED',
  'REVALIDATION_REQUIRED',
  'UNRESOLVED_MAPPING',
]);

type Filters = {
  search: string;
  effectiveStatus: string;
  reconciliationStatus: string;
  severity: string;
  component: string;
  vexSource: string;
  needsReview: boolean;
  sortBy: VexInvestigationSortField;
  sortOrder: 'asc' | 'desc';
};

const DEFAULT_FILTERS: Filters = {
  search: '',
  effectiveStatus: '',
  reconciliationStatus: '',
  severity: '',
  component: '',
  vexSource: '',
  needsReview: false,
  sortBy: 'last_seen_at',
  sortOrder: 'desc',
};

function positiveOrNull(value: string | null): number | null {
  const id = Number(value);
  return value && Number.isSafeInteger(id) && id > 0 ? id : null;
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
  const filters: Filters = {
    search: searchParams.get('q')?.trim() ?? '',
    effectiveStatus: searchParams.get('effective_status')?.trim() ?? '',
    reconciliationStatus: searchParams.get('reconciliation_status')?.trim() ?? '',
    severity: searchParams.get('severity')?.trim() ?? '',
    component: searchParams.get('component')?.trim() ?? '',
    vexSource: searchParams.get('vex_source')?.trim() ?? '',
    needsReview: searchParams.get('needs_review') === 'true',
    sortBy: SORT_FIELDS.includes(sortBy as VexInvestigationSortField)
      ? (sortBy as VexInvestigationSortField)
      : DEFAULT_FILTERS.sortBy,
    sortOrder: sortOrder === 'asc' || sortOrder === 'desc' ? sortOrder : 'desc',
  };
  return {
    filters,
    page: positiveInteger(searchParams.get('page'), 1),
    pageSize: positiveInteger(searchParams.get('limit'), DEFAULT_PAGE_SIZE, 250),
  };
}

function statusVariant(status: string): 'error' | 'success' | 'warning' | 'info' | 'gray' {
  if (status === 'AFFECTED') return 'error';
  if (status === 'NOT_AFFECTED') return 'success';
  if (status === 'FIXED') return 'info';
  if (status === 'UNDER_INVESTIGATION') return 'warning';
  return 'gray';
}

export default function VexInvestigationPage() {
  return (
    <Suspense fallback={<p className="p-6 text-sm text-hcl-muted">Loading VEX investigations...</p>}>
      <VexInvestigationContent />
    </Suspense>
  );
}

function VexInvestigationContent() {
  const router = useRouter();
  const searchParams = useSearchParams();
  const { showToast } = useToast();
  // Backend remains the gate (VEX-SEC-001); this only shapes the UI.
  const canRead = usePermission('vex:read');

  const [initial] = useState(() => initialState(searchParams));
  const [filters, setFilters] = useState<Filters>(initial.filters);
  const [searchInput, setSearchInput] = useState(initial.filters.search);
  const [page, setPage] = useState(initial.page);
  const [pageSize, setPageSize] = useState(initial.pageSize);
  const [selected, setSelected] = useState<{ row: VexInvestigationRow; tab: 'details' | 'investigation' } | null>(null);
  // Section 28 requires Project / Application / SBOM filters. Reuses the
  // dashboard's own cascading control so the two surfaces cannot drift apart.
  const [scope, setScope] = useState<DashboardFilterScope>(() => ({
    projectId: positiveOrNull(searchParams.get('project_id')),
    applicationId: positiveOrNull(searchParams.get('product_id')),
    sbomId: positiveOrNull(searchParams.get('sbom_id')),
  }));

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
    if (filters.effectiveStatus) params.set('effective_status', filters.effectiveStatus);
    if (filters.reconciliationStatus) params.set('reconciliation_status', filters.reconciliationStatus);
    if (filters.severity) params.set('severity', filters.severity);
    if (filters.component) params.set('component', filters.component);
    if (filters.vexSource) params.set('vex_source', filters.vexSource);
    if (filters.needsReview) params.set('needs_review', 'true');
    if (filters.sortBy !== DEFAULT_FILTERS.sortBy) params.set('sort_by', filters.sortBy);
    if (filters.sortOrder !== DEFAULT_FILTERS.sortOrder) params.set('sort_order', filters.sortOrder);
    if (page !== 1) params.set('page', String(page));
    if (pageSize !== DEFAULT_PAGE_SIZE) params.set('limit', String(pageSize));
    if (scope.projectId) params.set('project_id', String(scope.projectId));
    if (scope.applicationId) params.set('product_id', String(scope.applicationId));
    if (scope.sbomId) params.set('sbom_id', String(scope.sbomId));
    const query = params.toString();
    router.replace(query ? `/vex-investigation?${query}` : '/vex-investigation', { scroll: false });
  }, [filters, page, pageSize, scope, router]);

  const offset = (page - 1) * pageSize;

  const summaryQuery = useQuery<DashboardVex>({
    queryKey: ['dashboard-vex'],
    queryFn: ({ signal }) => getDashboardVex(signal),
  });

  const listQuery = useQuery({
    queryKey: ['vex-investigations', filters, scope, page, pageSize],
    queryFn: ({ signal }) =>
      listVexInvestigations(
        {
          q: filters.search || undefined,
          effective_status: filters.effectiveStatus || undefined,
          reconciliation_status: filters.reconciliationStatus || undefined,
          severity: filters.severity || undefined,
          component: filters.component || undefined,
          vex_source: filters.vexSource || undefined,
          needs_review: filters.needsReview ? true : undefined,
          project_id: scope.projectId ?? undefined,
          product_id: scope.applicationId ?? undefined,
          sbom_id: scope.sbomId ?? undefined,
          sort_by: filters.sortBy,
          sort_order: filters.sortOrder,
          limit: pageSize,
          offset,
        },
        signal,
      ),
    placeholderData: keepPreviousData,
    enabled: canRead,
  });

  const total = listQuery.data?.total ?? 0;
  const totalPages = Math.max(1, Math.ceil(total / pageSize));
  useEffect(() => {
    if (page > totalPages) setPage(totalPages);
  }, [page, totalPages]);

  const rows = listQuery.data?.items ?? [];
  const summary = summaryQuery.data;

  const cards = useMemo(
    () => [
      { label: 'Total Contexts', value: summary?.total_contexts, filter: {} },
      { label: 'Affected', value: summary?.affected_count, filter: { effectiveStatus: 'AFFECTED' } },
      { label: 'Not Affected', value: summary?.not_affected_count, filter: { effectiveStatus: 'NOT_AFFECTED' } },
      { label: 'Fixed', value: summary?.fixed_count, filter: { effectiveStatus: 'FIXED' } },
      {
        label: 'Under Investigation',
        value: summary?.under_investigation_count,
        filter: { effectiveStatus: 'UNDER_INVESTIGATION' },
      },
      { label: 'Analyzer Only', value: summary?.analyzer_only_count, filter: { reconciliationStatus: 'ANALYZER_ONLY' } },
      { label: 'VEX Only', value: summary?.vex_only_count, filter: { reconciliationStatus: 'VEX_ONLY' } },
      { label: 'Matched', value: summary?.matched_count, filter: { reconciliationStatus: 'MATCHED' } },
      { label: 'Needs Review', value: summary?.needs_review_count, filter: { needsReview: true } },
      {
        label: 'Unresolved Mapping',
        value: summary?.unresolved_mapping_count,
        filter: { reconciliationStatus: 'UNRESOLVED_MAPPING' },
      },
    ],
    [summary],
  );

  function applyCardFilter(patch: Partial<Filters>) {
    setFilters({ ...DEFAULT_FILTERS, search: '', ...patch });
    setSearchInput('');
    setPage(1);
  }

  function updateFilter(patch: Partial<Filters>) {
    setFilters((current) => ({ ...current, ...patch }));
    setPage(1);
  }

  if (!canRead) {
    return (
      <>
        <TopBar title="VEX Investigation" />
        <div className="p-6">
          <Alert variant="warning">You do not have permission to view VEX investigations.</Alert>
        </div>
      </>
    );
  }

  return (
    <>
      <TopBar title="VEX Investigation" />
      <div className="space-y-4 p-6">
        <div className="grid grid-cols-2 gap-3 md:grid-cols-5">
          {cards.map((card) => (
            <button
              key={card.label}
              type="button"
              onClick={() => applyCardFilter(card.filter as Partial<Filters>)}
              className="rounded-lg border border-gray-200 bg-white p-3 text-left transition hover:border-hcl-blue dark:border-gray-800 dark:bg-gray-900"
            >
              <div className="text-[10px] font-semibold uppercase tracking-wider text-hcl-muted">
                {card.label}
              </div>
              <div className="mt-1 text-xl font-semibold text-hcl-navy dark:text-gray-100">
                {card.value ?? '—'}
              </div>
            </button>
          ))}
        </div>

        <Card>
          <div className="border-b border-gray-200 p-3 dark:border-gray-800">
            <DashboardFilters
              scope={scope}
              onChange={(next) => {
                setScope(next);
                setPage(1);
              }}
              isUpdating={listQuery.isFetching}
            />
          </div>
          <TableFilterBar>
            <TableSearchInput
              value={searchInput}
              onChange={setSearchInput}
              placeholder="Vulnerability ID or alias..."
            />
            <Select
              value={filters.effectiveStatus}
              onChange={(event) => updateFilter({ effectiveStatus: event.target.value })}
              aria-label="Effective status"
            >
              <option value="">All effective statuses</option>
              {EFFECTIVE_STATUSES.map((status) => (
                <option key={status} value={status}>
                  {status.replace(/_/g, ' ')}
                </option>
              ))}
            </Select>
            <Select
              value={filters.reconciliationStatus}
              onChange={(event) => updateFilter({ reconciliationStatus: event.target.value })}
              aria-label="Reconciliation status"
            >
              <option value="">All reconciliation states</option>
              {RECONCILIATION_STATUSES.map((status) => (
                <option key={status} value={status}>
                  {status.replace(/_/g, ' ')}
                </option>
              ))}
            </Select>
            <Input
              value={filters.component}
              onChange={(event) => updateFilter({ component: event.target.value })}
              placeholder="Component"
              aria-label="Component"
            />
            <label className="flex items-center gap-2 text-xs text-hcl-muted">
              <input
                type="checkbox"
                checked={filters.needsReview}
                onChange={(event) => updateFilter({ needsReview: event.target.checked })}
              />
              Needs review
            </label>
          </TableFilterBar>

          <Table>
            <TableHead>
              <tr>
                <SortableTh
                  sortKey="vulnerability_id"
                  activeKey={filters.sortBy}
                  direction={filters.sortOrder}
                  onToggle={(key) =>
                    updateFilter({
                      sortBy: key as VexInvestigationSortField,
                      sortOrder: filters.sortBy === key && filters.sortOrder === 'asc' ? 'desc' : 'asc',
                    })
                  }
                >
                  Vulnerability
                </SortableTh>
                <Th>Severity</Th>
                <SortableTh
                  sortKey="component"
                  activeKey={filters.sortBy}
                  direction={filters.sortOrder}
                  onToggle={(key) =>
                    updateFilter({
                      sortBy: key as VexInvestigationSortField,
                      sortOrder: filters.sortBy === key && filters.sortOrder === 'asc' ? 'desc' : 'asc',
                    })
                  }
                >
                  Component
                </SortableTh>
                <Th>SBOM</Th>
                <Th>Analyzer</Th>
                <Th>Native VEX</Th>
                <SortableTh
                  sortKey="effective_status"
                  activeKey={filters.sortBy}
                  direction={filters.sortOrder}
                  onToggle={(key) =>
                    updateFilter({
                      sortBy: key as VexInvestigationSortField,
                      sortOrder: filters.sortBy === key && filters.sortOrder === 'asc' ? 'desc' : 'asc',
                    })
                  }
                >
                  Effective
                </SortableTh>
                <Th>Reconciliation</Th>
                <Th>Owner</Th>
                <Th>Action</Th>
              </tr>
            </TableHead>
            <TableBody>
              {listQuery.isLoading ? (
                <SkeletonRow cols={10} />
              ) : rows.length === 0 ? (
                <EmptyRow cols={10} message="No VEX investigations match these filters." />
              ) : (
                rows.map((row) => <InvestigationTableRow key={row.id} row={row} onOpen={(row, tab) => setSelected({ row, tab })} />)
              )}
            </TableBody>
          </Table>

          <Pagination
            page={page}
            pageSize={pageSize}
            total={total}
            totalPages={totalPages}
            rangeStart={total === 0 ? 0 : offset + 1}
            rangeEnd={Math.min(offset + pageSize, total)}
            hasPrev={page > 1}
            hasNext={page < totalPages}
            onPageChange={setPage}
            onPageSizeChange={(size) => {
              setPageSize(size);
              setPage(1);
            }}
            pageSizeOptions={PAGE_SIZE_OPTIONS}
            itemNoun="investigation"
          />
        </Card>
      </div>

      <VexInvestigationDialog
        row={selected?.row ?? null}
        initialTab={selected?.tab ?? 'details'}
        onClose={() => setSelected(null)}
        onSaved={() => showToast('VEX investigation updated', 'success')}
        onConflict={() => showToast('Updated by someone else — reloaded the latest version', 'error')}
      />
    </>
  );
}

function InvestigationTableRow({
  row,
  onOpen,
}: {
  row: VexInvestigationRow;
  onOpen: (row: VexInvestigationRow, tab: 'details' | 'investigation') => void;
}) {
  const flagged = FLAGGED_RECONCILIATION.has(row.reconciliation_status);
  const vexOnlyAffected = row.reconciliation_status === 'VEX_ONLY' && row.effective_status === 'AFFECTED';
  return (
    <tr className={flagged || vexOnlyAffected ? 'bg-amber-50/60 dark:bg-amber-950/20' : undefined}>
      <Td>
        <button type="button" onClick={() => onOpen(row, 'details')}
          className="rounded font-medium text-hcl-blue underline-offset-4 hover:underline focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-hcl-blue"
          aria-label={`View vulnerability ${row.canonical_vulnerability_id}`}>
          {row.canonical_vulnerability_id}
        </button>
        {row.aliases.length > 0 ? (
          <div className="text-[10px] text-hcl-muted">{row.aliases.join(', ')}</div>
        ) : null}
      </Td>
      {/* Severity describes the vulnerability and is never rewritten by VEX
          (VEX-DATA-005) — a NOT_AFFECTED context still shows CRITICAL. */}
      <Td><SeverityBadge severity={row.severity ?? "UNKNOWN"} /></Td>
      <Td>
        {row.component_name ?? <span className="text-hcl-muted">Unresolved</span>}
        {row.component_version ? (
          <span className="text-hcl-muted"> {row.component_version}</span>
        ) : null}
      </Td>
      <Td>{row.sbom_name ?? '—'}</Td>
      <Td>{row.analyzer_detection_state ?? '—'}</Td>
      <Td>{row.native_vex_status ?? '—'}</Td>
      <Td>
        <Badge variant={statusVariant(row.effective_status)}>{row.effective_status.replace(/_/g, ' ')}</Badge>
      </Td>
      <Td>
        <span className="inline-flex items-center gap-1">
          {flagged ? <AlertTriangle className="h-3 w-3 text-amber-600" aria-hidden /> : null}
          {vexOnlyAffected ? <ShieldQuestion className="h-3 w-3 text-amber-600" aria-hidden /> : null}
          {row.reconciliation_status.replace(/_/g, ' ')}
        </span>
      </Td>
      <Td>{row.assigned_to_label ?? row.reviewed_by ?? 'Unassigned'}</Td>
      <Td>
        <Button variant="ghost" size="sm" onClick={() => onOpen(row, 'investigation')}>
          Investigate
        </Button>
      </Td>
    </tr>
  );
}

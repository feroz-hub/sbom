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

import { Suspense, useEffect, useMemo, useRef, useState } from 'react';
import { useInfiniteQuery, useQuery } from '@tanstack/react-query';
import { AlertTriangle, ShieldQuestion } from 'lucide-react';
import { useRouter, useSearchParams } from 'next/navigation';
import { DashboardFilters } from '@/components/dashboard/DashboardFilters';
import { TopBar } from '@/components/layout/TopBar';
import { VexInvestigationDialog } from '@/components/vex/VexInvestigationDialog';
import { AssigneeCombobox } from '@/components/vex/AssigneeCombobox';
import { Dialog } from '@/components/ui/Dialog';
import { Alert } from '@/components/ui/Alert';
import { Badge, SeverityBadge } from '@/components/ui/Badge';
import { Button } from '@/components/ui/Button';
import { Card } from '@/components/ui/Card';
import { Input } from '@/components/ui/Input';
import { Pagination } from '@/components/ui/Pagination';
import { Select } from '@/components/ui/Select';
import { SkeletonRow } from '@/components/ui/Spinner';
import { SortableTh, Table, TableBody, TableHead, Td, Th } from '@/components/ui/Table';
import { TableFilterBar, TableSearchInput } from '@/components/ui/TableFilterBar';
import { usePermission } from '@/hooks/usePermission';
import { useAuth } from '@/hooks/useAuth';
import { useToast } from '@/hooks/useToast';
import {
  getDashboardVex,
  listVexInvestigations,
  searchVexAssignees,
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
  myWork: 'all' | 'me' | 'unassigned' | 'assigned' | 'attention';
  assignee: string;
  unresolvedComponent: boolean;
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
  myWork: 'all',
  assignee: '',
  unresolvedComponent: false,
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
    myWork: ['me', 'unassigned', 'assigned', 'attention'].includes(searchParams.get('my_work') ?? '')
      ? searchParams.get('my_work') as Filters['myWork'] : 'all',
    assignee: searchParams.get('assignee')?.trim() ?? '',
    unresolvedComponent: searchParams.get('unresolved_component') === 'true',
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

const WORK_LABELS = { all: 'All investigations', me: 'Assigned to me', unassigned: 'Unassigned', assigned: 'Assigned', attention: 'Needs my attention' };
function readable(value: string) {
  return value.toLowerCase().replaceAll('_', ' ').replace(/^./, first => first.toUpperCase());
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
  const { user, activeTenant, activeTenantId } = useAuth();
  const workingRole = (activeTenant?.roles ?? user?.roles ?? []).some(role => ['TENANT_ADMIN', 'SECURITY_ANALYST', 'DEVELOPER'].includes(role));
  const [mobileFiltersOpen, setMobileFiltersOpen] = useState(false);
  const [assigneeSearch, setAssigneeSearch] = useState('');
  const [debouncedAssigneeSearch, setDebouncedAssigneeSearch] = useState('');
  const [assigneeLabel, setAssigneeLabel] = useState('');
  useEffect(() => {
    const timer = window.setTimeout(() => setDebouncedAssigneeSearch(assigneeSearch.trim()), 300);
    return () => window.clearTimeout(timer);
  }, [assigneeSearch]);

  const [initial] = useState(() => initialState(searchParams));
  const [filters, setFilters] = useState<Filters>(initial.filters);
  const [searchInput, setSearchInput] = useState(initial.filters.search);
  const [componentInput, setComponentInput] = useState(initial.filters.component);
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
    if (searchInput.trim() === filters.search) return;
    const timer = window.setTimeout(() => {
      const search = searchInput.trim();
      setFilters((current) => (current.search === search ? current : { ...current, search }));
      setPage(1);
    }, 350);
    return () => window.clearTimeout(timer);
  }, [searchInput, filters.search]);
  useEffect(() => {
    if (componentInput.trim() === filters.component) return;
    const timer = window.setTimeout(() => { setFilters(current => ({ ...current, component: componentInput.trim() })); setPage(1); }, 300);
    return () => window.clearTimeout(timer);
  }, [componentInput, filters.component]);

  // Ignore our own URL writes, but restore state on browser back/forward.
  const incomingUrl = searchParams.toString();
  const observedUrl = useRef(incomingUrl);
  const writtenUrl = useRef(incomingUrl);
  const restoringUrl = useRef(false);
  useEffect(() => {
    if (incomingUrl === observedUrl.current) return;
    observedUrl.current = incomingUrl;
    if (incomingUrl === writtenUrl.current) return;
    restoringUrl.current = true;
    const restored = initialState(new URLSearchParams(incomingUrl));
    setFilters(restored.filters); setSearchInput(restored.filters.search);
    setComponentInput(restored.filters.component);
    setPage(restored.page); setPageSize(restored.pageSize);
    const params = new URLSearchParams(incomingUrl);
    setScope({ projectId: positiveOrNull(params.get('project_id')), applicationId: positiveOrNull(params.get('product_id')), sbomId: positiveOrNull(params.get('sbom_id')) });
  }, [incomingUrl]);

  useEffect(() => {
    if (restoringUrl.current) { restoringUrl.current = false; return; }
    const params = new URLSearchParams();
    if (filters.search) params.set('q', filters.search);
    if (filters.effectiveStatus) params.set('effective_status', filters.effectiveStatus);
    if (filters.reconciliationStatus) params.set('reconciliation_status', filters.reconciliationStatus);
    if (filters.severity) params.set('severity', filters.severity);
    if (filters.component) params.set('component', filters.component);
    if (filters.vexSource) params.set('vex_source', filters.vexSource);
    if (filters.needsReview) params.set('needs_review', 'true');
    if (filters.myWork !== 'all') params.set('my_work', filters.myWork);
    if (filters.assignee) params.set('assignee', filters.assignee);
    if (filters.unresolvedComponent) params.set('unresolved_component', 'true');
    if (filters.sortBy !== DEFAULT_FILTERS.sortBy) params.set('sort_by', filters.sortBy);
    if (filters.sortOrder !== DEFAULT_FILTERS.sortOrder) params.set('sort_order', filters.sortOrder);
    if (page !== 1) params.set('page', String(page));
    if (pageSize !== DEFAULT_PAGE_SIZE) params.set('limit', String(pageSize));
    if (scope.projectId) params.set('project_id', String(scope.projectId));
    if (scope.applicationId) params.set('product_id', String(scope.applicationId));
    if (scope.sbomId) params.set('sbom_id', String(scope.sbomId));
    const query = params.toString();
    writtenUrl.current = query;
    router.replace(query ? `/vex-investigation?${query}` : '/vex-investigation', { scroll: false });
  }, [filters, page, pageSize, scope, router]);

  const offset = (page - 1) * pageSize;

  const summaryQuery = useQuery<DashboardVex>({
    queryKey: ['dashboard-vex', activeTenantId],
    queryFn: ({ signal }) => getDashboardVex(signal),
    enabled: canRead,
  });

  const listQuery = useQuery({
    queryKey: ['vex-investigations', activeTenantId, filters, scope, page, pageSize],
    queryFn: ({ signal }) =>
      listVexInvestigations(
        {
          q: filters.search || undefined,
          my_work: filters.myWork === 'all' ? undefined : filters.myWork,
          assignee: filters.assignee || undefined,
          unresolved_component: filters.unresolvedComponent || undefined,
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
    placeholderData: (previous, previousQuery) => previousQuery?.queryKey[1] === activeTenantId ? previous : undefined,
    enabled: canRead,
  });

  const assigneesQuery = useInfiniteQuery({
    queryKey: ['vex-assignees', activeTenantId, debouncedAssigneeSearch],
    queryFn: ({ pageParam, signal }) => searchVexAssignees(debouncedAssigneeSearch, pageParam, signal),
    initialPageParam: 0,
    getNextPageParam: last => last.offset + last.items.length < last.total ? last.offset + last.limit : undefined,
    enabled: canRead,
  });
  const assignees = assigneesQuery.data?.pages.flatMap(part => part.items) ?? [];

  const total = listQuery.data?.total ?? 0;
  const totalPages = Math.max(1, Math.ceil(total / pageSize));
  useEffect(() => {
    if (!listQuery.isFetching && !listQuery.isPlaceholderData && listQuery.data && page > totalPages) setPage(totalPages);
  }, [page, totalPages, listQuery.isFetching, listQuery.isPlaceholderData, listQuery.data]);

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
    setComponentInput('');
    setPage(1);
  }

  function updateFilter(patch: Partial<Filters>) {
    setFilters((current) => ({ ...current, ...patch }));
    setPage(1);
  }

  function clearFilters() {
    setFilters(DEFAULT_FILTERS); setSearchInput(''); setAssigneeLabel('');
    setComponentInput('');
    setScope({ projectId: null, applicationId: null, sbomId: null }); setPage(1);
  }

  const personalWorkActive = filters.myWork === 'me' || filters.assignee === 'me';
  const unassignedActive = filters.myWork === 'unassigned' || filters.assignee === 'unassigned';

  const chips: Array<{ label: string; clear: () => void }> = [];
  if (filters.myWork !== 'all') chips.push({ label: WORK_LABELS[filters.myWork], clear: () => updateFilter({ myWork: 'all' }) });
  if (filters.assignee) chips.push({ label: `Assignee: ${filters.assignee === 'me' ? 'Me' : filters.assignee === 'unassigned' ? 'Unassigned' : assignees.find(item => item.id === filters.assignee)?.label || assigneeLabel || 'Selected tenant user'}`, clear: () => updateFilter({ assignee: '' }) });
  for (const [key, label] of [['severity', 'Severity'], ['effectiveStatus', 'Effective'], ['reconciliationStatus', 'Reconciliation'], ['component', 'Component'], ['vexSource', 'VEX source']] as const) {
    if (filters[key]) chips.push({ label: `${label}: ${readable(filters[key])}`, clear: () => { if (key === 'component') setComponentInput(''); updateFilter({ [key]: '' }); } });
  }
  if (filters.search) chips.push({ label: `Search: ${filters.search}`, clear: () => { setSearchInput(''); updateFilter({ search: '' }); } });
  if (filters.needsReview) chips.push({ label: 'Needs review', clear: () => updateFilter({ needsReview: false }) });
  if (filters.unresolvedComponent) chips.push({ label: 'Unresolved component', clear: () => updateFilter({ unresolvedComponent: false }) });
  for (const [key, label] of [['projectId', 'Project'], ['applicationId', 'Application'], ['sbomId', 'SBOM']] as const) {
    if (scope[key]) chips.push({ label: `${label} selected`, clear: () => { setScope(current => key === 'projectId' ? { projectId: null, applicationId: null, sbomId: null } : key === 'applicationId' ? { ...current, applicationId: null, sbomId: null } : { ...current, sbomId: null }); setPage(1); } });
  }
  const scopeControls = <DashboardFilters scope={scope} hideClear onChange={next => { setScope(next); setPage(1); }} isUpdating={listQuery.isFetching} />;
  const filterControls = <div className="flex flex-wrap items-end gap-3">
    {workingRole ? <Select label="My work" value={filters.myWork} onChange={event => updateFilter({ myWork: event.target.value as Filters['myWork'], assignee: '' })}>
      {Object.entries(WORK_LABELS).map(([value, label]) => <option key={value} value={value}>{label}</option>)}
    </Select> : null}
    <div className="min-w-[12rem] flex-1">
      <AssigneeCombobox compact label="Filter by assignee" selected={filters.assignee}
        selectedLabel={assigneeLabel || (filters.assignee ? 'Selected tenant user' : 'All assignees')}
        candidates={[...(!assigneeSearch.trim() ? [{ id: '', label: 'All assignees', roles: [] }, ...(workingRole ? [{ id: 'me', label: 'Me', roles: [] }] : []), { id: 'unassigned', label: 'Unassigned', roles: [] }] : []), ...assignees]}
        onSearch={setAssigneeSearch} loading={assigneesQuery.isFetching || assigneeSearch.trim() !== debouncedAssigneeSearch}
        error={assigneesQuery.isError} onRetry={() => assigneesQuery.refetch()}
        onLoadMore={assigneesQuery.hasNextPage ? () => assigneesQuery.fetchNextPage() : undefined}
        onSelect={id => { setAssigneeLabel(assignees.find(item => item.id === id)?.label ?? (id === 'me' ? 'Me' : id === 'unassigned' ? 'Unassigned' : 'All assignees')); updateFilter({ assignee: id, myWork: 'all' }); }} />
    </div>
    <Select label="Severity" value={filters.severity} onChange={event => updateFilter({ severity: event.target.value })}>
      <option value="">All severities</option>{['CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'UNKNOWN'].map(value => <option key={value} value={value}>{readable(value)}</option>)}
    </Select>
    <Select label="Effective status" value={filters.effectiveStatus} onChange={event => updateFilter({ effectiveStatus: event.target.value })}>
      <option value="">All effective statuses</option>{EFFECTIVE_STATUSES.map(value => <option key={value} value={value}>{readable(value)}</option>)}
    </Select>
    <Select label="Reconciliation status" value={filters.reconciliationStatus} onChange={event => updateFilter({ reconciliationStatus: event.target.value })}>
      <option value="">All reconciliation states</option>{RECONCILIATION_STATUSES.map(value => <option key={value} value={value}>{readable(value)}</option>)}
    </Select>
    <Input label="Component" value={componentInput} onChange={event => setComponentInput(event.target.value)} placeholder="Name or version" />
    {/* Review is the conflict/revalidation union, distinct from mapping. */}
    <label className="flex items-center gap-2 rounded border border-border px-2 py-2 text-xs"><input type="checkbox" checked={filters.needsReview} onChange={event => updateFilter({ needsReview: event.target.checked })} />Needs review</label>
    <label title="Contexts without a resolved component, including VEX-only records." className="flex items-center gap-2 rounded border border-border px-2 py-2 text-xs"><input type="checkbox" checked={filters.unresolvedComponent} onChange={event => updateFilter({ unresolvedComponent: event.target.checked })} />Unresolved component</label>
  </div>;

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
        <p className="text-xs text-hcl-muted">Tenant overview · metrics below are independent of queue filters.</p>
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
          <div className="hidden border-b border-gray-200 p-3 sm:block dark:border-gray-800">
            {!mobileFiltersOpen ? scopeControls : null}
          </div>
          <TableFilterBar>
            <TableSearchInput
              value={searchInput}
              onChange={setSearchInput}
              label="Search vulnerability"
              placeholder="Search CVE, alias or vulnerability..."
            />
            <Button variant="outline" className="sm:hidden" onClick={() => setMobileFiltersOpen(true)}>Filters ({chips.length})</Button>
          </TableFilterBar>
          <div className="hidden border-b border-border p-3 sm:block">{!mobileFiltersOpen ? filterControls : null}</div>
          <Dialog open={mobileFiltersOpen} onClose={() => setMobileFiltersOpen(false)} title="Investigation filters">
            <div className="space-y-3 p-4">{scopeControls}{filterControls}
              {chips.length ? <Button variant="ghost" onClick={clearFilters}>Clear all filters</Button> : null}
              <Button onClick={() => setMobileFiltersOpen(false)}>Show investigations</Button>
            </div>
          </Dialog>
          <div className="space-y-2 border-b border-border px-4 py-3">
            <div className="flex flex-wrap gap-2">
              {workingRole ? <Button size="sm" variant={personalWorkActive ? 'primary' : 'outline'} aria-pressed={personalWorkActive} onClick={() => updateFilter({ myWork: personalWorkActive ? 'all' : 'me', assignee: '' })}>Assigned to me</Button> : null}
              {workingRole ? <Button size="sm" variant="ghost" aria-pressed={unassignedActive} onClick={() => updateFilter({ myWork: unassignedActive ? 'all' : 'unassigned', assignee: '' })}>Unassigned</Button> : null}
              <Button size="sm" variant="ghost" aria-pressed={filters.needsReview} onClick={() => updateFilter({ needsReview: !filters.needsReview })}>Needs review</Button>
              <Button size="sm" variant="ghost" aria-pressed={filters.severity === 'CRITICAL'} onClick={() => updateFilter({ severity: filters.severity === 'CRITICAL' ? '' : 'CRITICAL' })}>Critical</Button>
              <Button size="sm" variant="ghost" aria-pressed={filters.reconciliationStatus === 'UNRESOLVED_MAPPING'} onClick={() => updateFilter({ reconciliationStatus: filters.reconciliationStatus === 'UNRESOLVED_MAPPING' ? '' : 'UNRESOLVED_MAPPING' })}>Unresolved mapping</Button>
            </div>
            {chips.length ? <div className="flex flex-wrap items-center gap-2" aria-label="Active filters">
              {chips.map(chip => <button key={chip.label} type="button" aria-label={`Remove ${chip.label} filter`} onClick={chip.clear} className="rounded-full border border-border px-2.5 py-1 text-xs focus-visible:ring-2 focus-visible:ring-hcl-blue">{chip.label} ×</button>)}
              <Button size="sm" variant="ghost" onClick={clearFilters}>Clear all filters</Button>
            </div> : null}
            <p role="status" className="text-xs text-hcl-muted">{listQuery.isFetching ? 'Updating investigations…' : listQuery.isError ? 'Investigation results unavailable' : `${total} matching investigations`}</p>
          </div>
          {listQuery.isError ? <Alert variant="error">Unable to load investigations. <Button size="sm" variant="ghost" onClick={() => listQuery.refetch()}>Retry</Button></Alert> : null}

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
              ) : listQuery.isError ? null : rows.length === 0 ? (
                <tr><td colSpan={10} className="p-8 text-center text-sm">
                  <p>{workingRole && chips.length === 1 && (filters.myWork === 'me' || filters.assignee === 'me') ? "You're all caught up" : chips.length ? 'No matching investigations' : 'No investigations exist'}</p>
                  <p className="mt-1 text-xs text-hcl-muted">{filters.myWork === 'me' || filters.assignee === 'me' ? 'No VEX investigations match your personal work filters.' : chips.length ? 'Try changing or clearing some filters.' : 'Investigations will appear when analyzer or VEX evidence is available.'}</p>
                  {chips.length ? <Button size="sm" variant="ghost" onClick={clearFilters}>Clear filters</Button> : null}
                </td></tr>
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
      <Td>{row.assigned_to ? <><span>{row.assigned_to_label ?? 'Legacy assignment'}</span>{row.assigned_to_is_self ? <Badge variant="info">You</Badge> : null}{row.assigned_to_active === false ? <span className="block text-[10px] text-hcl-muted">Inactive or legacy owner</span> : null}</> : <Badge variant="gray">Unassigned</Badge>}</Td>
      <Td>
        <Button variant="ghost" size="sm" onClick={() => onOpen(row, 'investigation')}>
          Investigate
        </Button>
      </Td>
    </tr>
  );
}

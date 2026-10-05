'use client';

/**
 * Secure Component Advisor dashboard (spec Step 9; FR-SCA-002/006/007/008).
 *
 * Tenant is the default scope (the active tenant); Project → Application →
 * SBOM cascade through the shared DashboardFilters control. KPI cards, the
 * table and the applied-filter line all come from one backend snapshot with
 * identical filters, so a card's count equals the rows it opens (T36).
 *
 * Structure mirrors app/vex-investigation/page.tsx: URL is the initial
 * source of truth, state writes back via router.replace, search is debounced.
 * The backend enforces every permission; this page only shapes the UI.
 */

import Link from 'next/link';
import { Suspense, useEffect, useMemo, useRef, useState } from 'react';
import { useQuery } from '@tanstack/react-query';
import { useRouter, useSearchParams } from 'next/navigation';
import { DashboardFilters } from '@/components/dashboard/DashboardFilters';
import { TopBar } from '@/components/layout/TopBar';
import { AdvisorNotice } from '@/components/component-advisor/AdvisorNotice';
import { LifecycleBadge, ProvenanceBadge, RiskBadge } from '@/components/component-advisor/AdvisorBadges';
import {
  FACET_LABELS,
  LIFECYCLE_LABELS,
  RISK_FILTERS,
  RISK_LABELS,
  STATUS_LABELS,
  formatTimestamp,
} from '@/components/component-advisor/labels';
import { Alert } from '@/components/ui/Alert';
import { Button } from '@/components/ui/Button';
import { Card } from '@/components/ui/Card';
import { Pagination } from '@/components/ui/Pagination';
import { Select } from '@/components/ui/Select';
import { SkeletonRow } from '@/components/ui/Spinner';
import { Table, TableBody, TableHead, Td, Th } from '@/components/ui/Table';
import { TableFilterBar, TableSearchInput } from '@/components/ui/TableFilterBar';
import { useAuth } from '@/hooks/useAuth';
import { usePermission } from '@/hooks/usePermission';
import {
  ApiError,
  getAdvisorSummary,
  listAdvisorComponents,
  type DashboardFilterScope,
} from '@/lib/api';
import type {
  AdvisorComponent,
  AdvisorFacet,
  AdvisorFilterParams,
  AdvisorKpi,
  AdvisorLifecycleBucket,
  AdvisorRiskClassification,
  AdvisorSortField,
} from '@/types/componentAdvisor';

const DEFAULT_PAGE_SIZE = 50;
const LIFECYCLE_FILTERS: AdvisorLifecycleBucket[] = ['SUPPORTED', 'MAINTENANCE', 'EOS', 'EOL', 'UNKNOWN'];
const SORT_FIELDS: AdvisorSortField[] = ['risk', 'name', 'occurrences', 'products', 'actionable', 'latest_analysis'];
const SORT_LABELS: Record<AdvisorSortField, string> = {
  risk: 'Risk', name: 'Name', occurrences: 'Active SBOM occurrences', products: 'Products',
  actionable: 'Actionable findings', latest_analysis: 'Latest analysis',
};

type Filters = {
  risk: AdvisorRiskClassification[];
  lifecycle: AdvisorLifecycleBucket[];
  needsReview: boolean;
  frequentlyAdopted: boolean;
  trusted: boolean;
  q: string;
  facet: AdvisorFacet;
  sortBy: AdvisorSortField;
  sortOrder: 'asc' | 'desc';
};

const DEFAULT_FILTERS: Filters = {
  risk: [], lifecycle: [], needsReview: false, frequentlyAdopted: false, trusted: false,
  q: '', facet: 'all', sortBy: 'risk', sortOrder: 'desc',
};

function positiveOrNull(value: string | null): number | null {
  const id = Number(value);
  return value && Number.isSafeInteger(id) && id > 0 ? id : null;
}

function readFilters(params: URLSearchParams | Readonly<URLSearchParams>): Filters {
  const facet = params.get('facet') as AdvisorFacet | null;
  const sortBy = params.get('sort_by') as AdvisorSortField | null;
  return {
    risk: params.getAll('risk').filter((v): v is AdvisorRiskClassification => RISK_FILTERS.includes(v as AdvisorRiskClassification)),
    lifecycle: params.getAll('lifecycle').filter((v): v is AdvisorLifecycleBucket => LIFECYCLE_FILTERS.includes(v as AdvisorLifecycleBucket)),
    needsReview: params.get('needs_review') === 'true',
    frequentlyAdopted: params.get('frequently_adopted') === 'true',
    trusted: params.get('trusted') === 'true',
    q: params.get('q')?.trim() ?? '',
    facet: facet && facet in FACET_LABELS ? facet : 'all',
    sortBy: sortBy && SORT_FIELDS.includes(sortBy) ? sortBy : 'risk',
    sortOrder: params.get('sort_order') === 'asc' ? 'asc' : 'desc',
  };
}

function toParams(filters: Filters, scope: DashboardFilterScope): AdvisorFilterParams {
  return {
    risk: filters.risk.length ? filters.risk : undefined,
    lifecycle: filters.lifecycle.length ? filters.lifecycle : undefined,
    needs_review: filters.needsReview || undefined,
    frequently_adopted: filters.frequentlyAdopted || undefined,
    trusted: filters.trusted || undefined,
    q: filters.q || undefined,
    facet: filters.facet,
    project_id: scope.projectId,
    product_id: scope.applicationId,
    sbom_id: scope.sbomId,
  };
}

function scopeQuery(scope: DashboardFilterScope): string {
  const params = new URLSearchParams();
  if (scope.projectId) params.set('project_id', String(scope.projectId));
  if (scope.applicationId) params.set('product_id', String(scope.applicationId));
  if (scope.sbomId) params.set('sbom_id', String(scope.sbomId));
  const query = params.toString();
  return query ? `?${query}` : '';
}

export default function ComponentAdvisorPage() {
  return (
    <Suspense fallback={<p className="p-6 text-sm text-hcl-muted">Loading Secure Component Advisor…</p>}>
      <ComponentAdvisorContent />
    </Suspense>
  );
}

function ComponentAdvisorContent() {
  const router = useRouter();
  const searchParams = useSearchParams();
  const { activeTenantId } = useAuth();
  const canRead = usePermission('component_advisor:read');
  const resultsHeading = useRef<HTMLHeadingElement>(null);

  const [filters, setFilters] = useState<Filters>(() => readFilters(searchParams));
  const [searchInput, setSearchInput] = useState(filters.q);
  const [page, setPage] = useState(() => Math.max(1, Number(searchParams.get('page')) || 1));
  const [pageSize, setPageSize] = useState(DEFAULT_PAGE_SIZE);
  const [scope, setScope] = useState<DashboardFilterScope>(() => ({
    projectId: positiveOrNull(searchParams.get('project_id')),
    applicationId: positiveOrNull(searchParams.get('product_id')),
    sbomId: positiveOrNull(searchParams.get('sbom_id')),
  }));

  useEffect(() => {
    if (searchInput.trim() === filters.q) return;
    const timer = window.setTimeout(() => { setFilters((c) => ({ ...c, q: searchInput.trim() })); setPage(1); }, 350);
    return () => window.clearTimeout(timer);
  }, [searchInput, filters.q]);

  useEffect(() => {
    const params = new URLSearchParams();
    filters.risk.forEach((v) => params.append('risk', v));
    filters.lifecycle.forEach((v) => params.append('lifecycle', v));
    if (filters.needsReview) params.set('needs_review', 'true');
    if (filters.frequentlyAdopted) params.set('frequently_adopted', 'true');
    if (filters.trusted) params.set('trusted', 'true');
    if (filters.q) params.set('q', filters.q);
    if (filters.facet !== 'all') params.set('facet', filters.facet);
    if (filters.sortBy !== 'risk') params.set('sort_by', filters.sortBy);
    if (filters.sortOrder !== 'desc') params.set('sort_order', filters.sortOrder);
    if (page !== 1) params.set('page', String(page));
    if (scope.projectId) params.set('project_id', String(scope.projectId));
    if (scope.applicationId) params.set('product_id', String(scope.applicationId));
    if (scope.sbomId) params.set('sbom_id', String(scope.sbomId));
    const query = params.toString();
    router.replace(query ? `/component-advisor?${query}` : '/component-advisor', { scroll: false });
  }, [filters, page, scope, router]);

  const params = useMemo(() => toParams(filters, scope), [filters, scope]);
  const offset = (page - 1) * pageSize;

  const summaryQuery = useQuery({
    queryKey: ['component-advisor-summary', activeTenantId, params],
    queryFn: ({ signal }) => getAdvisorSummary(params, signal),
    enabled: canRead,
  });
  const listQuery = useQuery({
    queryKey: ['component-advisor-components', activeTenantId, params, page, pageSize],
    queryFn: ({ signal }) =>
      listAdvisorComponents({ ...params, sort_by: filters.sortBy, sort_order: filters.sortOrder, limit: pageSize, offset }, signal),
    placeholderData: (previous, previousQuery) => (previousQuery?.queryKey[1] === activeTenantId ? previous : undefined),
    enabled: canRead,
  });

  function update(patch: Partial<Filters>, focusResults = false) {
    setFilters((current) => ({ ...current, ...patch }));
    setPage(1);
    // Focus management on filter changes (WCAG 2.2): land on the results heading.
    if (focusResults) window.setTimeout(() => resultsHeading.current?.focus(), 0);
  }

  function applyKpi(kpi: AdvisorKpi) {
    update({
      risk: kpi.filter.risk ?? [], lifecycle: kpi.filter.lifecycle ?? [],
      needsReview: Boolean(kpi.filter.needs_review), frequentlyAdopted: Boolean(kpi.filter.frequently_adopted),
      trusted: Boolean(kpi.filter.trusted),
    }, true);
  }

  function toggle<T>(list: T[], value: T): T[] {
    return list.includes(value) ? list.filter((item) => item !== value) : [...list, value];
  }

  function clearAll() {
    setFilters(DEFAULT_FILTERS);
    setSearchInput('');
    setScope({ projectId: null, applicationId: null, sbomId: null });
    setPage(1);
  }

  if (!canRead) {
    return (
      <>
        <TopBar title="Secure Component Advisor" />
        <div className="p-6"><Alert variant="warning">You do not have permission to view the Secure Component Advisor.</Alert></div>
      </>
    );
  }

  const meta = listQuery.data?.meta ?? summaryQuery.data?.meta;
  const error = (summaryQuery.error ?? listQuery.error) as unknown;
  const scopeDenied = error instanceof ApiError && (error.status === 404 || error.status === 403);
  const informationalSupported = meta?.capabilities.informational_severity_supported ?? false;
  const total = listQuery.data?.total ?? 0;
  const totalPages = Math.max(1, Math.ceil(total / pageSize));
  const rows = listQuery.data?.items ?? [];
  const kpis = (summaryQuery.data?.kpis ?? []).filter((kpi) => kpi.render);
  const filtered = filters.risk.length > 0 || filters.lifecycle.length > 0 || filters.needsReview
    || filters.frequentlyAdopted || filters.trusted || Boolean(filters.q);

  return (
    <>
      <TopBar title="Secure Component Advisor" />
      <div className="space-y-4 p-6">
        <p className="text-xs text-hcl-muted">
          Advisory only — nothing here changes a dependency, manifest or SBOM. &ldquo;No Known Actionable
          Vulnerabilities&rdquo; reflects the current snapshot and is not proof of security.
        </p>

        {scopeDenied ? <AdvisorNotice kind="UNAUTHORIZED_SCOPE" /> : null}
        {error && !scopeDenied ? (
          <Alert variant="error">Unable to load component intelligence. <Button size="sm" variant="ghost" onClick={() => { summaryQuery.refetch(); listQuery.refetch(); }}>Retry</Button></Alert>
        ) : null}
        {meta && meta.freshness.coverage.eligible_sboms === 0 ? <AdvisorNotice kind="NO_ACTIVE_SBOM_OCCURRENCES" /> : null}
        {meta && meta.freshness.stale_flags.length > 0 ? (
          <AdvisorNotice kind="STALE_VULNERABILITY_DATA">
            <span className="text-xs">{meta.freshness.stale_flags.map((flag) => flag.replaceAll('_', ' ').toLowerCase()).join(' · ')}</span>
          </AdvisorNotice>
        ) : null}

        <section aria-labelledby="advisor-kpis">
          <h2 id="advisor-kpis" className="sr-only">Key indicators</h2>
          <div className="grid grid-cols-2 gap-3 md:grid-cols-3 xl:grid-cols-5">
            {kpis.map((kpi) => (
              <button
                key={kpi.key}
                type="button"
                onClick={() => applyKpi(kpi)}
                aria-label={`${kpi.label}: ${kpi.status === 'POLICY_NOT_CONFIGURED' ? 'policy not configured' : kpi.value ?? 'unavailable'}. Show these components.`}
                className="rounded-lg border border-gray-200 bg-white p-3 text-left transition hover:border-hcl-blue focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-hcl-blue dark:border-gray-800 dark:bg-gray-900"
              >
                <span className="block text-[10px] font-semibold uppercase tracking-wider text-hcl-muted">{kpi.label}</span>
                <span className="mt-1 block text-xl font-semibold text-hcl-navy dark:text-gray-100">
                  {kpi.status === 'POLICY_NOT_CONFIGURED' ? <span className="text-sm font-normal text-hcl-muted">Policy not configured</span> : kpi.value ?? '—'}
                </span>
              </button>
            ))}
            {summaryQuery.isLoading ? <p className="text-sm text-hcl-muted" role="status">Loading indicators…</p> : null}
          </div>
        </section>

        <Card>
          <div className="border-b border-gray-200 p-3 dark:border-gray-800">
            <DashboardFilters scope={scope} hideClear onChange={(next) => { setScope(next); setPage(1); }} isUpdating={listQuery.isFetching} />
          </div>
          <TableFilterBar>
            <TableSearchInput value={searchInput} onChange={setSearchInput} label="Search components" placeholder="Name, PURL, supplier, ecosystem, category or purpose…" />
            <Select label="Search in" value={filters.facet} onChange={(event) => update({ facet: event.target.value as AdvisorFacet })}>
              {(Object.keys(FACET_LABELS) as AdvisorFacet[]).map((facet) => <option key={facet} value={facet}>{FACET_LABELS[facet]}</option>)}
            </Select>
            <Select label="Sort by" value={filters.sortBy} onChange={(event) => update({ sortBy: event.target.value as AdvisorSortField })}>
              {SORT_FIELDS.map((field) => <option key={field} value={field}>{SORT_LABELS[field]}</option>)}
            </Select>
          </TableFilterBar>

          <div className="space-y-2 border-b border-border px-4 py-3">
            <fieldset>
              <legend className="mb-1 text-xs font-semibold text-hcl-muted">Risk</legend>
              <div className="flex flex-wrap gap-2">
                {RISK_FILTERS.map((risk) => {
                  const unsupported = risk === 'INFORMATIONAL' && !informationalSupported;
                  return (
                    <Button key={risk} size="sm" variant={filters.risk.includes(risk) ? 'primary' : 'outline'}
                      aria-pressed={filters.risk.includes(risk)} disabled={unsupported}
                      title={unsupported ? 'The severity model has no informational level' : undefined}
                      onClick={() => update({ risk: toggle(filters.risk, risk) })}>
                      {RISK_LABELS[risk]}{unsupported ? ' (not supported)' : ''}
                    </Button>
                  );
                })}
              </div>
            </fieldset>
            <fieldset>
              <legend className="mb-1 text-xs font-semibold text-hcl-muted">Lifecycle</legend>
              <div className="flex flex-wrap gap-2">
                {LIFECYCLE_FILTERS.map((bucket) => (
                  <Button key={bucket} size="sm" variant={filters.lifecycle.includes(bucket) ? 'primary' : 'outline'}
                    aria-pressed={filters.lifecycle.includes(bucket)} onClick={() => update({ lifecycle: toggle(filters.lifecycle, bucket) })}>
                    {LIFECYCLE_LABELS[bucket]}
                  </Button>
                ))}
                <Button size="sm" variant={filters.needsReview ? 'primary' : 'ghost'} aria-pressed={filters.needsReview} onClick={() => update({ needsReview: !filters.needsReview })}>Requiring review</Button>
                <Button size="sm" variant={filters.frequentlyAdopted ? 'primary' : 'ghost'} aria-pressed={filters.frequentlyAdopted} onClick={() => update({ frequentlyAdopted: !filters.frequentlyAdopted })}>Frequently adopted</Button>
                {meta?.policy_versions.trust ? (
                  <Button size="sm" variant={filters.trusted ? 'primary' : 'ghost'} aria-pressed={filters.trusted} onClick={() => update({ trusted: !filters.trusted })}>Trusted by policy</Button>
                ) : null}
                {filtered || scope.projectId ? <Button size="sm" variant="ghost" onClick={clearAll}>Clear all filters</Button> : null}
              </div>
            </fieldset>
            {meta ? (
              <p className="text-xs text-hcl-muted" data-testid="applied-filters">
                Scope: {meta.scope.level.toLowerCase()} · As of {formatTimestamp(meta.as_of)} · Latest analysis {formatTimestamp(meta.freshness.latest_analysis_at)}
                {' · '}Analysed SBOMs {meta.freshness.coverage.analysed_sboms}/{meta.freshness.coverage.eligible_sboms}
                {meta.unsupported_filters.length ? ` · Unsupported: ${meta.unsupported_filters.join(', ')}` : ''}
              </p>
            ) : null}
          </div>

          <div className="px-4 pt-3">
            <h2 ref={resultsHeading} tabIndex={-1} className="text-sm font-semibold focus:outline-none focus-visible:ring-2 focus-visible:ring-hcl-blue">
              Components
            </h2>
            <p role="status" className="text-xs text-hcl-muted">
              {listQuery.isFetching ? 'Updating components…' : listQuery.isError ? 'Component results unavailable' : `${total} matching component versions`}
            </p>
          </div>
          {filters.q && (filters.facet === 'category' || filters.facet === 'purpose') && !listQuery.isFetching && total === 0 ? (
            <div className="px-4 py-2"><AdvisorNotice kind="INSUFFICIENT_PURPOSE_EVIDENCE" /></div>
          ) : null}

          <Table ariaLabel="Component versions">
            <TableHead>
              <tr>
                <Th scope="colgroup" colSpan={3} resizable={false}>Identity</Th>
                <Th scope="colgroup" colSpan={3} resizable={false}>Risk</Th>
                <Th scope="colgroup" colSpan={3} resizable={false}>Usage</Th>
                <Th scope="colgroup" colSpan={1} resizable={false}>Lifecycle</Th>
                <Th scope="colgroup" colSpan={3} resizable={false}>Decision support</Th>
              </tr>
              <tr>
                <Th>Component</Th><Th>Version</Th><Th>Supplier / ecosystem</Th>
                <Th>Classification</Th><Th>Actionable</Th><Th>Severity / CVSS</Th>
                <Th>SBOMs</Th><Th>Projects</Th><Th>Products</Th>
                <Th>Status</Th>
                <Th>Purpose</Th><Th>Recommendation</Th><Th>Evidence freshness</Th>
              </tr>
            </TableHead>
            <TableBody>
              {listQuery.isLoading ? <SkeletonRow cols={13} /> : listQuery.isError ? null : rows.length === 0 ? (
                <tr><td colSpan={13} className="p-6"><AdvisorNotice kind="NO_MATCHING_COMPONENTS" /></td></tr>
              ) : rows.map((row) => <ComponentRow key={row.canonical_key} row={row} scope={scope} />)}
            </TableBody>
          </Table>

          <Pagination
            page={page} pageSize={pageSize} total={total} totalPages={totalPages}
            rangeStart={total === 0 ? 0 : offset + 1} rangeEnd={Math.min(offset + pageSize, total)}
            hasPrev={page > 1} hasNext={page < totalPages} onPageChange={setPage}
            onPageSizeChange={(size) => { setPageSize(size); setPage(1); }}
            pageSizeOptions={[25, 50, 100, 250]} itemNoun="component version"
          />
        </Card>
      </div>
    </>
  );
}

function ComponentRow({ row, scope }: { row: AdvisorComponent; scope: DashboardFilterScope }) {
  const counts = row.risk.actionable_severity_counts;
  const severity = `Critical ${counts.critical}, High ${counts.high}, Medium ${counts.medium}, Low ${counts.low}`;
  const category = row.purpose.technology_category;
  return (
    <tr>
      <Td>
        <Link href={`/component-advisor/components/${row.canonical_key}${scopeQuery(scope)}`}
          className="font-medium text-hcl-blue underline-offset-4 hover:underline focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-hcl-blue">
          {row.name}
        </Link>
      </Td>
      <Td>{row.version ?? '—'}</Td>
      <Td>
        <span className="block">{row.supplier ?? '—'}</span>
        <span className="block text-[10px] text-hcl-muted">{row.ecosystem ?? 'unknown ecosystem'}{row.purl ? ` · ${row.purl}` : ''}</span>
      </Td>
      <Td>
        <RiskBadge classification={row.risk.classification} />
        {row.risk.review_reasons.length ? <span className="block text-[10px] text-hcl-muted">Needs review: {row.risk.review_reasons.length} reason(s)</span> : null}
      </Td>
      <Td>{row.risk.actionable_vulnerability_count}</Td>
      <Td>
        <span aria-label={severity} className="block text-xs">C{counts.critical} H{counts.high} M{counts.medium} L{counts.low}</span>
        <span className="block text-[10px] text-hcl-muted">CVSS max {row.risk.cvss.max_score ?? '—'}</span>
      </Td>
      <Td>{row.usage.active_sbom_occurrences}</Td>
      <Td>{row.usage.project_count}</Td>
      <Td>{row.usage.product_count}</Td>
      <Td>
        <LifecycleBadge bucket={row.lifecycle.bucket} />
        {row.lifecycle.effective_date ? <span className="block text-[10px] text-hcl-muted">{row.lifecycle.effective_date}</span> : null}
      </Td>
      <Td>
        {category ? <><span className="block text-xs">{category.value}</span><ProvenanceBadge field={category} /></> : <span className="text-xs text-hcl-muted">Not available</span>}
      </Td>
      <Td>{STATUS_LABELS[row.recommendation.status] ?? row.recommendation.status}</Td>
      <Td><span className="text-xs">{formatTimestamp(row.freshness.latest_analysis_at)}</span></Td>
    </tr>
  );
}

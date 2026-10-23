'use client';

import { useEffect, useState } from 'react';
import { useRouter } from 'next/navigation';
import { useQuery } from '@tanstack/react-query';
import { FileJson, GitCompareArrows } from 'lucide-react';
import { Button } from '@/components/ui/Button';
import { Select } from '@/components/ui/Select';
import { TableSearchInput } from '@/components/ui/TableFilterBar';
import { RunsTable, type RunSortKey } from './RunsTable';
import { getRunsPage, getRunsAggregate, exportRunsJson, type RunsFilter } from '@/lib/api';
import { runStatusShortLabel } from '@/lib/analysisRunStatusLabels';
import { getApiErrorMessage } from '@/lib/notifications';
import { useToast } from '@/hooks/useToast';
import { useAuth } from '@/hooks/useAuth';
import type { AnalysisRun } from '@/types';

export function AnalysisRunsHistory({ scope, status, onStatusChange }: {
  scope: RunsFilter; status: string; onStatusChange: (status: string) => void;
}) {
  const { activeTenantId } = useAuth();
  const router = useRouter();
  const { showToast } = useToast();
  const [page, setPage] = useState(1);
  const [pageSize, setPageSize] = useState(25);
  const [search, setSearch] = useState('');
  const [query, setQuery] = useState('');
  const [source, setSource] = useState('');
  const [order, setOrder] = useState<{ key: RunSortKey; direction: 'asc' | 'desc' }>({ key: 'completed_on', direction: 'desc' });
  const [selected, setSelected] = useState<Map<string, AnalysisRun>>(new Map());
  const [exporting, setExporting] = useState(false);
  useEffect(() => {
    if (search.trim() === query) return;
    const timer = setTimeout(() => { setQuery(search.trim()); setPage(1); }, 250);
    return () => clearTimeout(timer);
  }, [search, query]);
  const filter: RunsFilter = { ...scope, run_status: status || undefined, q: query || undefined,
    source: source || undefined, sort_by: order.key, sort_direction: order.direction };
  const runs = useQuery({
    queryKey: ['runs', activeTenantId, filter, page, pageSize],
    queryFn: ({ signal }) => getRunsPage({ ...filter, page, page_size: pageSize, summary_only: true }, signal),
    refetchInterval: query => query.state.data?.items.some(run => ['RUNNING', 'PENDING'].includes(run.run_status)) ? 5000 : false,
  });
  const aggregate = useQuery({
    queryKey: ['runs-aggregate', activeTenantId, scope],
    queryFn: ({ signal }) => getRunsAggregate(scope, signal),
  });
  useEffect(() => {
    if (runs.data && page > Math.max(1, Math.ceil(runs.data.total / pageSize))) setPage(1);
  }, [runs.data, page, pageSize]);
  const toggle = (id: string) => setSelected(previous => {
    const next = new Map(previous);
    if (next.has(id)) next.delete(id);
    else {
      const run = runs.data?.items.find(run => run.id === id);
      if (!run || run.processing_eligibility?.eligible === false) return previous;
      if (next.size === 2) next.delete(next.keys().next().value!);
      next.set(id, run);
    }
    return next;
  });
  const exportJson = async () => {
    setExporting(true);
    try { await exportRunsJson(filter); showToast('Analysis runs were exported successfully.', 'success'); }
    catch (error) { showToast(getApiErrorMessage(error, 'Analysis export failed. Please try again.'), 'error'); }
    finally { setExporting(false); }
  };
  return <div className="min-w-0 space-y-4">
    {aggregate.data && <div className="grid grid-cols-2 gap-3 lg:grid-cols-4" aria-label="Historical run totals">
      {[
        ['Total runs', aggregate.data.total_runs], ['With findings', aggregate.data.by_outcome.with_findings],
        ['Incomplete coverage', aggregate.data.by_outcome.source_errors], ['Failed', aggregate.data.by_outcome.failed],
      ].map(([label, value]) => <div key={label} className="rounded-xl border border-border bg-surface px-4 py-3"><p className="text-xs text-hcl-muted">{label}</p><p className="mt-1 text-2xl font-semibold tabular-nums text-hcl-navy">{value.toLocaleString()}</p></div>)}
      <p className="col-span-full text-xs text-hcl-muted">Scope totals include current eligible runs across all outcomes. Search and outcome filters apply to the history table below.</p>
    </div>}
    <div className="rounded-xl border border-border bg-surface p-4">
      <div className="grid items-end gap-3 sm:grid-cols-2 xl:grid-cols-[minmax(12rem,1fr)_14rem_10rem_auto]">
        <TableSearchInput value={search} onChange={setSearch} label="Search runs" placeholder="Run ID, project, product, SBOM or source…" />
        <Select label="Status" aria-label="Status" value={status} onChange={event => { setPage(1); onStatusChange(event.target.value); }}>
          <option value="">All outcomes</option>{['OK', 'FINDINGS', 'PARTIAL', 'NO_DATA', 'ERROR', 'INTERRUPTED', 'RUNNING', 'PENDING'].map(value => <option key={value} value={value}>{runStatusShortLabel(value)}</option>)}
        </Select>
        <Select label="Source" aria-label="Source" value={source} onChange={event => { setSource(event.target.value); setPage(1); }}>
          <option value="">All sources</option>{['NVD', 'OSV', 'GITHUB', 'BACKFILL'].map(value => <option key={value} value={value}>{value === 'GITHUB' ? 'GHSA' : value}</option>)}
        </Select>
        <Button variant="secondary" size="sm" disabled={!search && !status && !source} onClick={() => { setSearch(''); setQuery(''); setSource(''); onStatusChange(''); setPage(1); }}>Clear table filters</Button>
      </div>
    </div>
    <div className="flex flex-wrap items-center justify-between gap-3">
      <p className="text-sm text-hcl-muted" role="status">{selected.size ? `${selected.size} of 2 runs selected for comparison` : 'Select two eligible runs to compare. Selection carries across pages.'}</p>
      <div className="flex flex-wrap gap-2">
        {selected.size > 0 && <Button variant="ghost" size="sm" onClick={() => setSelected(new Map())}>Clear selection</Button>}
        <Button variant="secondary" size="sm" disabled={selected.size !== 2} onClick={() => {
          const [a, b] = [...selected.keys()]; router.push(`/analysis/compare?run_a=${a}&run_b=${b}`);
        }}><GitCompareArrows className="h-4 w-4" aria-hidden />Compare ({selected.size}/2)</Button>
        <Button variant="secondary" size="sm" loading={exporting} disabled={search.trim() !== query} onClick={exportJson}><FileJson className="h-4 w-4" aria-hidden />Export JSON</Button>
      </div>
    </div>
    <RunsTable runs={runs.data?.items} isLoading={runs.isLoading} error={runs.error} onRetry={() => { void runs.refetch(); }}
      selectedIds={new Set(selected.keys())} onToggleSelect={toggle}
      serverPage={{ page, pageSize, total: runs.data?.total ?? 0, sortBy: order.key, direction: order.direction,
        onPageChange: setPage, onPageSizeChange: size => { setPageSize(size); setPage(1); },
        onSort: key => { setOrder(previous => ({ key, direction: previous.key === key && previous.direction === 'desc' ? 'asc' : 'desc' })); setPage(1); } }} />
  </div>;
}

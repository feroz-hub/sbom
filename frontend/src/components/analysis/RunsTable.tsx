'use client';

import { useEffect, useMemo, useState } from 'react';
import { useRouter } from 'next/navigation';
import { Eye, Download } from 'lucide-react';
import { Alert } from '@/components/ui/Alert';
import { Select } from '@/components/ui/Select';
import { Table, TableHead, TableBody, Th, SortableTh, Td, EmptyRow } from '@/components/ui/Table';
import { TableFilterBar, TableSearchInput } from '@/components/ui/TableFilterBar';
import { StatusBadge } from '@/components/ui/Badge';
import { SkeletonRow } from '@/components/ui/Spinner';
import { Pagination } from '@/components/ui/Pagination';
import { downloadPdfReport } from '@/lib/api';
import { runStatusShortLabel } from '@/lib/analysisRunStatusLabels';
import { matchesMultiField } from '@/lib/tableFilters';
import { formatDate, formatDuration, downloadBlob } from '@/lib/utils';
import { useToast } from '@/hooks/useToast';
import { useTableSort } from '@/hooks/useTableSort';
import { usePagination } from '@/hooks/usePagination';
import type { AnalysisRun } from '@/types';

type RunSortKey =
  | 'id'
  | 'sbom_name'
  | 'run_status'
  | 'total_components'
  | 'total_findings'
  | 'query_error_count'
  | 'duration_ms'
  | 'completed_on';

interface RunsTableProps {
  runs: AnalysisRun[] | undefined;
  isLoading: boolean;
  error: Error | null;
  /** Optional multi-select state for the Compare Runs flow. When provided,
   *  the table renders a checkbox in the first column. */
  selectedIds?: Set<number>;
  onToggleSelect?: (id: number) => void;
}

const STATUS_VALUES: AnalysisRun['run_status'][] = [
  'PASS',
  'FAIL',
  'PARTIAL',
  'ERROR',
  'RUNNING',
  'PENDING',
  'NO_DATA',
];

export function RunsTable({ runs, isLoading, error, selectedIds, onToggleSelect }: RunsTableProps) {
  const selectable = Boolean(onToggleSelect);
  const colCount = selectable ? 12 : 11;
  const router = useRouter();
  const { showToast } = useToast();
  const [downloadingId, setDownloadingId] = useState<number | null>(null);
  const [search, setSearch] = useState('');
  const [statusFilter, setStatusFilter] = useState('');
  const [sourceFilter, setSourceFilter] = useState('');

  const handleDownloadPdf = async (run: AnalysisRun) => {
    setDownloadingId(run.id);
    try {
      const blob = await downloadPdfReport({
        runId: run.id,
        title: `Analysis Report - Run #${run.id}`,
        filename: `sbom-analysis-run-${run.id}.pdf`,
      });
      downloadBlob(blob, `sbom-analysis-run-${run.id}.pdf`);
      showToast('PDF report downloaded', 'success');
    } catch (err) {
      showToast(`Failed to download PDF: ${(err as Error).message}`, 'error');
    } finally {
      setDownloadingId(null);
    }
  };

  const sourceOptions = useMemo(() => {
    const set = new Set<string>();
    runs?.forEach((r) => {
      if (r.source?.trim()) {
        r.source.split(',').forEach((s) => set.add(s.trim()));
      }
    });
    return Array.from(set).sort((a, b) => a.localeCompare(b));
  }, [runs]);

  const filteredRuns = useMemo(() => {
    if (!runs?.length) return [];
    let rows = runs;
    if (statusFilter) {
      rows = rows.filter((r) => r.run_status === statusFilter);
    }
    if (sourceFilter) {
      rows = rows.filter((r) =>
        (r.source ?? '')
          .toLowerCase()
          .includes(sourceFilter.toLowerCase()),
      );
    }
    if (search.trim()) {
      rows = rows.filter((r) =>
        matchesMultiField(search, [
          String(r.id),
          r.sbom_name,
          r.source,
          String(r.sbom_id ?? ''),
          String(r.total_findings ?? ''),
          formatDate(r.completed_on),
        ]),
      );
    }
    return rows;
  }, [runs, search, statusFilter, sourceFilter]);

  const filtersActive = Boolean(search.trim() || statusFilter || sourceFilter);
  const clearFilters = () => {
    setSearch('');
    setStatusFilter('');
    setSourceFilter('');
  };

  const sortAccessors = useMemo(
    () => ({
      id: (r: AnalysisRun) => r.id,
      sbom_name: (r: AnalysisRun) => (r.sbom_name ?? '').toLowerCase(),
      run_status: (r: AnalysisRun) => r.run_status ?? '',
      total_components: (r: AnalysisRun) => r.total_components ?? -1,
      total_findings: (r: AnalysisRun) => r.total_findings ?? -1,
      query_error_count: (r: AnalysisRun) => r.query_error_count ?? -1,
      duration_ms: (r: AnalysisRun) => r.duration_ms ?? -1,
      completed_on: (r: AnalysisRun) => r.completed_on ?? '',
    }),
    [],
  );

  const { sort, sortedRows, toggle: toggleSort } = useTableSort<AnalysisRun, RunSortKey>(
    filteredRuns,
    sortAccessors,
    { initialKey: 'id', initialDirection: 'desc' },
  );

  const pagination = usePagination<AnalysisRun>(sortedRows, {
    defaultPageSize: 25,
    storageKey: 'runs',
  });

  useEffect(() => {
    pagination.resetPage();
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [search, statusFilter, sourceFilter]);

  if (error) {
    return (
      <Alert variant="error" title="Could not load analysis runs">
        {error.message}
      </Alert>
    );
  }

  const total = runs?.length ?? 0;
  const shown = filteredRuns.length;

  return (
    <div className="overflow-hidden rounded-xl border border-hcl-border bg-surface shadow-card">
      {!isLoading && total > 0 ? (
        <TableFilterBar
          onClear={clearFilters}
          clearDisabled={!filtersActive}
          resultHint={
            filtersActive ? `Showing ${shown} of ${total}` : `${total} run${total === 1 ? '' : 's'}`
          }
        >
          <TableSearchInput
            value={search}
            onChange={setSearch}
            placeholder="Run ID, SBOM name, source…"
            label="Search"
          />
          <div className="w-full min-w-[10rem] sm:w-44">
            <Select
              label="Status"
              value={statusFilter}
              onChange={(e) => setStatusFilter(e.target.value)}
              className="w-full"
            >
              <option value="">All outcomes</option>
              {STATUS_VALUES.map((s) => (
                <option key={s} value={s}>
                  {runStatusShortLabel(s)}
                </option>
              ))}
            </Select>
          </div>
          <div className="w-full min-w-[10rem] sm:w-44">
            <Select
              label="Source"
              value={sourceFilter}
              onChange={(e) => setSourceFilter(e.target.value)}
              className="w-full"
            >
              <option value="">All sources</option>
              {sourceOptions.map((s) => (
                <option key={s} value={s}>
                  {s}
                </option>
              ))}
            </Select>
          </div>
        </TableFilterBar>
      ) : null}

      <Table striped>
        <TableHead>
          <tr>
            {selectable && (
              <Th className="w-8">
                <span className="sr-only">Select</span>
              </Th>
            )}
            <SortableTh
              sortKey="id"
              activeKey={sort.key}
              direction={sort.direction}
              onToggle={(k) => toggleSort(k as RunSortKey)}
            >
              Run ID
            </SortableTh>
            <SortableTh
              sortKey="sbom_name"
              activeKey={sort.key}
              direction={sort.direction}
              onToggle={(k) => toggleSort(k as RunSortKey)}
            >
              SBOM
            </SortableTh>
            <SortableTh
              sortKey="run_status"
              activeKey={sort.key}
              direction={sort.direction}
              onToggle={(k) => toggleSort(k as RunSortKey)}
            >
              Status
            </SortableTh>
            <Th>Source</Th>
            <SortableTh
              sortKey="total_components"
              activeKey={sort.key}
              direction={sort.direction}
              onToggle={(k) => toggleSort(k as RunSortKey)}
            >
              Components
            </SortableTh>
            <Th>With CPE</Th>
            <SortableTh
              sortKey="total_findings"
              activeKey={sort.key}
              direction={sort.direction}
              onToggle={(k) => toggleSort(k as RunSortKey)}
            >
              Findings
            </SortableTh>
            <SortableTh
              sortKey="query_error_count"
              activeKey={sort.key}
              direction={sort.direction}
              onToggle={(k) => toggleSort(k as RunSortKey)}
            >
              Errors
            </SortableTh>
            <SortableTh
              sortKey="duration_ms"
              activeKey={sort.key}
              direction={sort.direction}
              onToggle={(k) => toggleSort(k as RunSortKey)}
            >
              Duration
            </SortableTh>
            <SortableTh
              sortKey="completed_on"
              activeKey={sort.key}
              direction={sort.direction}
              onToggle={(k) => toggleSort(k as RunSortKey)}
            >
              Completed On
            </SortableTh>
            <Th className="text-right">Actions</Th>
          </tr>
        </TableHead>
        <TableBody>
          {isLoading ? (
            Array.from({ length: 5 }).map((_, i) => <SkeletonRow key={i} cols={colCount} />)
          ) : !runs?.length ? (
            <EmptyRow
              cols={colCount}
              message="No analysis runs found. Run an analysis from an SBOM detail page."
            />
          ) : !filteredRuns.length ? (
            <EmptyRow
              cols={colCount}
              message="No runs match your filters. Try adjusting search or clear filters."
            />
          ) : (
            pagination.pageItems.map((run) => (
              <tr
                key={run.id}
                className="cursor-pointer transition-colors hover:bg-hcl-light/40"
                onClick={() => router.push(`/analysis/${run.id}`)}
              >
                {selectable && (
                  <Td onClick={(e) => e.stopPropagation()} className="w-8">
                    <input
                      type="checkbox"
                      aria-label={`Select run #${run.id} for comparison`}
                      checked={selectedIds?.has(run.id) ?? false}
                      onChange={() => onToggleSelect?.(run.id)}
                      className="h-4 w-4 rounded border-hcl-border text-hcl-blue focus:ring-hcl-blue"
                    />
                  </Td>
                )}
                <Td className="font-mono text-xs text-hcl-muted">#{run.id}</Td>
                <Td className="max-w-[140px] truncate font-medium text-hcl-navy">
                  {run.sbom_name || (run.sbom_id ? `SBOM #${run.sbom_id}` : '—')}
                </Td>
                <Td onClick={(e) => e.stopPropagation()}>
                  <StatusBadge status={run.run_status} />
                </Td>
                <Td className="text-xs text-hcl-muted">{run.source || '—'}</Td>
                <Td className="text-foreground/90">{run.total_components ?? '—'}</Td>
                <Td className="text-foreground/90">{run.components_with_cpe ?? '—'}</Td>
                <Td onClick={(e) => e.stopPropagation()}>
                  <div className="flex flex-wrap items-center gap-1">
                    {run.critical_count != null && run.critical_count > 0 && (
                      <span className="inline-flex items-center rounded bg-red-50 px-1.5 py-0.5 text-xs font-medium text-red-700 dark:bg-red-950/40 dark:text-red-200">
                        C:{run.critical_count}
                      </span>
                    )}
                    {run.high_count != null && run.high_count > 0 && (
                      <span className="inline-flex items-center rounded bg-orange-50 px-1.5 py-0.5 text-xs font-medium text-orange-700 dark:bg-orange-950/40 dark:text-orange-200">
                        H:{run.high_count}
                      </span>
                    )}
                    {run.medium_count != null && run.medium_count > 0 && (
                      <span className="inline-flex items-center rounded bg-amber-50 px-1.5 py-0.5 text-xs font-medium text-amber-700 dark:bg-amber-950/40 dark:text-amber-200">
                        M:{run.medium_count}
                      </span>
                    )}
                    {run.low_count != null && run.low_count > 0 && (
                      <span className="inline-flex items-center rounded bg-hcl-light px-1.5 py-0.5 text-xs font-medium text-hcl-blue">
                        L:{run.low_count}
                      </span>
                    )}
                    {run.total_findings === 0 && (
                      <span className="text-xs text-hcl-muted">None</span>
                    )}
                    {run.total_findings == null && (
                      <span className="text-xs text-hcl-muted">—</span>
                    )}
                  </div>
                </Td>
                <Td className="text-foreground/90">
                  {run.query_error_count != null && run.query_error_count > 0 ? (
                    <span className="text-xs font-medium text-orange-600">{run.query_error_count}</span>
                  ) : (
                    <span className="text-hcl-muted">{run.query_error_count ?? '—'}</span>
                  )}
                </Td>
                <Td className="whitespace-nowrap text-hcl-muted">{formatDuration(run.duration_ms)}</Td>
                <Td className="whitespace-nowrap text-hcl-muted">{formatDate(run.completed_on)}</Td>
                <Td className="text-right" onClick={(e) => e.stopPropagation()}>
                  <div className="flex items-center justify-end gap-2">
                    <button
                      onClick={() => router.push(`/analysis/${run.id}`)}
                      className="rounded-lg p-1.5 text-hcl-muted transition-colors hover:bg-hcl-light hover:text-hcl-blue"
                      aria-label="View run"
                    >
                      <Eye className="h-4 w-4" />
                    </button>
                    <button
                      onClick={() => handleDownloadPdf(run)}
                      disabled={downloadingId === run.id}
                      className="rounded-lg p-1.5 text-hcl-muted transition-colors hover:bg-green-50 hover:text-green-600 disabled:opacity-50 dark:hover:bg-emerald-950/40"
                      aria-label="Download PDF"
                    >
                      <Download className="h-4 w-4" />
                    </button>
                  </div>
                </Td>
              </tr>
            ))
          )}
        </TableBody>
      </Table>

      {!isLoading && filteredRuns.length > 0 ? (
        <Pagination
          page={pagination.page}
          pageSize={pagination.pageSize}
          total={pagination.total}
          totalPages={pagination.totalPages}
          rangeStart={pagination.rangeStart}
          rangeEnd={pagination.rangeEnd}
          hasPrev={pagination.hasPrev}
          hasNext={pagination.hasNext}
          onPageChange={pagination.setPage}
          onPageSizeChange={pagination.setPageSize}
          itemNoun="run"
        />
      ) : null}
    </div>
  );
}

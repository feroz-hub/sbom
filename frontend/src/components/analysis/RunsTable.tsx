'use client';

import Link from 'next/link';
import { useMemo, useState } from 'react';
import { Copy, Download, Eye } from 'lucide-react';
import { Alert } from '@/components/ui/Alert';
import { Table, TableHead, TableBody, Th, SortableTh, Td, EmptyRow } from '@/components/ui/Table';
import { TableFilterBar, TableSearchInput } from '@/components/ui/TableFilterBar';
import { Select } from '@/components/ui/Select';
import { StatusBadge } from '@/components/ui/Badge';
import { PinButton } from '@/components/ui/PinButton';
import { SkeletonRow } from '@/components/ui/Spinner';
import { Pagination } from '@/components/ui/Pagination';
import { RunSeveritySummary } from './RunSeveritySummary';
import { downloadPdfReport, type RunsFilter } from '@/lib/api';
import { canonicalRunStatus, runStatusShortLabel } from '@/lib/analysisRunStatusLabels';
import { recordIdLabel } from '@/lib/recordDisplay';
import { formatDate, formatDuration, downloadBlob } from '@/lib/utils';
import { useToast } from '@/hooks/useToast';
import { getApiErrorMessage } from '@/lib/notifications';
import type { AnalysisRun } from '@/types';

export type RunSortKey = NonNullable<RunsFilter['sort_by']>;
export interface RunTablePage {
  page: number; pageSize: number; total: number;
  sortBy: RunSortKey; direction: 'asc' | 'desc';
  onPageChange: (page: number) => void; onPageSizeChange: (size: number) => void;
  onSort: (key: RunSortKey) => void;
}
interface RunsTableProps {
  runs: AnalysisRun[] | undefined; isLoading: boolean; error: Error | null;
  selectedIds?: Set<string>; onToggleSelect?: (id: string) => void;
  serverPage?: RunTablePage;
  compact?: boolean;
  onRetry?: () => void;
}
const statuses = ['OK', 'FINDINGS', 'PARTIAL', 'ERROR', 'INTERRUPTED', 'RUNNING', 'PENDING', 'NO_DATA'];

/** History receives one server page; compact mode renders at most five recent runs. */
export function RunsTable({ runs, isLoading, error, selectedIds, onToggleSelect, serverPage, compact, onRetry }: RunsTableProps) {
  const { showToast } = useToast();
  const [downloadingId, setDownloadingId] = useState<string | null>(null);
  // Retain local use for existing embedded callers; the history page owns server filters.
  const [search, setSearch] = useState('');
  const [status, setStatus] = useState('');
  const localRows = useMemo(() => (runs ?? []).filter(run =>
    (!status || canonicalRunStatus(run.run_status) === status) &&
    (!search.trim() || [run.id, run.display_id, run.sbom_name, run.source, run.project_name, run.product_name]
      .some(value => String(value ?? '').toLowerCase().includes(search.trim().toLowerCase())))), [runs, search, status]);
  const rows = serverPage ? runs ?? [] : compact ? (runs ?? []).slice(0, 5) : localRows;
  const count = onToggleSelect ? 9 : 8;
  const download = async (run: AnalysisRun) => {
    if (run.processing_eligibility?.eligible === false) return;
    setDownloadingId(run.id);
    try {
      const blob = await downloadPdfReport({ runId: run.id, title: `Analysis Report - ${recordIdLabel('Run', run.display_id)}`, filename: `sbom-analysis-run-${run.id}.pdf` });
      downloadBlob(blob, `sbom-analysis-run-${run.id}.pdf`);
      showToast('The report is ready for download.', 'success');
    } catch (error) { showToast(getApiErrorMessage(error, 'Report generation failed. Please try again.'), 'error'); }
    finally { setDownloadingId(null); }
  };
  const copy = async (id: string) => {
    try { await navigator.clipboard.writeText(id); showToast('Run identifier copied.', 'success'); }
    catch { showToast('Could not copy the run identifier.', 'error'); }
  };
  const heading = (key: RunSortKey, label: string) => serverPage
    ? <SortableTh sortKey={key} activeKey={serverPage.sortBy} direction={serverPage.direction} onToggle={value => serverPage.onSort(value as RunSortKey)}>{label}</SortableTh>
    : <Th>{label}</Th>;
  const totalPages = Math.max(1, Math.ceil((serverPage?.total ?? 0) / (serverPage?.pageSize ?? 25)));
  return <div className="min-w-0 overflow-hidden rounded-xl border border-border bg-surface shadow-card" aria-busy={isLoading}>
    {error && <Alert variant="error" title="Could not load analysis runs">{error.message}{onRetry && <button type="button" className="ml-2 underline" onClick={onRetry}>Retry</button>}</Alert>}
    {!serverPage && !compact && <TableFilterBar onClear={() => { setSearch(''); setStatus(''); }} clearDisabled={!search && !status}>
      <TableSearchInput value={search} onChange={setSearch} label="Search" placeholder="Run ID, SBOM, source…" />
      <Select label="Status" value={status} onChange={event => setStatus(event.target.value)}><option value="">All outcomes</option>{statuses.map(value => <option key={value} value={value}>{runStatusShortLabel(value)}</option>)}</Select>
    </TableFilterBar>}
    <Table striped ariaLabel={compact ? 'Recent analysis runs' : 'Analysis runs table'}>
      <TableHead><tr>
        {onToggleSelect && <Th resizable={false}><span className="sr-only">Select for comparison</span></Th>}
        {heading('id', 'Analysis run')}<Th>Project / Product</Th>{heading('sbom_name', 'SBOM')}
        {heading('run_status', 'Status')}{heading('total_findings', 'Findings')}<Th>Severity</Th>
        {heading('completed_on', 'Analyzed at')}<Th>Actions</Th>
      </tr></TableHead>
      <TableBody>
        {isLoading ? Array.from({ length: compact ? 3 : 5 }, (_, i) => <SkeletonRow key={i} cols={count} />)
          : error ? <EmptyRow cols={count} message="Run history is unavailable. Retry the request above." />
          : !rows.length ? <EmptyRow cols={count} message="No analysis runs match this selection. Adjust filters or start a consolidated analysis." />
          : rows.map(run => <tr key={run.id}>
            {onToggleSelect && <Td><input type="checkbox" aria-label={`Select ${recordIdLabel('Run', run.display_id)} for comparison`}
              checked={selectedIds?.has(run.id) ?? false} disabled={run.processing_eligibility?.eligible === false}
              title={run.processing_eligibility?.reason ?? undefined} onChange={() => onToggleSelect(run.id)}
              className="h-4 w-4 rounded border-border accent-hcl-blue" /></Td>}
            <Td><div className="flex items-center gap-1">
              <Link className="whitespace-nowrap font-semibold text-primary underline-offset-2 hover:underline focus-visible:outline focus-visible:outline-primary" href={`/analysis/${run.id}`}>{recordIdLabel('', run.display_id)}</Link>
              <button type="button" onClick={() => copy(run.id)} aria-label={`Copy identifier for ${recordIdLabel('Run', run.display_id)}`} title="Copy full run identifier" className="rounded p-1 text-hcl-muted hover:bg-surface-muted focus-visible:outline focus-visible:outline-primary"><Copy className="h-3.5 w-3.5" aria-hidden /></button>
              {!compact && <PinButton kind="run" id={run.id} label={`${run.sbom_name ?? 'Analysis'} · ${recordIdLabel('Run', run.display_id)}`} href={`/analysis/${run.id}`} compact hoverOnly />}
            </div></Td>
            <Td><div className="min-w-[8rem] max-w-[12rem] break-words text-xs"><p className="font-medium">{run.project_name || 'Unassigned project'}</p><p className="mt-1 text-hcl-muted">{run.product_name || 'Unassigned product'}</p></div></Td>
            <Td><div className="min-w-[9rem] max-w-[15rem] break-words"><p className="font-medium">{run.sbom_name || 'Unavailable SBOM'}</p><p className="mt-1 text-xs text-hcl-muted">Version {run.sbom_version || 'unavailable'}</p></div></Td>
            <Td><StatusBadge status={run.run_status} /><p className="mt-1 text-xs text-hcl-muted">{run.source || 'Source unavailable'}</p>
              {(run.query_error_count ?? 0) > 0 && <p className="mt-1 text-xs text-amber-700 dark:text-amber-300">{run.query_error_count} source errors</p>}
              {run.is_current === false && <p className="mt-1 text-xs text-hcl-muted">Historical evidence</p>}</Td>
            <Td><span className="font-semibold tabular-nums">{run.total_findings?.toLocaleString() ?? '—'}</span>{run.total_findings === 0 && <span className="sr-only">None</span>}</Td>
            <Td><RunSeveritySummary run={run} /></Td>
            <Td><p className="whitespace-nowrap text-xs">{['PENDING', 'RUNNING'].includes(canonicalRunStatus(run.run_status)) ? 'Awaiting completion' : formatDate(run.completed_on)}</p><p className="mt-1 whitespace-nowrap text-xs text-hcl-muted">{formatDuration(run.duration_ms)}</p></Td>
            <Td><div className="flex items-center gap-1">
              <Link href={`/analysis/${run.id}`} aria-label="View run" title="View run details" className="rounded-lg p-2 text-primary hover:bg-surface-muted focus-visible:outline focus-visible:outline-primary"><Eye className="h-4 w-4" aria-hidden /></Link>
              {!compact && <button type="button" onClick={() => download(run)} disabled={downloadingId === run.id || run.processing_eligibility?.eligible === false}
                title={run.processing_eligibility?.reason || 'Download PDF'} aria-label="Download PDF" className="rounded-lg p-2 text-hcl-muted hover:bg-surface-muted disabled:opacity-40 focus-visible:outline focus-visible:outline-primary"><Download className="h-4 w-4" aria-hidden /></button>}
            </div></Td>
          </tr>)}
      </TableBody>
    </Table>
    {serverPage && !isLoading && !error && <Pagination page={serverPage.page} pageSize={serverPage.pageSize} total={serverPage.total} totalPages={totalPages}
      rangeStart={serverPage.total ? (serverPage.page - 1) * serverPage.pageSize + 1 : 0} rangeEnd={Math.min(serverPage.page * serverPage.pageSize, serverPage.total)}
      hasPrev={serverPage.page > 1} hasNext={serverPage.page < totalPages} onPageChange={serverPage.onPageChange} onPageSizeChange={serverPage.onPageSizeChange} itemNoun="run" />}
  </div>;
}

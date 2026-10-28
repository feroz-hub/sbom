'use client';

import { useId, useMemo, useState } from 'react';
import Link from 'next/link';
import { useQuery } from '@tanstack/react-query';
import { useAuth } from '@/hooks/useAuth';
import { getDashboardPostureVersions, type DashboardFilterScope } from '@/lib/api';
import { Alert } from '@/components/ui/Alert';
import { Button } from '@/components/ui/Button';
import { Badge } from '@/components/ui/Badge';
import { Pagination } from '@/components/ui/Pagination';
import { Skeleton } from '@/components/ui/Spinner';
import { Table, TableHead, TableBody, Th, Td } from '@/components/ui/Table';
import { TableSearchInput } from '@/components/ui/TableFilterBar';
import { formatDate } from '@/lib/utils';
import type { SbomPosture, SbomPostureSummary } from '@/types';

function VersionIdentity({ version }: { version: SbomPosture['current_sbom'] }) {
  return version ? <div className="max-w-56 break-words">
    <span className="block font-medium text-hcl-navy">{version.name}</span>
    <span className="text-xs text-hcl-muted">{version.version || 'Version unavailable'}</span>
  </div> : <span className="text-hcl-muted">Unavailable</span>;
}

function EvidenceTable({ items }: { items: SbomPosture[] }) {
  const [search, setSearch] = useState('');
  const [page, setPage] = useState(1);
  const [pageSize, setPageSize] = useState(10);
  const matches = useMemo(() => {
    const needle = search.trim().toLowerCase();
    return items.filter(item => !needle || [item.application_name, item.analysis_run_id, item.analysis_status, item.warning,
      ...[item.current_sbom, item.effective_current_sbom, item.latest_uploaded, item.latest_analyzed, item.posture_sbom]
        .flatMap(version => [version?.name, version?.version]),
    ].some(value => value?.toLowerCase().includes(needle)));
  }, [items, search]);
  const totalPages = Math.max(1, Math.ceil(matches.length / pageSize));
  const currentPage = Math.min(page, totalPages);
  const offset = (currentPage - 1) * pageSize;
  return <div className="space-y-3 border-t border-border pt-3">
    <div className="px-4"><TableSearchInput label="Search version evidence" value={search}
      onChange={value => { setSearch(value); setPage(1); }} placeholder="Application, SBOM, version or analysis run…" /></div>
    <Table ariaLabel="SBOM version evidence table" striped>
      <TableHead><tr><Th>Application</Th><Th>Current SBOM</Th><Th>Latest uploaded</Th><Th>Latest analyzed</Th><Th>Analysis evidence</Th></tr></TableHead>
      <TableBody>{matches.slice(offset, offset + pageSize).map((item, index) => {
        const current = item.effective_current_sbom === undefined ? item.current_sbom : item.effective_current_sbom;
        return <tr key={`${item.product_id}-${item.target_sbom_id}-${item.posture_sbom_id}-${offset + index}`}>
          <Td className="max-w-48 break-words font-medium">{item.application_name || item.current_sbom?.name || 'Application unavailable'}</Td>
          <Td><VersionIdentity version={current} /></Td><Td><VersionIdentity version={item.latest_uploaded} /></Td>
          <Td><VersionIdentity version={item.latest_analyzed ?? null} /></Td>
          <Td className="min-w-64 max-w-sm">
            <div className="space-y-2">
              <Badge variant={!item.analysis_run_id || item.last_known_posture || item.coverage_incomplete ? 'warning' : 'info'}>
                {!item.analysis_run_id ? 'No successful analysis' : item.last_known_posture ? 'Last known evidence' : 'Analysis evidence available'}
              </Badge>
              <p className="text-xs text-hcl-muted">Latest upload: {item.analysis_status.toLowerCase().replaceAll('_', ' ')}</p>
              {item.analysis_run_id && <>
                <div className="text-xs text-hcl-muted">Evidence version<VersionIdentity version={item.posture_sbom} /></div>
                <p className="text-xs">Analysis finding rows: <span className="font-semibold tabular-nums">{item.analysis_finding_rows?.toLocaleString() ?? 'Unavailable'}</span></p>
                <p className="text-xs text-hcl-muted">Last successful analysis: {item.analysis_completed_on ? formatDate(item.analysis_completed_on) : 'Time unavailable'}</p>
                <Link href={`/analysis/${item.analysis_run_id}`} title={item.analysis_run_id}
                  aria-label={`Open analysis run ${item.analysis_run_id}`} className="inline-block rounded text-xs font-medium text-hcl-blue underline focus-visible:ring-2 focus-visible:ring-primary/30">
                  View analysis · {item.analysis_run_id.slice(0, 8)}
                </Link>
              </>}
              {item.coverage_incomplete && <p className="text-xs text-amber-800 dark:text-amber-200">Source coverage is incomplete.</p>}
              {item.warning && <p className="break-words text-xs text-amber-800 dark:text-amber-200">{item.warning}</p>}
            </div>
          </Td>
        </tr>;
      })}{!matches.length && <tr><td colSpan={5} className="p-6 text-center text-sm text-hcl-muted">No version evidence matches your search.</td></tr>}</TableBody>
    </Table>
    <Pagination page={currentPage} pageSize={pageSize} total={matches.length} totalPages={totalPages}
      rangeStart={matches.length ? offset + 1 : 0} rangeEnd={Math.min(offset + pageSize, matches.length)}
      hasPrev={currentPage > 1} hasNext={currentPage < totalPages} onPageChange={setPage}
      onPageSizeChange={size => { setPageSize(size); setPage(1); }} pageSizeOptions={[5, 10, 25]} itemNoun="lineage" />
    <p className="px-4 pb-3 text-xs text-hcl-muted">Version provenance identifies the source of evidence. Analysis finding rows are not VEX investigation counts. Zero reported findings does not guarantee security.</p>
  </div>;
}

/** VEX-UI-001/002: provenance must not displace the operational investigation queue. */
export function PostureEvidence({ items, summary }: { items: SbomPosture[]; summary?: SbomPostureSummary }) {
  const [expanded, setExpanded] = useState(false);
  const id = useId();
  const missing = summary?.missing_targets ?? items.filter(item => item.analysis_run_id == null).length;
  const incomplete = summary?.coverage_incomplete_targets ?? items.filter(item => item.coverage_incomplete).length;
  const fallback = items.filter(item => item.last_known_posture).length;
  const notices = items.filter(item => item.warning || item.designation_required).length;
  return <section aria-label="SBOM version evidence" className="min-w-0 rounded-xl border border-border bg-surface text-foreground">
    <div className="flex flex-wrap items-center justify-between gap-3 p-4">
      <div className="min-w-0">
        <h2 className="text-sm font-semibold text-hcl-navy">SBOM version evidence</h2>
        <p className="mt-1 text-xs text-hcl-muted">{items.length ? `${items.length.toLocaleString()} version lineage${items.length === 1 ? '' : 's'} in this scope.` : 'No eligible SBOM versions in this scope.'}</p>
      </div>
      {!!items.length && <Button size="sm" variant="outline" aria-expanded={expanded} aria-controls={id} onClick={() => setExpanded(value => !value)}>
        {expanded ? 'Collapse version evidence' : 'Review version evidence'}
      </Button>}
    </div>
    {(missing > 0 || incomplete > 0 || fallback > 0 || notices > 0) && <div className="px-4 pb-3"><Alert variant="warning" showIcon={false} className="px-3 py-2 text-xs">
      <span>{[
        missing > 0 && `${missing} without successful analysis evidence`,
        fallback > 0 && `${fallback} using last known evidence`,
        incomplete > 0 && `${incomplete} with incomplete source coverage`,
        notices > 0 && `${notices} with version notices`,
      ].filter(Boolean).join(' · ')}.</span>
    </Alert></div>}
    {expanded && <div id={id}><EvidenceTable items={items} /></div>}
  </section>;
}

export function SbomPostureNotice({scope}: {scope: DashboardFilterScope}) {
  const {activeTenantId} = useAuth();
  const query = useQuery({
    queryKey: ['sbom-posture', activeTenantId, scope.projectId, scope.applicationId, scope.sbomId],
    queryFn: ({signal}) => getDashboardPostureVersions(scope, signal),
    enabled: !!activeTenantId, refetchInterval: 15000,
    retry: (count, error) => (error as {status?: number}).status !== 403 && count < 1,
  });
  if (!activeTenantId) return null;
  const status = (query.error as {status?: number} | null)?.status;
  return <>
    {query.isError && <Alert variant="error">
      {status === 403 ? 'You do not have permission to load version posture details (HTTP 403).' : `Version posture request failed${status ? ` (HTTP ${status})` : ''}.`}
      {' '}Findings and investigation metrics are unchanged.
      {query.data && ' Last loaded evidence is shown below; its freshness could not be verified.'}
      <Button size="sm" variant="outline" disabled={query.isFetching} onClick={() => { void query.refetch(); }}>Retry version posture</Button>
    </Alert>}
    {query.data ? <PostureEvidence key={`${activeTenantId}-${scope.projectId}-${scope.applicationId}-${scope.sbomId}`} items={query.data.items} summary={query.data.summary} />
      : !query.isError ? <div role="status" aria-label="Loading version evidence" className="space-y-2 rounded-xl border border-border p-4"><span className="text-sm text-hcl-muted">Loading version evidence…</span><Skeleton className="h-4 w-48" /></div> : null}
  </>;
}

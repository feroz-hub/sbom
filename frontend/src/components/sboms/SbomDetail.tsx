'use client';

import { useQuery, useQueryClient } from '@tanstack/react-query';
import { useRouter } from 'next/navigation';
import Link from 'next/link';
import { useEffect, useMemo } from 'react';
import { Play, ArrowLeft, ExternalLink } from 'lucide-react';
import { Card, CardHeader, CardTitle, CardContent } from '@/components/ui/Card';
import { Button } from '@/components/ui/Button';
import { StatusBadge } from '@/components/ui/Badge';
import { Table, TableHead, TableBody, Th, SortableTh, Td, EmptyRow } from '@/components/ui/Table';
import { SkeletonRow } from '@/components/ui/Spinner';
import { Pagination } from '@/components/ui/Pagination';
import { AnalysisProgress } from '@/components/analysis/AnalysisProgress';
import { getSbomComponents, getRuns, getSbomInfo, getSbomRiskSummary } from '@/lib/api';
import { useAnalysisStream } from '@/hooks/useAnalysisStream';
import { useTableSort } from '@/hooks/useTableSort';
import { usePagination } from '@/hooks/usePagination';
import { formatDate, formatDuration } from '@/lib/utils';
import type { SBOMSource, SBOMComponent, AnalysisRun } from '@/types';

type ComponentSortKey = 'name' | 'version' | 'component_type' | 'cpe' | 'purl';
type RunSortKey = 'id' | 'run_status' | 'total_findings' | 'duration_ms' | 'started_on';

interface SbomDetailProps {
  sbom: SBOMSource;
}

export function SbomDetail({ sbom }: SbomDetailProps) {
  const router = useRouter();
  const queryClient = useQueryClient();
  const { state, startAnalysis, cancel, reset } = useAnalysisStream(sbom.id);

  const { data: components, isLoading: compLoading } = useQuery({
    queryKey: ['sbom-components', sbom.id],
    queryFn: ({ signal }) => getSbomComponents(sbom.id, signal),
  });

  const { data: runs, isLoading: runsLoading } = useQuery({
    queryKey: ['runs', { sbom_id: sbom.id }],
    queryFn: ({ signal }) => getRuns({ sbom_id: sbom.id }, signal),
    // Refetch runs list when analysis completes so the new run appears
    refetchInterval: state.phase === 'done' ? false : undefined,
  });

  // SBOM info card (parsed metadata) — backed by GET /api/sboms/{id}/info
  const { data: info } = useQuery({
    queryKey: ['sbom-info', sbom.id],
    queryFn: ({ signal }) => getSbomInfo(sbom.id, signal),
    // info endpoint 400s for SBOMs with no stored data — fail silently
    retry: false,
  });

  // Risk summary — backed by GET /api/sboms/{id}/risk-summary
  // Refetch after a new analysis run completes
  const { data: risk } = useQuery({
    queryKey: ['sbom-risk', sbom.id, runs?.[0]?.id ?? null],
    queryFn: ({ signal }) => getSbomRiskSummary(sbom.id, signal),
    enabled: !!runs && runs.length > 0,
    retry: false,
  });

  // Components table: in-memory sort + paginate over the fetched list.
  const componentRows = useMemo<SBOMComponent[]>(() => components ?? [], [components]);
  const componentSortAccessors = useMemo(
    () => ({
      name: (c: SBOMComponent) => (c.name ?? '').toLowerCase(),
      version: (c: SBOMComponent) => c.version ?? '',
      component_type: (c: SBOMComponent) => (c.component_type ?? '').toLowerCase(),
      cpe: (c: SBOMComponent) => (c.cpe ?? '').toLowerCase(),
      purl: (c: SBOMComponent) => (c.purl ?? '').toLowerCase(),
    }),
    [],
  );
  const {
    sort: compSort,
    sortedRows: sortedComponents,
    toggle: toggleCompSort,
  } = useTableSort<SBOMComponent, ComponentSortKey>(componentRows, componentSortAccessors, {
    initialKey: 'name',
    initialDirection: 'asc',
  });
  const compPagination = usePagination<SBOMComponent>(sortedComponents, {
    defaultPageSize: 25,
    storageKey: 'sbom-components',
  });

  // Analysis runs (per-SBOM): same pattern.
  const runRows = useMemo<AnalysisRun[]>(() => runs ?? [], [runs]);
  const runSortAccessors = useMemo(
    () => ({
      id: (r: AnalysisRun) => r.id,
      run_status: (r: AnalysisRun) => r.run_status ?? '',
      total_findings: (r: AnalysisRun) => r.total_findings ?? -1,
      duration_ms: (r: AnalysisRun) => r.duration_ms ?? -1,
      started_on: (r: AnalysisRun) => r.started_on ?? '',
    }),
    [],
  );
  const {
    sort: runSort,
    sortedRows: sortedRuns,
    toggle: toggleRunSort,
  } = useTableSort<AnalysisRun, RunSortKey>(runRows, runSortAccessors, {
    initialKey: 'id',
    initialDirection: 'desc',
  });
  const runPagination = usePagination<AnalysisRun>(sortedRuns, {
    defaultPageSize: 10,
    storageKey: 'sbom-detail-runs',
  });

  // When the underlying lists change (new analysis lands, components refetched
  // post-cleanup), reset to the first page so the new top-most row is visible.
  useEffect(() => {
    compPagination.resetPage();
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [components?.length]);
  useEffect(() => {
    runPagination.resetPage();
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [runs?.length]);

  const handleRunAnalysis = () => {
    startAnalysis({ sources: ['NVD', 'OSV', 'GITHUB', 'VULNDB'] });
  };

  // Invalidate runs list when analysis completes
  const handleReset = () => {
    if (state.phase === 'done') {
      queryClient.invalidateQueries({ queryKey: ['runs'] });
    }
    reset();
  };

  const isAnalyzing = state.phase === 'connecting' || state.phase === 'parsing' || state.phase === 'running';

  return (
    <div className="space-y-6">
      {/* Back button */}
      <button
        onClick={() => router.back()}
        className="flex items-center gap-2 text-sm text-hcl-muted hover:text-hcl-navy transition-colors"
      >
        <ArrowLeft className="h-4 w-4" /> Back to SBOMs
      </button>

      {/* SBOM Metadata Card */}
      <Card>
        <CardHeader className="flex flex-row items-center justify-between">
          <CardTitle>SBOM Details</CardTitle>
          <Button
            onClick={handleRunAnalysis}
            loading={isAnalyzing}
            disabled={isAnalyzing}
            size="sm"
          >
            <Play className="h-4 w-4" />
            {isAnalyzing ? 'Analyzing…' : 'Run Analysis'}
          </Button>
        </CardHeader>
        <CardContent>
          <dl className="grid grid-cols-2 md:grid-cols-4 gap-4">
            {[
              { label: 'Name', value: sbom.sbom_name },
              { label: 'Format / Type', value: sbom.sbom_type || '—' },
              { label: 'SBOM Version', value: sbom.sbom_version || '—' },
              { label: 'Product Version', value: sbom.productver || '—' },
              { label: 'Project ID', value: sbom.projectid ? `#${sbom.projectid}` : '—' },
              { label: 'Created By', value: sbom.created_by || '—' },
              { label: 'Created On', value: formatDate(sbom.created_on) },
              { label: 'Updated On', value: formatDate(sbom.modified_on) },
            ].map(({ label, value }) => (
              <div key={label}>
                <dt className="text-xs font-medium text-hcl-muted uppercase tracking-wide">{label}</dt>
                <dd className="mt-1 text-sm font-medium text-hcl-navy break-words">{value}</dd>
              </div>
            ))}
          </dl>
        </CardContent>
      </Card>

      {/* SBOM Format & Ecosystem Info — GET /api/sboms/{id}/info */}
      {info && (
        <Card>
          <CardHeader>
            <CardTitle>Format &amp; Ecosystems</CardTitle>
          </CardHeader>
          <CardContent>
            <dl className="grid grid-cols-2 md:grid-cols-4 gap-4">
              <div>
                <dt className="text-xs font-medium text-hcl-muted uppercase tracking-wide">Format</dt>
                <dd className="mt-1 text-sm font-medium text-hcl-navy">{info.format}</dd>
              </div>
              <div>
                <dt className="text-xs font-medium text-hcl-muted uppercase tracking-wide">Spec Version</dt>
                <dd className="mt-1 text-sm font-medium text-hcl-navy">{info.spec_version || '—'}</dd>
              </div>
              <div>
                <dt className="text-xs font-medium text-hcl-muted uppercase tracking-wide">Components</dt>
                <dd className="mt-1 text-sm font-medium text-hcl-navy">{info.component_count.toLocaleString()}</dd>
              </div>
              <div>
                <dt className="text-xs font-medium text-hcl-muted uppercase tracking-wide">Identifiers</dt>
                <dd className="mt-1 text-sm font-medium text-hcl-navy">
                  {info.has_purls && 'PURL'}
                  {info.has_purls && info.has_cpes && ' · '}
                  {info.has_cpes && 'CPE'}
                  {!info.has_purls && !info.has_cpes && '—'}
                </dd>
              </div>
              {info.ecosystems.length > 0 && (
                <div className="col-span-2 md:col-span-4">
                  <dt className="text-xs font-medium text-hcl-muted uppercase tracking-wide">Ecosystems</dt>
                  <dd className="mt-1 flex flex-wrap gap-2">
                    {info.ecosystems.map((eco) => (
                      <span
                        key={eco}
                        className="inline-flex items-center px-2 py-0.5 rounded-md text-xs font-medium bg-hcl-light text-hcl-blue border border-hcl-border"
                      >
                        {eco}
                      </span>
                    ))}
                  </dd>
                </div>
              )}
            </dl>
          </CardContent>
        </Card>
      )}

      {/* Risk Summary — GET /api/sboms/{id}/risk-summary */}
      {risk && (
        <Card>
          <CardHeader>
            <CardTitle>
              Risk Summary
              <span
                className={`ml-3 inline-flex items-center px-2.5 py-0.5 rounded-full text-xs font-semibold border ${
                  risk.risk_band === 'CRITICAL'
                    ? 'bg-red-50 text-red-700 border-red-200'
                    : risk.risk_band === 'HIGH'
                    ? 'bg-orange-50 text-orange-700 border-orange-200'
                    : risk.risk_band === 'MEDIUM'
                    ? 'bg-amber-50 text-amber-700 border-amber-200'
                    : 'bg-emerald-50 text-emerald-700 border-emerald-200'
                }`}
                title={
                  risk.methodology
                    ? `${risk.methodology.name} v${risk.methodology.version}\n` +
                      `Formula: ${risk.methodology.formula}\n` +
                      `Aggregation: ${risk.methodology.aggregation}\n` +
                      `Sources: CVSS, EPSS (FIRST.org), KEV (CISA)`
                    : undefined
                }
              >
                {risk.risk_band} · score {risk.total_risk_score.toFixed(1)}
              </span>
              {risk.methodology && (
                <span className="ml-2 text-xs font-normal text-hcl-muted">
                  · {risk.methodology.name} v{risk.methodology.version}
                </span>
              )}
            </CardTitle>
            {(risk.kev_count !== undefined || risk.epss_avg !== undefined || risk.worst_finding) && (
              <div className="mt-2 flex flex-wrap gap-3 text-xs text-hcl-muted">
                {risk.kev_count !== undefined && (
                  <span className={risk.kev_count > 0 ? 'text-red-700 font-medium' : ''}>
                    KEV findings: <span className="font-mono">{risk.kev_count}</span>
                  </span>
                )}
                {risk.epss_avg !== undefined && (
                  <span>
                    Avg EPSS: <span className="font-mono">{(risk.epss_avg * 100).toFixed(2)}%</span>
                  </span>
                )}
                {risk.worst_finding && (
                  <span>
                    Worst CVE:{' '}
                    <span className="font-mono">{risk.worst_finding.vuln_id}</span>{' '}
                    on{' '}
                    <span className="font-medium text-hcl-navy">
                      {risk.worst_finding.component_name}
                    </span>
                    {' '}(score {risk.worst_finding.score.toFixed(1)}
                    {risk.worst_finding.in_kev && (
                      <span className="ml-1 inline-flex items-center px-1.5 py-0 rounded text-[10px] font-bold bg-red-100 text-red-700 border border-red-200">
                        KEV
                      </span>
                    )}
                    )
                  </span>
                )}
              </div>
            )}
          </CardHeader>
          <div className="overflow-hidden">
            <Table striped ariaLabel="Risk by vulnerable component">
              <TableHead>
                <tr>
                  <Th>Component</Th>
                  <Th>Critical</Th>
                  <Th>High</Th>
                  <Th>Medium</Th>
                  <Th>Low</Th>
                  <Th>
                    <span title="Findings on the CISA Known Exploited Vulnerabilities catalog">KEV</span>
                  </Th>
                  <Th className="text-right">Score</Th>
                </tr>
              </TableHead>
              <TableBody>
                {risk.components.length === 0 ? (
                  <EmptyRow cols={7} message="No vulnerable components." />
                ) : (
                  risk.components.slice(0, 10).map((c) => (
                    <tr key={`${c.name}@${c.version}`} className="hover:bg-hcl-light/40">
                      <Td className="font-medium text-hcl-navy">
                        {c.name}
                        {c.version && <span className="text-hcl-muted"> @ {c.version}</span>}
                      </Td>
                      <Td className="text-red-700">{c.critical}</Td>
                      <Td className="text-orange-700">{c.high}</Td>
                      <Td className="text-amber-700">{c.medium}</Td>
                      <Td className="text-hcl-blue">{c.low}</Td>
                      <Td
                        className={
                          c.kev_count && c.kev_count > 0
                            ? 'text-red-700 font-semibold'
                            : 'text-hcl-muted'
                        }
                      >
                        {c.kev_count ?? 0}
                      </Td>
                      <Td className="text-right font-mono text-xs text-hcl-navy">
                        {c.component_score.toFixed(1)}
                      </Td>
                    </tr>
                  ))
                )}
              </TableBody>
            </Table>
          </div>
          {risk.methodology && (
            <div className="px-4 py-2 text-xs text-hcl-muted border-t border-hcl-border bg-hcl-light/30">
              <span className="font-medium">How is this calculated?</span>{' '}
              <span className="font-mono">{risk.methodology.formula}</span>
              {' · '}
              Sources: CVSS (per-finding), EPSS (FIRST.org, exploit-likelihood), KEV (CISA, known-exploited).
            </div>
          )}
        </Card>
      )}

      {/* Live analysis progress (shown while running or after completion) */}
      {state.phase !== 'idle' && (
        <AnalysisProgress
          state={state}
          onCancel={isAnalyzing ? cancel : undefined}
          onReset={handleReset}
        />
      )}

      {/* Components Table */}
      <Card>
        <CardHeader>
          <CardTitle>
            Components{' '}
            {components && (
              <span className="ml-2 text-sm font-normal text-hcl-muted">
                ({components.length})
              </span>
            )}
          </CardTitle>
        </CardHeader>
        <div className="overflow-hidden">
          <Table striped ariaLabel="SBOM components">
            <TableHead>
              <tr>
                <SortableTh
                  sortKey="name"
                  activeKey={compSort.key}
                  direction={compSort.direction}
                  onToggle={(k) => toggleCompSort(k as ComponentSortKey)}
                >
                  Name
                </SortableTh>
                <SortableTh
                  sortKey="version"
                  activeKey={compSort.key}
                  direction={compSort.direction}
                  onToggle={(k) => toggleCompSort(k as ComponentSortKey)}
                >
                  Version
                </SortableTh>
                <SortableTh
                  sortKey="component_type"
                  activeKey={compSort.key}
                  direction={compSort.direction}
                  onToggle={(k) => toggleCompSort(k as ComponentSortKey)}
                >
                  Type
                </SortableTh>
                <SortableTh
                  sortKey="cpe"
                  activeKey={compSort.key}
                  direction={compSort.direction}
                  onToggle={(k) => toggleCompSort(k as ComponentSortKey)}
                >
                  CPE
                </SortableTh>
                <SortableTh
                  sortKey="purl"
                  activeKey={compSort.key}
                  direction={compSort.direction}
                  onToggle={(k) => toggleCompSort(k as ComponentSortKey)}
                >
                  PURL
                </SortableTh>
              </tr>
            </TableHead>
            <TableBody>
              {compLoading ? (
                Array.from({ length: 5 }).map((_, i) => <SkeletonRow key={i} cols={5} />)
              ) : !components?.length ? (
                <EmptyRow cols={5} message="No components found for this SBOM" />
              ) : (
                compPagination.pageItems.map((c) => (
                  <tr key={c.id} className="hover:bg-hcl-light/40">
                    <Td className="font-medium text-hcl-navy">{c.name}</Td>
                    <Td className="font-mono text-xs">{c.version || '—'}</Td>
                    <Td className="text-hcl-muted">{c.component_type || '—'}</Td>
                    <Td className="font-mono text-xs text-hcl-muted max-w-[180px] truncate">
                      {c.cpe || '—'}
                    </Td>
                    <Td className="font-mono text-xs text-hcl-muted max-w-[200px] truncate">
                      {c.purl || '—'}
                    </Td>
                  </tr>
                ))
              )}
            </TableBody>
          </Table>

          {!compLoading && componentRows.length > 0 ? (
            <Pagination
              page={compPagination.page}
              pageSize={compPagination.pageSize}
              total={compPagination.total}
              totalPages={compPagination.totalPages}
              rangeStart={compPagination.rangeStart}
              rangeEnd={compPagination.rangeEnd}
              hasPrev={compPagination.hasPrev}
              hasNext={compPagination.hasNext}
              onPageChange={compPagination.setPage}
              onPageSizeChange={compPagination.setPageSize}
              itemNoun="component"
            />
          ) : null}
        </div>
      </Card>

      {/* Analysis Runs */}
      <Card>
        <CardHeader>
          <CardTitle>Analysis Runs</CardTitle>
        </CardHeader>
        <div className="overflow-hidden">
          <Table striped ariaLabel="Analysis runs for this SBOM">
            <TableHead>
              <tr>
                <SortableTh
                  sortKey="id"
                  activeKey={runSort.key}
                  direction={runSort.direction}
                  onToggle={(k) => toggleRunSort(k as RunSortKey)}
                >
                  Run ID
                </SortableTh>
                <SortableTh
                  sortKey="run_status"
                  activeKey={runSort.key}
                  direction={runSort.direction}
                  onToggle={(k) => toggleRunSort(k as RunSortKey)}
                >
                  Status
                </SortableTh>
                <SortableTh
                  sortKey="total_findings"
                  activeKey={runSort.key}
                  direction={runSort.direction}
                  onToggle={(k) => toggleRunSort(k as RunSortKey)}
                >
                  Findings
                </SortableTh>
                <SortableTh
                  sortKey="duration_ms"
                  activeKey={runSort.key}
                  direction={runSort.direction}
                  onToggle={(k) => toggleRunSort(k as RunSortKey)}
                >
                  Duration
                </SortableTh>
                <SortableTh
                  sortKey="started_on"
                  activeKey={runSort.key}
                  direction={runSort.direction}
                  onToggle={(k) => toggleRunSort(k as RunSortKey)}
                >
                  Started On
                </SortableTh>
                <Th className="text-right">Actions</Th>
              </tr>
            </TableHead>
            <TableBody>
              {runsLoading ? (
                Array.from({ length: 3 }).map((_, i) => <SkeletonRow key={i} cols={6} />)
              ) : !runs?.length ? (
                <EmptyRow cols={6} message="No analysis runs yet. Click 'Run Analysis' to get started." />
              ) : (
                runPagination.pageItems.map((run) => (
                  <tr key={run.id} className="hover:bg-hcl-light/40">
                    <Td className="font-mono text-xs text-hcl-muted">#{run.id}</Td>
                    <Td>
                      <StatusBadge status={run.run_status} />
                    </Td>
                    <Td className="text-foreground/90">{run.total_findings ?? '—'}</Td>
                    <Td className="text-hcl-muted">{formatDuration(run.duration_ms)}</Td>
                    <Td className="text-hcl-muted whitespace-nowrap">{formatDate(run.started_on)}</Td>
                    <Td className="text-right">
                      <Link
                        href={`/analysis/${run.id}`}
                        className="inline-flex items-center gap-1 text-xs text-hcl-blue hover:underline font-medium"
                      >
                        View <ExternalLink className="h-3 w-3" />
                      </Link>
                    </Td>
                  </tr>
                ))
              )}
            </TableBody>
          </Table>

          {!runsLoading && runRows.length > 0 ? (
            <Pagination
              page={runPagination.page}
              pageSize={runPagination.pageSize}
              total={runPagination.total}
              totalPages={runPagination.totalPages}
              rangeStart={runPagination.rangeStart}
              rangeEnd={runPagination.rangeEnd}
              hasPrev={runPagination.hasPrev}
              hasNext={runPagination.hasNext}
              onPageChange={runPagination.setPage}
              onPageSizeChange={runPagination.setPageSize}
              itemNoun="run"
              pageSizeOptions={[5, 10, 25, 50]}
            />
          ) : null}
        </div>
      </Card>
    </div>
  );
}

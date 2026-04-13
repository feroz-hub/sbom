'use client';

import { useQuery, useQueryClient } from '@tanstack/react-query';
import { useRouter } from 'next/navigation';
import Link from 'next/link';
import { Play, ArrowLeft, ExternalLink } from 'lucide-react';
import { Card, CardHeader, CardTitle, CardContent } from '@/components/ui/Card';
import { Button } from '@/components/ui/Button';
import { StatusBadge } from '@/components/ui/Badge';
import { Table, TableHead, TableBody, Th, Td, EmptyRow } from '@/components/ui/Table';
import { SkeletonRow } from '@/components/ui/Spinner';
import { AnalysisProgress } from '@/components/analysis/AnalysisProgress';
import { getSbomComponents, getRuns, getSbomInfo, getSbomRiskSummary } from '@/lib/api';
import { useAnalysisStream } from '@/hooks/useAnalysisStream';
import { formatDate, formatDuration } from '@/lib/utils';
import type { SBOMSource } from '@/types';

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

  const handleRunAnalysis = () => {
    startAnalysis({ sources: ['NVD', 'OSV', 'GITHUB'] });
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
              >
                {risk.risk_band} · score {risk.total_risk_score.toFixed(1)}
              </span>
            </CardTitle>
          </CardHeader>
          <div className="overflow-hidden">
            <Table striped>
              <TableHead>
                <tr>
                  <Th>Component</Th>
                  <Th>Critical</Th>
                  <Th>High</Th>
                  <Th>Medium</Th>
                  <Th>Low</Th>
                  <Th className="text-right">Score</Th>
                </tr>
              </TableHead>
              <TableBody>
                {risk.components.length === 0 ? (
                  <EmptyRow cols={6} message="No vulnerable components." />
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
                      <Td className="text-right font-mono text-xs text-hcl-navy">
                        {c.component_score.toFixed(1)}
                      </Td>
                    </tr>
                  ))
                )}
              </TableBody>
            </Table>
          </div>
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
          <Table striped>
            <TableHead>
              <tr>
                <Th>Name</Th>
                <Th>Version</Th>
                <Th>Type</Th>
                <Th>CPE</Th>
                <Th>PURL</Th>
              </tr>
            </TableHead>
            <TableBody>
              {compLoading ? (
                Array.from({ length: 5 }).map((_, i) => <SkeletonRow key={i} cols={5} />)
              ) : !components?.length ? (
                <EmptyRow cols={5} message="No components found for this SBOM" />
              ) : (
                components.map((c) => (
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
        </div>
      </Card>

      {/* Analysis Runs */}
      <Card>
        <CardHeader>
          <CardTitle>Analysis Runs</CardTitle>
        </CardHeader>
        <div className="overflow-hidden">
          <Table striped>
            <TableHead>
              <tr>
                <Th>Run ID</Th>
                <Th>Status</Th>
                <Th>Findings</Th>
                <Th>Duration</Th>
                <Th>Started On</Th>
                <Th className="text-right">Actions</Th>
              </tr>
            </TableHead>
            <TableBody>
              {runsLoading ? (
                Array.from({ length: 3 }).map((_, i) => <SkeletonRow key={i} cols={6} />)
              ) : !runs?.length ? (
                <EmptyRow cols={6} message="No analysis runs yet. Click 'Run Analysis' to get started." />
              ) : (
                runs.map((run) => (
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
        </div>
      </Card>
    </div>
  );
}

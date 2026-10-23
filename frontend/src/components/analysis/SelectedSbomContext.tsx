'use client';

import Link from 'next/link';
import { useQuery } from '@tanstack/react-query';
import { Alert } from '@/components/ui/Alert';
import { Skeleton } from '@/components/ui/Spinner';
import { StatusBadge } from '@/components/ui/Badge';
import { Surface, SurfaceHeader, SurfaceContent } from '@/components/ui/Surface';
import { RunSeveritySummary } from './RunSeveritySummary';
import { getDashboardPostureVersions, getRun } from '@/lib/api';
import { formatDate } from '@/lib/utils';
import { recordIdLabel } from '@/lib/recordDisplay';
import { sourceSummaryFromRun } from '@/lib/runSourceSummary';
import { sourceCoverageDetail, sourceCoverageReason } from '@/lib/sourceCoverage';
import { useAuth } from '@/hooks/useAuth';
import type { SBOMSource, SbomPosture } from '@/types';

function versionLabel(version: SbomPosture['current_sbom']) {
  return version ? `${version.name}${version.version ? ` · ${version.version}` : ''}` : 'Unavailable';
}

/** A single selected lineage; never mounts a portfolio-wide paragraph feed. */
export function SelectedSbomContext({ sbom }: { sbom: SBOMSource }) {
  const { activeTenantId } = useAuth();
  const scope = { projectId: sbom.projectid ?? sbom.project_id ?? null, applicationId: sbom.product_id ?? null, sbomId: sbom.id };
  const posture = useQuery({
    queryKey: ['sbom-posture', activeTenantId, scope.projectId, scope.applicationId, scope.sbomId],
    queryFn: ({ signal }) => getDashboardPostureVersions(scope, signal),
    enabled: !!activeTenantId,
  });
  const evidence = posture.data?.items.find(item => String(item.target_sbom_id) === String(sbom.id))
    ?? posture.data?.items.find(item => String(item.posture_sbom_id) === String(sbom.id));
  const runId = evidence?.analysis_run_id;
  const run = useQuery({
    queryKey: ['run', runId, activeTenantId],
    queryFn: ({ signal }) => getRun(runId!, signal),
    enabled: !!runId && !!activeTenantId,
  });
  const current = evidence?.effective_current_sbom === undefined ? evidence?.current_sbom : evidence.effective_current_sbom;
  const sourceSummary = sourceSummaryFromRun(run.data);
  return <Surface>
    <SurfaceHeader><div>
      <h2 className="text-base font-semibold text-hcl-navy">Security posture</h2>
      <p className="mt-1 text-xs text-hcl-muted">Latest successful evidence for the selected SBOM lineage.</p>
    </div></SurfaceHeader>
    <SurfaceContent className="space-y-4">
      <dl className="grid gap-3 text-sm sm:grid-cols-3">
        {[
          ['Current SBOM', versionLabel(current ?? null)],
          ['Latest uploaded', versionLabel(evidence?.latest_uploaded ?? null)],
          ['Latest analyzed', versionLabel(evidence?.latest_analyzed ?? null)],
        ].map(([label, value]) => <div key={label} className="min-w-0"><dt className="text-xs text-hcl-muted">{label}</dt>
          <dd className="mt-1 break-words font-medium text-hcl-navy">{posture.isLoading ? <Skeleton className="h-4 w-24" /> : value}</dd></div>)}
      </dl>
      {posture.error && <Alert variant="error" title="Version evidence unavailable">{posture.error.message}</Alert>}
      {evidence?.warning && <Alert variant="warning">{evidence.warning}</Alert>}
      {evidence?.coverage_incomplete && <Alert variant="warning">Source coverage is incomplete. Findings may be incomplete.</Alert>}
      {run.isLoading ? <Skeleton className="h-24 w-full" /> : run.error ? <Alert variant="error" title="Analysis results unavailable">{run.error.message}</Alert>
        : run.data ? <>
          <div className="flex flex-wrap items-center justify-between gap-2 text-sm">
            <div><StatusBadge status={run.data.run_status} /><span className="ml-2 text-hcl-muted">Last successful analysis: {formatDate(run.data.completed_on)}</span></div>
            <Link href={`/analysis/${run.data.id}`} className="font-medium text-primary underline">{recordIdLabel('Run', run.data.display_id)} · View findings</Link>
          </div>
          <RunSeveritySummary run={run.data} expanded />
          <p className="text-xs text-hcl-muted">Sources: {run.data.source || 'Unavailable'} · Evidence from {versionLabel(evidence?.posture_sbom ?? null)}.</p>
          {sourceSummary.length > 0 ? <ul className="grid gap-2 sm:grid-cols-3" aria-label="Source coverage breakdown">
            {sourceSummary.map(source => <li key={source.source} className="rounded-lg border border-border p-3 text-xs">
              <p className="font-semibold text-hcl-navy">{source.source === 'GITHUB' ? 'GHSA' : source.source}</p>
              <p className="mt-1 text-hcl-muted">{sourceCoverageDetail(source)}</p>
              {sourceCoverageReason(source) && <p className="mt-1 break-words text-hcl-muted">{sourceCoverageReason(source)}</p>}
            </li>)}
          </ul> : <p className="text-xs text-hcl-muted">Per-source coverage breakdown is unavailable for this historical run.</p>}
          <p className="text-xs text-hcl-muted">Zero reported findings does not guarantee security. Results reflect source coverage at the time of analysis.</p>
        </> : !posture.isLoading && !posture.error && <p className="text-sm text-hcl-muted">No successful analysis evidence is available for this selection. Run an analysis to review findings.</p>}
    </SurfaceContent>
  </Surface>;
}

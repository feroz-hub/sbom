'use client';

import { useQuery } from '@tanstack/react-query';
import { useAuth } from '@/hooks/useAuth';
import { getDashboardPostureVersions, type DashboardFilterScope } from '@/lib/api';
import { Alert } from '@/components/ui/Alert';
import { Button } from '@/components/ui/Button';
import type { SbomPosture, SbomPostureSummary } from '@/types';

export function PostureEvidence({items, summary}: {items: SbomPosture[]; summary?: SbomPostureSummary}) {
  const missing = summary?.missing_targets ?? items.filter(item => item.analysis_run_id == null).length;
  return <div className="min-w-0 break-words space-y-2" aria-label="SBOM version posture">
    {!items.length && <p className="text-sm text-hcl-muted">No eligible SBOM versions in this scope.</p>}
    {missing > 0 && <Alert variant="warning">
      {missing === items.length ? 'Analysis evidence is not yet available for the selected SBOM versions.' : `Partial posture availability: ${missing} of ${items.length} selected SBOM lineages have no successful analysis.`}
      {' '}Affected: {items.filter(item => item.analysis_run_id == null).map(item => item.application_name || item.current_sbom?.name || 'No eligible version').join(', ')}.
      {' '}Findings from analyzed SBOMs remain displayed separately.
    </Alert>}
    {items.map((item, index) => {
      const current = item.effective_current_sbom === undefined ? item.current_sbom : item.effective_current_sbom;
      return <div key={`${item.target_sbom_id}-${index}`} className="text-sm">
      <p className="font-semibold">{item.application_name || item.current_sbom?.name || 'No eligible version'}</p>
      <p>Current SBOM: {current?.version ?? current?.name ?? 'No eligible version'} · Latest uploaded: {item.latest_uploaded?.version ?? item.latest_uploaded?.name ?? 'Unavailable'}</p>
      {item.latest_analyzed && <p>Latest analyzed: {item.latest_analyzed.version ?? item.latest_analyzed.name}</p>}
      <p>{item.last_known_posture ? 'Last known posture' : 'Security posture'}: {item.posture_sbom?.version ?? item.posture_sbom?.name ?? 'Unavailable'} · {item.analysis_run_id ? `Analysis run ${item.analysis_run_id}` : 'No successful analysis'} · {item.analysis_status.toLowerCase().replaceAll('_', ' ')}</p>
      {item.analysis_finding_rows != null && <p>Last successful analysis: {item.analysis_finding_rows} finding records (VEX context counts may differ).</p>}
      {item.warning && <Alert variant="warning">{item.warning}</Alert>}
    </div>; })}
  </div>;
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
      {' '}This does not change the dashboard metrics.
      {query.data && ' Last loaded evidence is shown below; its freshness could not be verified.'}
      <Button size="sm" variant="outline" disabled={query.isFetching} onClick={() => { void query.refetch(); }}>Retry version posture</Button>
    </Alert>}
    {query.data ? <PostureEvidence items={query.data.items} summary={query.data.summary} />
      : !query.isError ? <p className="text-sm text-hcl-muted">Loading version posture…</p> : null}
  </>;
}

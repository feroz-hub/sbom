'use client';
import Link from 'next/link';
import { useQuery } from '@tanstack/react-query';
import { getLogicalSbom, getLogicalSbomVersions } from '@/lib/api';
import { formatDate } from '@/lib/utils';
import { sbomEligibility } from '@/lib/sbomEligibility';
import { useAnalysisStream } from '@/hooks/useAnalysisStream';
import { useAuth } from '@/hooks/useAuth';
import { Button } from '@/components/ui/Button';
import { Alert } from '@/components/ui/Alert';
import { Table, TableHead, TableBody, Th, Td } from '@/components/ui/Table';
import { SbomStatusBadge } from './SbomStatusBadge';
import type { SBOMSource } from '@/types';

function VersionRow({ version, latestId }: { version: SBOMSource; latestId?: number }) {
  const { state, startAnalysis } = useAnalysisStream(version.id);
  const { hasPermission } = useAuth();
  const busy = ['connecting', 'parsing', 'running'].includes(state.phase);
  const eligibility = sbomEligibility(version);
  return <tr>
    <Td><Link className="font-medium text-hcl-blue hover:underline" href={`/sboms/${version.id}`}>{version.sbom_version || 'Unversioned'}</Link>{version.id === latestId && <span className="ml-2 rounded bg-surface-muted px-2 py-1 text-xs">Latest</span>}</Td>
    <Td>{version.product_version || version.productver || '—'}</Td>
    <Td>{formatDate(version.created_on)}</Td><Td>{version.created_by || '—'}</Td>
    <Td>{version.lifecycle_status || 'ACTIVE'} · {version.status}</Td>
    <Td><SbomStatusBadge sbomId={version.id} latestAnalysis={version.latest_analysis} initialStatus={busy ? 'RUNNING' : undefined} /></Td>
    <Td>{hasPermission('analysis:run') && <Button size="sm" disabled={busy || !eligibility.eligible} loading={busy} onClick={() => startAnalysis({ sources: ['NVD', 'OSV', 'GITHUB'] })}>Run Analysis</Button>}</Td>
  </tr>;
}
export function LogicalSbomHistory({ id }: { id: number }) {
  const { activeTenantId } = useAuth();
  const master = useQuery({ queryKey: ['logical-sbom', activeTenantId, id], queryFn: ({ signal }) => getLogicalSbom(id, signal) });
  const versions = useQuery({ queryKey: ['logical-sbom-versions', activeTenantId, id], queryFn: ({ signal }) => getLogicalSbomVersions(id, signal) });
  if (master.isPending || versions.isPending) return <p>Loading version history…</p>;
  if (master.isError || versions.isError) return <Alert variant="error" title="Could not load version history">{master.error?.message || versions.error?.message}<Button variant="secondary" onClick={() => { void master.refetch(); void versions.refetch(); }}>Retry</Button></Alert>;
  return <div className="space-y-4">
    <h1 className="text-xl font-semibold">{master.data.name}</h1>
    {master.data.product_id && <Link className="text-hcl-blue hover:underline" href={`/products/${master.data.product_id}`}>Back to application</Link>}
    <p>{master.data.description}</p><p>{versions.data.length} versions · Latest: {master.data.latest_version ? master.data.latest_version.sbom_version || 'Unversioned' : '—'}</p>
    <p className="text-sm text-hcl-muted">Numeric revisions use version ordering (1.10 follows 1.9). Other release labels use upload order. Latest does not change the application’s explicit current SBOM selection.</p>
    <Table ariaLabel="SBOM version history"><TableHead><tr><Th>SBOM Version</Th><Th>Product Version</Th><Th>Uploaded</Th><Th>Uploaded By</Th><Th>Status</Th><Th>Analysis</Th><Th>Actions</Th></tr></TableHead><TableBody>{versions.data.map(version => <VersionRow key={version.id} version={version} latestId={master.data.latest_version?.id} />)}</TableBody></Table>
    {!versions.data.length && <p>No versions uploaded yet. Open the application to upload the first version.</p>}
  </div>;
}

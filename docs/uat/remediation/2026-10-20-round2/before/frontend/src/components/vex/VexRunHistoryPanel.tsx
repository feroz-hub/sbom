'use client';

import { useState } from 'react';
import { useQuery } from '@tanstack/react-query';
import { useAuth } from '@/hooks/useAuth';
import { getVexAnalysisRuns, getVexRunSnapshot } from '@/lib/api';
import { Select } from '@/components/ui/Select';
import { Alert } from '@/components/ui/Alert';
import { Button } from '@/components/ui/Button';

export function VexRunHistoryPanel({sbomId}: {sbomId: (string | number)}) {
  const {activeTenantId} = useAuth();
  const [runId, setRunId] = useState(0);
  const [offset, setOffset] = useState(0);
  const runs = useQuery({queryKey: ['vex-run-history', activeTenantId, sbomId],
    queryFn: ({signal}) => getVexAnalysisRuns(sbomId, signal), enabled: !!activeTenantId});
  const snapshot = useQuery({queryKey: ['vex-run-snapshot', activeTenantId, sbomId, runId, offset],
    queryFn: ({signal}) => getVexRunSnapshot(sbomId, runId, offset, signal), enabled: !!activeTenantId && !!runId});
  return <section aria-label="Historical analysis snapshots" className="space-y-3 rounded border border-border p-4">
    <Select label="Historical analysis run" value={runId} onChange={event => {setRunId(Number(event.target.value)); setOffset(0);}}>
      <option value={0}>Select run evidence…</option>
      {runs.data?.items.map(run => <option key={run.id} value={run.id}>Run {run.id} · {run.run_status} · {run.completed_on ?? 'Incomplete'}{!run.is_current ? ' · Obsolete' : ''}</option>)}
    </Select>
    {runs.isError || snapshot.isError ? <Alert variant="error">Historical run evidence could not be loaded.</Alert> : null}
    {!!runId && snapshot.isPending && <p role="status">Loading historical snapshot…</p>}
    {snapshot.data && <>
      <p>Read-only decisions and assignments captured at analysis completion. The version investigation below retains the full later audit history.</p>
      {snapshot.data.obsolete && <Alert variant="warning">This run is obsolete and cannot supply current security posture.</Alert>}
      {!snapshot.data.snapshot_available && <Alert variant="info">No investigation snapshot was captured for this run. Legacy decisions are not reconstructed or inferred. Original findings remain in Analysis run details.</Alert>}
      <a className="text-hcl-blue underline" href={`/analysis/${runId}`}>Open original analysis evidence</a>
      {snapshot.data.items.map(row => <article key={row.investigation_id} className="rounded border border-border p-2 text-sm">
        <p>{row.canonical_vulnerability_id} · {row.component_name} {row.component_version}</p>
        <p>{row.effective_status} · {row.reconciliation_status}</p>
        <p>Previous assignment: {row.assigned_to ?? 'Unassigned'} · Reviewer: {row.reviewed_by ?? 'Not reviewed'}</p>
      </article>)}
      {snapshot.data.total > 50 && <div className="flex gap-2">
        <Button disabled={!offset} onClick={() => setOffset(value => Math.max(0, value - 50))}>Previous</Button>
        <Button disabled={offset + 50 >= snapshot.data.total} onClick={() => setOffset(value => value + 50)}>Next</Button>
      </div>}
    </>}
  </section>;
}

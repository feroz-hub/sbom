'use client';

import { useState } from 'react';
import Link from 'next/link';
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query';
import { analyzeSbomRepair, getLatestSbomRepair, runSbomRepair, decideSbomRepair, downloadSbomRepair, downloadValidationSessionOriginal } from '@/lib/api';
import { invalidateSbomSurfaces, invalidateDashboardTiles, invalidateProjectSurfaces, invalidateProductSurfaces } from '@/lib/queryInvalidation';
import { Button } from '@/components/ui/Button';
import { Alert } from '@/components/ui/Alert';
import type { DeterministicRepairJob } from '@/types/sbomAutoRepair';

function saveDownload(result: { blob: Blob; filename: string }) {
  const url = URL.createObjectURL(result.blob);
  const anchor = document.createElement('a');
  anchor.href = url;
  anchor.download = result.filename;
  anchor.click();
  URL.revokeObjectURL(url);
}

export function SbomAutoRepairPanel({ sessionId, onApproved }: { sessionId: string; onApproved?: () => void }) {
  const client = useQueryClient();
  const [showChanges, setShowChanges] = useState(false);
  const [showErrors, setShowErrors] = useState(false);
  const analysis = useQuery({ queryKey: ['sbom-auto-repair-analysis', sessionId], queryFn: ({ signal }) => analyzeSbomRepair(sessionId, signal), retry: false });
  const latest = useQuery({ queryKey: ['sbom-auto-repair-job', sessionId], queryFn: ({ signal }) => getLatestSbomRepair(sessionId, signal), retry: false });
  const invalidateRepairJob = (job: DeterministicRepairJob) => {
    client.setQueryData(['sbom-auto-repair-job', sessionId], job);
    client.invalidateQueries({ queryKey: ['validation-repair-history', sessionId] });
  };
  const repair = useMutation({ mutationFn: () => runSbomRepair(sessionId), onSuccess: (job) => invalidateRepairJob(job) });
  const decide = useMutation({ mutationFn: (decision: 'approve' | 'reject') => decision === 'approve' ? decideSbomRepair(sessionId, latest.data!.repair_job_id, decision, latest.data!.candidate_sha256) : decideSbomRepair(sessionId, latest.data!.repair_job_id, decision), onSuccess: (job) => {
    invalidateRepairJob(job);
    client.invalidateQueries({ queryKey: ['validation-repair-session', sessionId] });
    if (job.imported_sbom_id) {
      invalidateSbomSurfaces(client, job.imported_sbom_id);
      invalidateDashboardTiles(client);
      invalidateProjectSurfaces(client, job.source_project_id);
      invalidateProductSurfaces(client, job.source_product_id);
      client.invalidateQueries({ queryKey: ['validation-repair-content', sessionId] });
      client.invalidateQueries({ queryKey: ['validation-repair-lines', sessionId] });
      client.invalidateQueries({ queryKey: ['validation-repair-search', sessionId] });
      client.invalidateQueries({ queryKey: ['sbom-auto-repair-analysis', sessionId] });
      onApproved?.();
    }
  } });
  // @no-invalidation-needed — downloads retained immutable artifacts.
  const download = useMutation({ mutationFn: (kind: 'download' | 'report' | 'original') => kind === 'original'
    ? downloadValidationSessionOriginal(sessionId) : downloadSbomRepair(sessionId, latest.data!.repair_job_id, kind), onSuccess: saveDownload });
  const error = repair.error || decide.error || download.error;
  if (analysis.isPending) return <p role="status">Classifying validation issues…</p>;
  if (analysis.error || !analysis.data) return <Alert variant="warning">Repair classification unavailable. Existing validation and manual repair remain available.</Alert>;
  const data = analysis.data;
  if (!data.enabled) return null;
  const job = latest.data;
  const caps = job?.capabilities ?? data.capabilities;
  if (!job && data.validation_status === 'PASSED' && data.total_errors === 0) return null;
  const expectedSource = job?.approval_status === 'APPROVED' ? job.candidate_sha256 : job?.source_sha256;
  const stale = !!(job && expectedSource && data.source_sha256 && expectedSource !== data.source_sha256);
  const displayedIssues = (!stale && job?.analysis?.issues) || data.issues;
  const autoFixable = !stale && job?.analysis && job.approval_status !== 'REJECTED' ? job.analysis.auto_fixable : data.auto_fixable;
  const busy = repair.isPending || decide.isPending;
  return <section aria-label="Deterministic SBOM auto-repair" className="shrink-0 rounded-lg border border-border bg-white p-4 dark:bg-slate-900">
    <h2 className="font-semibold">{job ? job.status === 'REPAIRED' ? 'Auto-Repair Completed' : job.status === 'PARTIALLY_REPAIRED' ? 'Partial Repair — Manual Review Required' : job.status === 'REPAIR_FAILED' ? 'Auto-Repair Failed' : job.status === 'REJECTED' ? 'Repairs Rejected' : 'Manual Review Required' : data.total_errors ? 'SBOM Validation Failed' : 'No Repair Required'}</h2>
    {(job?.manual_review_reason || data.manual_review_reason) && <p className="text-sm">{job?.manual_review_reason || data.manual_review_reason}</p>}
    {stale && <Alert variant="warning">Source draft changed. This result belongs to an earlier draft. Run repair again before accepting changes.</Alert>}
    {error && <Alert variant="error">{error instanceof Error ? error.message : 'Repair action failed'}</Alert>}
    {job ? <>
      <p className="text-sm">Original Issues: {job.errors_before} · Repairs Applied: {job.repairs_applied} · Remaining Issues: {job.errors_after}</p>
      <p className="text-sm">{job.status.replaceAll('_', ' ')} · Validation: {job.validation_status} · Approval: {job.approval_status}</p>
      {job.analysis && <p className="text-sm">{job.suggested_repairs ?? job.analysis.suggested} have suggested fixes · {job.manual_errors ?? job.analysis.manual_only} require manual review</p>}
      {job.limit_reached && <p className="text-sm">Automatic repair stopped at the configured pass or time limit. Remaining issues require manual review.</p>}
      {job.validation_status === 'FAILED' && <p className="text-sm">Remaining issues require review. This candidate cannot be accepted until validation passes.</p>}
      <div className="mt-2 flex flex-wrap gap-2">
        <Button size="sm" variant="secondary" onClick={() => setShowChanges(!showChanges)}>View Changes</Button>
        {job.approval_status === 'PENDING' && <>
          {caps.can_approve && <Button size="sm" disabled={busy || stale || job.status !== 'REPAIRED' || job.validation_status !== 'PASSED'} onClick={() => decide.mutate('approve')}>Accept Repairs</Button>}
          {caps.can_reject && <Button size="sm" variant="secondary" disabled={busy} onClick={() => decide.mutate('reject')}>Reject Repairs</Button>}
        </>}
        {caps.can_download && <>
          <Button size="sm" variant="secondary" onClick={() => download.mutate('download')}>Download Repaired SBOM</Button>
          <Button size="sm" variant="secondary" onClick={() => download.mutate('original')}>Download Original SBOM</Button>
          <Button size="sm" variant="secondary" onClick={() => download.mutate('report')}>Download Validation Report</Button>
        </>}
        {job.approval_status === 'APPROVED' && job.imported_sbom_id && <Link href={`/sboms/${job.imported_sbom_id}`} className="text-sm underline">Open Accepted SBOM</Link>}
      </div>
      {showChanges && <div className="mt-3 max-h-72 space-y-3 overflow-auto">
        {job.changes.map(change => <article key={change.repair_id} className="rounded border border-border p-3 text-sm">
          <p><strong>Validation Error:</strong> {change.error_code}</p>
          <p><strong>JSON Path:</strong> <code>{change.path}</code></p>
          <p><strong>Repair Rule:</strong> {change.rule_name}</p>
          <p><strong>Reason:</strong> {change.reason}</p>
          <p><strong>Confidence:</strong> {Math.round(change.confidence * 100)}%</p>
          <div className="grid gap-2 md:grid-cols-2">
            <div><strong>Old Value</strong><pre className="overflow-auto whitespace-pre-wrap break-all">{JSON.stringify(change.old_value, null, 2)}</pre></div>
            <div><strong>New Value</strong><pre className="overflow-auto whitespace-pre-wrap break-all">{JSON.stringify(change.new_value, null, 2)}</pre></div>
          </div>
        </article>)}
        {!job.changes.length && <p>No deterministic changes applied.</p>}
      </div>}
    </> : <p className="text-sm">{data.total_errors} issues detected · {data.auto_fixable} can be safely repaired · {data.suggested} have suggested fixes · {data.manual_only} require manual review</p>}
    {data.truncated && <p className="text-sm">The validator capped this report. Additional issues may appear after revalidation.</p>}
    <div className="mt-2 flex flex-wrap gap-2">
      <Button size="sm" variant="secondary" onClick={() => setShowErrors(!showErrors)}>View Errors</Button>
      {!job && caps.can_download && <Button size="sm" variant="secondary" onClick={() => saveDownload({ blob: new Blob([JSON.stringify(data, null, 2)], { type: 'application/json' }), filename: 'validation-report.json' })}>Download Validation Report</Button>}
      {caps.can_repair && autoFixable > 0 && (!job || stale || job.approval_status === 'REJECTED') && <Button size="sm" loading={repair.isPending} disabled={busy} onClick={() => repair.mutate()}>Auto-Repair Safe Issues</Button>}
    </div>
    {showErrors && <ul className="mt-2 max-h-48 overflow-auto text-sm">{displayedIssues.map((issue, i) => <li key={i}><code>{issue.code} {issue.path}</code> · {issue.classification} · {issue.message}</li>)}</ul>}
  </section>;
}

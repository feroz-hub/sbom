'use client';

import { useId, useState } from 'react';
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query';
import { Badge } from '@/components/ui/Badge';
import { Button } from '@/components/ui/Button';
import { Alert } from '@/components/ui/Alert';
import { Dialog, DialogBody, DialogFooter } from '@/components/ui/Dialog';
import { useAuth } from '@/hooks/useAuth';
import { usePermission } from '@/hooks/usePermission';
import { useToast } from '@/hooks/useToast';
import { changeSbomLifecycle, getSbomLifecycleHistory } from '@/lib/api';
import { getApiErrorMessage } from '@/lib/notifications';
import { invalidateSbomLifecycle } from '@/lib/queryInvalidation';
import { formatDate } from '@/lib/utils';
import type { SBOMSource } from '@/types';

export function SbomLifecycleBadge({ sbom }: { sbom: SBOMSource }) {
  const active = sbom.lifecycle_status !== 'INACTIVE';
  return <Badge variant={active ? 'success' : 'gray'}>{active ? 'ACTIVE' : 'INACTIVE'}</Badge>;
}

export function SbomLifecycleControls({ sbom, showHistory = false }: { sbom: SBOMSource; showHistory?: boolean }) {
  const { user } = useAuth();
  const allowed = usePermission('sbom:delete');
  const canManage = allowed && (user?.isPlatformAdmin || user?.roles.includes('TENANT_ADMIN'));
  const qc = useQueryClient();
  const { showToast } = useToast();
  const [open, setOpen] = useState(false);
  const [reason, setReason] = useState('');
  const [historyOpen, setHistoryOpen] = useState(false);
  const reasonId = useId();
  const next = sbom.lifecycle_status === 'INACTIVE' ? 'ACTIVE' : 'INACTIVE';
  const label = next === 'ACTIVE' ? 'Mark Active' : 'Mark Inactive';
  const history = useQuery({ queryKey: ['sbom-lifecycle-history', sbom.id], queryFn: ({ signal }) => getSbomLifecycleHistory(sbom.id, signal), enabled: showHistory && historyOpen });
  const mutation = useMutation({
    mutationFn: () => changeSbomLifecycle(sbom.id, next, reason.trim()),
    retry: false,
    onSuccess: updated => {
      qc.setQueryData(['sbom', sbom.id], updated);
      invalidateSbomLifecycle(qc, sbom);
      showToast(`SBOM marked ${next.toLowerCase()}.`, 'success');
      setOpen(false); setReason('');
    },
    onError: error => showToast(getApiErrorMessage(error, 'Unable to change SBOM lifecycle.'), 'error'),
  });
  return <div className="flex flex-wrap items-center gap-2">
    <SbomLifecycleBadge sbom={sbom} />
    {canManage && <Button size="sm" variant="outline" onClick={() => { setReason(''); mutation.reset(); setOpen(true); }}>{label}</Button>}
    {showHistory && <Button size="sm" variant="ghost" aria-expanded={historyOpen} onClick={() => setHistoryOpen(value => !value)}>Lifecycle history</Button>}
    {historyOpen && <div className="basis-full text-xs">
      {history.isLoading ? <p role="status">Loading lifecycle history…</p> : history.isError ? <Alert variant="error">Unable to load lifecycle history.</Alert> : !history.data?.length ? <p>No lifecycle changes recorded.</p> : <ol className="space-y-2">{history.data.map(event => <li key={event.id} className="rounded border border-hcl-border p-2"><strong>{event.old_status} → {event.new_status}</strong><p>{event.reason}</p><span className="text-hcl-muted">{event.actor} · {formatDate(event.timestamp)}</span></li>)}</ol>}
    </div>}
    <Dialog open={open} onClose={() => { if (!mutation.isPending) setOpen(false); }} title={`${label}: ${sbom.sbom_name}`}>
      <DialogBody>
        <p className="mb-3 text-sm text-hcl-muted">{next === 'INACTIVE' ? 'Historical files, components, findings and reports will remain available. New analysis, comparison and report generation will be unavailable.' : 'Current participation resumes only for eligible data. Previous analysis may require reanalysis if its inputs or freshness cannot be verified.'}</p>
        <label htmlFor={reasonId} className="block text-sm font-medium">Reason (required)</label>
        <textarea id={reasonId} required maxLength={2000} rows={3} value={reason} onChange={event => setReason(event.target.value)} disabled={mutation.isPending} className="mt-2 w-full rounded border border-hcl-border p-2 text-sm focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-hcl-blue" />
        {mutation.isError && <Alert variant="error">{getApiErrorMessage(mutation.error, 'Unable to change SBOM lifecycle.')}</Alert>}
      </DialogBody>
      <DialogFooter><Button variant="secondary" disabled={mutation.isPending} onClick={() => setOpen(false)}>Cancel</Button><Button disabled={!reason.trim() || mutation.isPending} loading={mutation.isPending} onClick={() => mutation.mutate()}>{label}</Button></DialogFooter>
    </Dialog>
  </div>;
}

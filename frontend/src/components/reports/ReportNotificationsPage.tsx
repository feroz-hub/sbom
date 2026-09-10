'use client';

import { useState } from 'react';
import { useSearchParams } from 'next/navigation';
import { useQuery } from '@tanstack/react-query';
import { Button } from '@/components/ui/Button';
import { Dialog, DialogBody, DialogFooter } from '@/components/ui/Dialog';
import { DeleteConfirmDialog } from '@/components/ui/DeleteConfirmDialog';
import { useToast } from '@/hooks/useToast';
import { useDeleteReportSubscription, usePauseReportSubscription, usePreviewReport, useReportConfig, useReportDeliveries, useReportSubscriptions, useSaveReportSubscription, useSendReportNow } from '@/hooks/useReportNotifications';
import { downloadReportArtifact, getReportTargets } from '@/lib/reportApi';
import { getApiErrorMessage } from '@/lib/notifications';
import { canonicalRunStatus } from '@/lib/analysisRunStatusLabels';
import { getTenantSchedule } from '@/lib/api';
import { ScheduleEditor } from '@/components/schedules/ScheduleEditor';
import type { ReportPreferences, ReportScope, ReportSubscription } from '@/types/reports';

const fieldClass = 'mt-1 w-full rounded-lg border border-border-subtle bg-surface p-2 text-sm text-hcl-navy';
const parts = { A: 'Latest state (required)', B: 'Previous successful run', C: 'Baseline and persistent risk', D: 'Declared version comparison' };

function preferencesOnly(sub: ReportSubscription): ReportPreferences {
  return { scope: sub.scope, project_id: sub.project_id, product_id: sub.product_id, sbom_id: sub.sbom_id,
    cadence: sub.cadence, parts: sub.parts, formats: sub.formats, severity_floor: sub.severity_floor,
    baseline_mode: sub.baseline_mode, cross_version_target: sub.cross_version_target, timezone: sub.timezone,
    suppress_when_unchanged: sub.suppress_when_unchanged, enabled: sub.enabled };
}

function TenantAnalysisSchedule({ tenantId }: { tenantId: number }) {
  const [open, setOpen] = useState(false);
  const schedule = useQuery({ queryKey: ['schedule', 'TENANT', tenantId], queryFn: () => getTenantSchedule(tenantId) });
  return <div className="mt-4 border-t border-border-subtle pt-4"><p className="mb-2 text-sm text-hcl-muted">Tenant-wide analysis schedule: {schedule.data ? `${schedule.data.cadence} · ${schedule.data.enabled ? 'enabled' : 'paused'}` : 'not configured'}. Child schedules, including paused overrides, take priority.</p>
    {schedule.isError ? <p role="alert">Tenant schedule could not be loaded.</p> : <Button size="sm" variant="secondary" onClick={() => setOpen(true)}>Configure tenant analysis schedule</Button>}
    <ScheduleEditor open={open} onClose={() => setOpen(false)} scope="TENANT" targetId={tenantId} existing={schedule.data} />
  </div>;
}
export function defaultReportPreferences(scope: ReportScope = 'PROJECT', target?: number): ReportPreferences {
  return { scope, project_id: scope === 'PROJECT' ? target ?? null : null, product_id: scope === 'PRODUCT' ? target ?? null : null,
    sbom_id: scope === 'SBOM' ? target ?? null : null, cadence: 'DAILY', parts: ['A', 'B'], formats: ['PDF', 'XLSX'],
    severity_floor: 'ALL', baseline_mode: 'FIRST_RUN_OF_SBOM', cross_version_target: 'PARENT', timezone: 'UTC', suppress_when_unchanged: false, enabled: true };
}

export function ReportPreferencesEditor({ initial, id, tenantScopeAllowed, onClose }: { initial: ReportPreferences; id?: number; tenantScopeAllowed: boolean; onClose: () => void }) {
  const [form, setForm] = useState(initial);
  const [search, setSearch] = useState('');
  const [previewOpen, setPreviewOpen] = useState(false);
  const [error, setError] = useState('');
  const save = useSaveReportSubscription();
  const preview = usePreviewReport();
  const { showToast } = useToast();
  const targets = useQuery({ queryKey: ['reports', 'targets', form.scope, search], queryFn: () => getReportTargets(form.scope, search), enabled: form.scope !== 'TENANT' });
  const target = form.project_id ?? form.product_id ?? form.sbom_id;
  const patch = (values: Partial<ReportPreferences>) => { setForm({ ...form, ...values }); preview.reset(); setError(''); };
  const invalid = form.scope !== 'TENANT' && !target || form.suppress_when_unchanged && form.parts.length < 2 || !form.timezone.trim();
  async function submit() {
    try { await save.mutateAsync({ id, body: form }); showToast('Report subscription saved.', 'success'); onClose(); }
    catch (err) { const message = getApiErrorMessage(err, 'Could not save this subscription.'); setError(message); showToast(message, 'error'); }
  }
  async function showPreview() {
    try { await preview.mutateAsync(form); setPreviewOpen(true); }
    catch (err) { const message = getApiErrorMessage(err, 'Preview could not be generated.'); setError(message); showToast(message, 'error'); }
  }
  return <>
    <Dialog open onClose={onClose} title={id ? 'Edit report subscription' : 'Subscribe to security reports'} maxWidth="xl">
      <DialogBody>
        <p className="mb-4 text-sm text-hcl-muted">Reports go only to your verified account email. Narrower subscriptions take priority when reporting cycles overlap.</p>
        <div className="grid gap-4 sm:grid-cols-2">
          <label>Scope<select className={fieldClass} value={form.scope} onChange={e => patch({ scope: e.target.value as ReportScope, project_id: null, product_id: null, sbom_id: null })}>
            {(['TENANT', 'PROJECT', 'PRODUCT', 'SBOM'] as const).filter(s => s !== 'TENANT' || tenantScopeAllowed).map(s => <option key={s}>{s}</option>)}
          </select></label>
          {form.scope !== 'TENANT' && <div><label>Search scope<input className={fieldClass} value={search} onChange={e => setSearch(e.target.value)} placeholder="Filter by name (first 200 matches)" /></label>
            <label>Target<select className={fieldClass} value={target ?? ''} onChange={e => patch({ project_id: form.scope === 'PROJECT' ? Number(e.target.value) || null : null, product_id: form.scope === 'PRODUCT' ? Number(e.target.value) || null : null, sbom_id: form.scope === 'SBOM' ? Number(e.target.value) || null : null })}>
              <option value="">Choose a target</option>{target && !targets.data?.some(t => t.id === target) && <option value={target}>Selected #{target}</option>}
              {targets.data?.map(t => <option value={t.id} key={t.id}>{t.label} · #{t.id}</option>)}
            </select></label>{targets.isError && <p role="alert">Could not load targets.</p>}</div>}
          <label>Cadence<select className={fieldClass} value={form.cadence} onChange={e => patch({ cadence: e.target.value as ReportPreferences['cadence'] })}>{['ON_EVERY_RUN', 'DAILY', 'WEEKLY', 'MONTHLY'].map(c => <option key={c}>{c}</option>)}</select></label>
          <label>IANA timezone<input className={fieldClass} value={form.timezone} onChange={e => patch({ timezone: e.target.value })} placeholder="UTC" /></label>
          <fieldset className="space-y-2"><legend className="mb-2">Report parts</legend>{(Object.keys(parts) as Array<keyof typeof parts>).map(part => <label key={part} className="flex gap-2 text-sm"><input type="checkbox" checked={form.parts.includes(part)} disabled={part === 'A'} onChange={e => patch({ parts: e.target.checked ? [...form.parts, part] : form.parts.filter(p => p !== part), suppress_when_unchanged: false })} />Part {part}: {parts[part]}</label>)}</fieldset>
          <fieldset className="space-y-2"><legend className="mb-2">Attachments</legend>{(['PDF', 'XLSX'] as const).map(format => <label key={format} className="flex gap-2 text-sm"><input type="checkbox" checked={form.formats.includes(format)} onChange={e => patch({ formats: e.target.checked ? [...form.formats, format] : form.formats.filter(f => f !== format) })} />{format}</label>)}<p className="text-xs text-hcl-muted">The email always includes a readable summary, even with no attachments.</p></fieldset>
          <label>Finding detail severity floor<select className={fieldClass} value={form.severity_floor} onChange={e => patch({ severity_floor: e.target.value as ReportPreferences['severity_floor'] })}>{['ALL', 'LOW', 'MEDIUM', 'HIGH', 'CRITICAL'].map(s => <option key={s}>{s}</option>)}</select></label>
          {form.parts.includes('C') && <label>Baseline<select className={fieldClass} value={form.baseline_mode} onChange={e => patch({ baseline_mode: e.target.value as ReportPreferences['baseline_mode'] })}><option value="FIRST_RUN_OF_SBOM">First successful run of this SBOM</option><option value="FIRST_RUN_OF_LINEAGE_ROOT">First successful run of lineage root</option></select></label>}
          {form.parts.includes('D') && <label>Compare version to<select className={fieldClass} value={form.cross_version_target} onChange={e => patch({ cross_version_target: e.target.value as ReportPreferences['cross_version_target'] })}><option value="PARENT">Immediate parent</option><option value="ROOT">Lineage root</option></select></label>}
          <label className="flex items-center gap-2 text-sm"><input type="checkbox" checked={form.suppress_when_unchanged} disabled={form.parts.length < 2} onChange={e => patch({ suppress_when_unchanged: e.target.checked })} />Skip when selected comparisons are unchanged</label>
        </div>
        {error && <p role="alert" className="mt-4 text-sm text-red-700">{error}</p>}
      </DialogBody>
      <DialogFooter><Button variant="secondary" onClick={onClose}>Cancel</Button><Button variant="secondary" disabled={Boolean(invalid) || preview.isPending} onClick={showPreview}>{preview.isPending ? 'Generating preview…' : 'Preview'}</Button><Button disabled={Boolean(invalid) || save.isPending} onClick={submit}>{save.isPending ? 'Saving…' : 'Save subscription'}</Button></DialogFooter>
    </Dialog>
    <Dialog open={previewOpen} onClose={() => setPreviewOpen(false)} title="Report preview — no email sent" maxWidth="2xl"><DialogBody>
      <p className="mb-2 text-sm">{preview.data?.report.sboms.map(s => `${s.name}: ${canonicalRunStatus(s.A.run_status)}`).join(' · ')}</p>
      <iframe title="Security digest email preview" sandbox="" srcDoc={preview.data?.html_body} className="h-[65vh] w-full border" />
    </DialogBody></Dialog>
  </>;
}

export function ReportNotificationsPage() {
  const params = useSearchParams();
  const requestedScope = params.get('scope') as ReportScope;
  const initial = defaultReportPreferences(['TENANT', 'PROJECT', 'PRODUCT', 'SBOM'].includes(requestedScope) ? requestedScope : 'PROJECT', Number(params.get('target')) || undefined);
  const [editing, setEditing] = useState<{ preferences: ReportPreferences; id?: number } | null>(params.has('scope') ? { preferences: initial } : null);
  const [remove, setRemove] = useState<ReportSubscription | null>(null);
  const [allTenant, setAllTenant] = useState(false);
  const [status, setStatus] = useState('');
  const [deliveryId, setDeliveryId] = useState(() => {
    const value = Number(params.get('delivery'));
    return Number.isSafeInteger(value) && value > 0 ? value : undefined;
  });
  const config = useReportConfig();
  const subscriptions = useReportSubscriptions(allTenant ? config.data?.tenant_id : undefined);
  const deliveries = useReportDeliveries(allTenant, status, deliveryId);
  const pause = usePauseReportSubscription();
  const deletion = useDeleteReportSubscription();
  const send = useSendReportNow();
  const { showToast } = useToast();
  const act = async (operation: Promise<unknown>, success: string) => {
    try { await operation; showToast(success, 'success'); } catch (err) { showToast(getApiErrorMessage(err, 'Report action failed.'), 'error'); }
  };
  async function download(deliveryId: number, artifactId: number) {
    try {
      const { blob, filename } = await downloadReportArtifact(deliveryId, artifactId);
      const url = URL.createObjectURL(blob); const link = document.createElement('a');
      link.href = url; link.download = filename; link.click(); setTimeout(() => URL.revokeObjectURL(url), 1000);
    } catch (err) { showToast(getApiErrorMessage(err, 'Download failed.'), 'error'); }
  }
  if (config.isLoading) return <p>Loading notification settings…</p>;
  if (config.isError) return <p role="alert">Unable to load notification settings.</p>;
  return <div className="space-y-6">
    <section className="rounded-xl border border-border-subtle bg-surface p-5">
      <div className="flex flex-wrap items-start justify-between gap-3"><div><h2 className="text-lg font-semibold">Scheduled security reports</h2><p className="text-sm text-hcl-muted">Recipient: {config.data?.recipient_email || 'Verified IAM email required'}. Retention: {config.data?.retention_days} days.</p></div><Button onClick={() => setEditing({ preferences: defaultReportPreferences() })}>Add subscription</Button></div>
      {(!config.data?.enabled || !config.data.delivery_enabled || !!config.data.diagnostics.length) && <div role="status" className="mt-4 rounded-lg bg-amber-50 p-3 text-sm text-amber-900">Delivery is not ready. An operator must enable report notifications, authenticated mode, SMTP and private artifact storage. {config.data?.diagnostics.join(', ')}. Preview does not send email.</div>}
      {config.data?.is_tenant_admin && <label className="mt-4 flex gap-2 text-sm"><input type="checkbox" checked={allTenant} onChange={e => setAllTenant(e.target.checked)} />Tenant administration: view all subscriptions and deliveries</label>}
      {config.data?.is_tenant_admin && <TenantAnalysisSchedule tenantId={config.data.tenant_id} />}
    </section>
    <section className="rounded-xl border border-border-subtle bg-surface p-5"><h2 className="mb-4 text-lg font-semibold">Subscriptions</h2>
      {subscriptions.isError && <p role="alert">Subscriptions could not be loaded.</p>}
      {subscriptions.isLoading ? <p>Loading…</p> : !subscriptions.data?.length ? <p className="text-sm text-hcl-muted">No subscriptions yet. Add one or use “Notify me” on a project, product or SBOM.</p> : <div className="space-y-3">{subscriptions.data.map(sub => <div key={sub.id} className="flex flex-wrap items-center justify-between gap-3 rounded-lg border border-border-subtle p-3">
        <div><strong>{sub.scope} {sub.project_id ?? sub.product_id ?? sub.sbom_id ?? ''}</strong><p className="text-sm text-hcl-muted">{sub.cadence} · Parts {sub.parts.join(', ')} · {sub.formats.join(', ') || 'Email only'} · {sub.enabled ? 'Enabled' : 'Paused'}{allTenant ? ` · User #${sub.iam_user_id}` : ''}</p></div>
        <div className="flex flex-wrap gap-2">{!allTenant && <><Button size="sm" variant="secondary" onClick={() => setEditing({ id: sub.id, preferences: preferencesOnly(sub) })}>Edit / preview</Button><Button size="sm" variant="secondary" disabled={!sub.enabled || send.isPending} onClick={() => act(send.mutateAsync(sub.id), 'Report request saved. Check delivery history for its outcome.')}>Send now</Button></>}
          <Button size="sm" variant="secondary" disabled={pause.isPending || allTenant && !sub.enabled} onClick={() => act(pause.mutateAsync({ id: sub.id, enabled: !sub.enabled }), sub.enabled ? 'Subscription paused.' : 'Subscription resumed.')}>{sub.enabled ? 'Pause' : 'Resume'}</Button>
          {!allTenant && <Button size="sm" variant="secondary" onClick={() => setRemove(sub)}>Delete</Button>}
        </div></div>)}</div>}
    </section>
    <section className="rounded-xl border border-border-subtle bg-surface p-5"><div className="mb-4 flex flex-wrap items-center justify-between gap-2"><h2 className="text-lg font-semibold">Delivery history</h2><label className="text-sm">Status <select className={fieldClass} value={status} onChange={e => setStatus(e.target.value)}><option value="">All</option>{['PENDING', 'SENT', 'FAILED', 'SKIPPED', 'SUPPRESSED'].map(s => <option key={s}>{s}</option>)}</select></label></div>
      {deliveries.isError && <p role="alert">Delivery history could not be loaded.</p>}
      {deliveryId && <p className="mb-3 text-sm">Showing linked delivery #{deliveryId}. <button className="text-hcl-blue underline" onClick={() => setDeliveryId(undefined)}>Show recent deliveries</button></p>}
      {!deliveries.data?.length && <p className="text-sm text-hcl-muted">No deliveries in this filter.</p>}
      <div className="space-y-3">{deliveries.data?.map(row => <article id={`delivery-${row.id}`} key={row.id} className="rounded-lg border border-border-subtle p-3"><strong>#{row.id} · {row.status}</strong><p className="text-sm text-hcl-muted">{row.cycle_start} → {row.cycle_end} · {row.sbom_count} SBOMs · {row.run_count} runs · {row.attempt_count} attempts</p>{row.error_code && <p role="status" className="text-sm text-amber-800">{row.error_code.replaceAll('_', ' ')}{row.error_code === 'SMTP_OUTCOME_UNKNOWN' ? ' — do not resend until the SMTP delivery outcome has been checked.' : ''}</p>}<div className="mt-2 flex flex-wrap gap-3">{row.artifacts.map(a => <button className="text-sm text-hcl-blue underline" key={a.id} onClick={() => download(row.id, a.id)}>{a.kind} · expires {a.expires_at.slice(0, 10)}</button>)}</div></article>)}</div>
    </section>
    {editing && <ReportPreferencesEditor initial={editing.preferences} id={editing.id} tenantScopeAllowed={Boolean(config.data?.tenant_scope_allowed)} onClose={() => setEditing(null)} />}
    <DeleteConfirmDialog open={!!remove} onClose={() => setRemove(null)} onConfirm={() => { if (remove) void act(deletion.mutateAsync(remove.id).then(() => setRemove(null)), 'Subscription deleted. Retained delivery history is unchanged.'); }} loading={deletion.isPending} recordName={`${remove?.scope ?? ''} subscription #${remove?.id ?? ''}`} recordKind="report subscription" allowPermanent={false} />
  </div>;
}

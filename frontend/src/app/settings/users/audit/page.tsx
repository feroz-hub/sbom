'use client';

import Link from 'next/link';
import { useState } from 'react';
import { useQuery } from '@tanstack/react-query';
import { useAuth } from '@/hooks/useAuth';
import { getTenantAuditPage, type TenantAuditEvent } from '@/lib/api';
import { Dialog, DialogBody } from '@/components/ui/Dialog';

export default function TenantAuditPage() {
  const { activeTenantId } = useAuth();
  return <TenantAuditLog key={activeTenantId ?? 'platform'} />;
}

function TenantAuditLog() {
  const { activeTenantId, hasPermission, isLoading } = useAuth();
  const tenantId = Number(activeTenantId);
  const [filters, setFilters] = useState({ page: 1, page_size: 25, q: '', category: '', outcome: '', from_time: '', to_time: '' });
  const [detail, setDetail] = useState<TenantAuditEvent | null>(null);
  const allowed = hasPermission('tenant:user:read') && tenantId > 0;
  const events = useQuery({ queryKey: ['tenant-audit-history', tenantId, filters], queryFn: () => getTenantAuditPage(tenantId, filters), enabled: !isLoading && allowed });
  const change = (key: string, value: string | number) => setFilters(previous => ({ ...previous, [key]: value, page: 1 }));
  if (isLoading) return <p>Verifying tenant access…</p>;
  if (!allowed) return <p role="alert">Select an authorized tenant to view audit logs.</p>;
  return <main className="mx-auto max-w-6xl space-y-5 p-6">
    <Link href="/settings/users">← Users & Access</Link><h1 className="text-2xl font-semibold">Tenant Audit Log</h1>
    <div className="flex flex-wrap items-end gap-3">
      <label>Search<input className="block rounded border p-2" value={filters.q} onChange={event => change('q', event.target.value)} placeholder="Action, name or email…" /></label>
      <label>Category<select className="block rounded border p-2" value={filters.category} onChange={event => change('category', event.target.value)}><option value="">All categories</option>{['membership', 'role', 'invitation', 'tenant'].map(value => <option key={value} value={value}>{value}</option>)}</select></label>
      <label>Outcome<select className="block rounded border p-2" value={filters.outcome} onChange={event => change('outcome', event.target.value)}><option value="">All outcomes</option>{['SUCCESS', 'DENIED', 'FAILED'].map(value => <option key={value}>{value}</option>)}</select></label>
      <label>From date<input className="block rounded border p-2" type="date" value={filters.from_time.slice(0, 10)} onChange={event => change('from_time', event.target.value ? `${event.target.value}T00:00:00Z` : '')} /></label>
      <label>To date<input className="block rounded border p-2" type="date" value={filters.to_time.slice(0, 10)} onChange={event => change('to_time', event.target.value ? `${event.target.value}T23:59:59.999Z` : '')} /></label>
      <label>Rows per page<select className="block rounded border p-2" value={filters.page_size} onChange={event => change('page_size', Number(event.target.value))}>{[25, 50, 100].map(value => <option key={value}>{value}</option>)}</select></label>
    </div>
    {events.isFetching && <p role="status">Loading audit events…</p>}
    {events.error && <div role="alert">Unable to retrieve tenant audit events. <button onClick={() => events.refetch()}>Retry</button></div>}
    {events.data && <><p aria-live="polite">{events.data.total} matching events · Page {events.data.page} of {Math.max(events.data.total_pages, 1)}</p>
      <div className="overflow-x-auto"><table className="w-full text-left text-sm"><thead><tr>{['Time', 'Action', 'Actor', 'Target', 'Outcome', 'Details'].map(label => <th className="p-3" key={label}>{label}</th>)}</tr></thead><tbody>{events.data.items.map(event => <tr className="border-t" key={event.id}><td className="p-3">{new Date(event.timestamp).toLocaleString()}</td><td>{event.label ?? event.action.replaceAll('_', ' ').replaceAll('.', ' ').toLowerCase()}</td><td>{event.actor_email || 'System'}</td><td>{event.target_email || '—'}</td><td>{event.outcome}</td><td><button onClick={() => setDetail(event)}>View event</button></td></tr>)}</tbody></table></div>
      {events.data.items.length === 0 && <p>No matching audit events.</p>}
      <div className="flex gap-4"><button disabled={filters.page === 1} onClick={() => setFilters(previous => ({ ...previous, page: previous.page - 1 }))}>Previous</button><button disabled={filters.page >= events.data.total_pages} onClick={() => setFilters(previous => ({ ...previous, page: previous.page + 1 }))}>Next</button></div>
    </>}
    <Dialog open={Boolean(detail)} title="Audit event details" onClose={() => setDetail(null)}><DialogBody>{detail && <div className="space-y-3"><p>{detail.label ?? detail.action.replaceAll('_', ' ')}</p><p>{detail.outcome} · {detail.actor_email || 'System'}</p><details><summary>Technical Details</summary><p>Action: {detail.action}</p><p>Correlation ID: {detail.correlation_id || '—'}</p><pre className="overflow-x-auto text-xs">{JSON.stringify({ old_state: detail.old_state, new_state: detail.new_state }, null, 2)}</pre></details></div>}</DialogBody></Dialog>
  </main>;
}

'use client';

import Link from 'next/link';
import { useQuery } from '@tanstack/react-query';
import { getTenantAuditHistory } from '@/lib/api';
import { getApiErrorMessage } from '@/lib/notifications';

export function TenantAuditHistory({ tenantId }: { tenantId: number }) {
  const history = useQuery({ queryKey: ['tenant-audit-history', tenantId], queryFn: () => getTenantAuditHistory(tenantId), enabled: tenantId > 0 });
  const events = history.data?.slice(0, 5) ?? [];
  return <section aria-labelledby="tenant-audit-heading" className="space-y-3">
    <header className="flex flex-wrap justify-between gap-3"><h2 id="tenant-audit-heading" className="text-lg font-semibold">Recent Audit Activity</h2><Link href="/settings/users/audit">View all audit logs →</Link></header>
    {history.isLoading && <p>Loading recent activity…</p>}
    {history.error && <p role="alert">{getApiErrorMessage(history.error, 'Could not load audit activity.')}</p>}
    {!history.isLoading && !history.error && events.length === 0 && <p>No tenant administration events have been recorded.</p>}
    <ul className="divide-y rounded-lg border">{events.map(event => <li key={event.id} className="flex flex-wrap justify-between gap-2 p-3 text-sm">
      <div><p className="font-medium">{event.label ?? event.action.replaceAll('_', ' ').replaceAll('.', ' ').toLowerCase()}</p><p className="text-hcl-muted">{event.actor_email || 'System'} · {event.target_email || 'Tenant access'}</p></div>
      <div>{event.outcome} · {new Date(event.timestamp).toLocaleString()}</div>
    </li>)}</ul>
  </section>;
}

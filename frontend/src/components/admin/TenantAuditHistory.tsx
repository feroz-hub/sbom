'use client';

import Link from 'next/link';
import { useQuery } from '@tanstack/react-query';
import { getTenantAuditHistory } from '@/lib/api';
import { getApiErrorMessage } from '@/lib/notifications';

export function TenantAuditHistory({ tenantId }: { tenantId: (string | number) }) {
  const history = useQuery({ queryKey: ['tenant-audit-history', tenantId], queryFn: () => getTenantAuditHistory(tenantId), enabled: Boolean(tenantId) });
  const events = history.data?.slice(0, 5) ?? [];
  return <section aria-labelledby="tenant-audit-heading" className="space-y-4 rounded-xl border border-border bg-surface p-4 shadow-elev-1 sm:p-5">
    <header className="flex flex-wrap justify-between gap-3"><h2 id="tenant-audit-heading" className="text-lg font-semibold">Recent Audit Activity</h2><Link className="rounded text-sm font-medium text-hcl-blue hover:underline focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-hcl-blue" href="/settings/users/audit">View all audit logs →</Link></header>
    {history.isLoading && <p role="status" className="text-sm text-hcl-muted">Loading recent activity…</p>}
    {history.error && <p role="alert" className="text-sm text-red-700 dark:text-red-300">{getApiErrorMessage(history.error, 'Could not load audit activity.')}</p>}
    {!history.isLoading && !history.error && events.length === 0 && <p className="text-sm text-hcl-muted">No tenant administration events have been recorded.</p>}
    <ul className="divide-y divide-border">{events.map(event => <li key={event.id} className="flex flex-wrap justify-between gap-3 py-4 text-sm">
      <div className="min-w-0 break-words"><p className="font-medium">{event.label ?? event.action.replaceAll('_', ' ').replaceAll('.', ' ').toLowerCase()}</p><p className="mt-1 break-all text-xs text-hcl-muted">{event.actor_email || 'System'} · {event.target_email || 'Tenant access'}</p></div>
      <div className="space-y-1 text-xs text-hcl-muted sm:text-right"><p className="font-medium text-foreground">{event.outcome}</p><time dateTime={event.timestamp}>{new Date(event.timestamp).toLocaleString()}</time></div>
    </li>)}</ul>
  </section>;
}

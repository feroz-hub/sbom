'use client';

import { useQuery } from '@tanstack/react-query';

import { getTenantAuditHistory } from '@/lib/api';
import { getApiErrorMessage } from '@/lib/notifications';

export function TenantAuditHistory({ tenantId }: { tenantId: number }) {
  const history = useQuery({
    queryKey: ['tenant-audit-history', tenantId],
    queryFn: () => getTenantAuditHistory(tenantId),
    enabled: tenantId > 0,
  });

  return (
    <section aria-labelledby="tenant-audit-heading" className="space-y-3">
      <h2 id="tenant-audit-heading" className="text-lg font-semibold">Audit History</h2>
      {history.isLoading && <p className="text-sm text-hcl-muted">Loading tenant audit history…</p>}
      {history.error && (
        <p role="alert" className="text-sm text-red-600">
          {getApiErrorMessage(history.error, 'Could not load tenant audit history.')}
        </p>
      )}
      {history.data?.length === 0 && (
        <p className="rounded-lg border border-dashed border-border p-5 text-sm text-hcl-muted">
          No tenant administration events have been recorded.
        </p>
      )}
      {history.data && history.data.length > 0 && (
        <div className="overflow-x-auto rounded-lg border border-border">
          <table className="min-w-full text-sm">
            <thead className="bg-surface-elevated">
              <tr>
                <th className="px-3 py-2 text-left">Timestamp</th>
                <th className="px-3 py-2 text-left">Action</th>
                <th className="px-3 py-2 text-left">Actor</th>
                <th className="px-3 py-2 text-left">Target</th>
                <th className="px-3 py-2 text-left">Outcome</th>
                <th className="px-3 py-2 text-left">Correlation ID</th>
              </tr>
            </thead>
            <tbody>
              {history.data.map((event) => (
                <tr key={event.id} className="border-t border-border">
                  <td className="px-3 py-2 whitespace-nowrap">
                    {new Date(event.timestamp).toLocaleString()}
                  </td>
                  <td className="px-3 py-2 font-mono text-xs">{event.action}</td>
                  <td className="px-3 py-2">{event.actor_email || event.actor_user_id || 'System'}</td>
                  <td className="px-3 py-2">{event.target_email || event.target_user_id || '—'}</td>
                  <td className="px-3 py-2">{event.outcome}</td>
                  <td className="px-3 py-2 font-mono text-xs">{event.correlation_id || '—'}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}
    </section>
  );
}

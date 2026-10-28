'use client';

import { useQuery } from '@tanstack/react-query';
import { History } from 'lucide-react';
import { Badge } from '@/components/ui/Badge';
import { Button } from '@/components/ui/Button';
import {
  getAdvisorPolicyHistory,
  type AdvisorPolicyKind,
} from '@/lib/advisorPolicyApi';

export function PolicyHistory({
  tenantId,
  kind,
}: {
  tenantId: (string | number) | null;
  kind: AdvisorPolicyKind;
}) {
  const history = useQuery({
    queryKey: ['advisor-policy-history', tenantId, kind],
    queryFn: () => getAdvisorPolicyHistory(tenantId, kind),
    retry: false,
  });
  return (
    <details className="rounded-xl border border-border bg-surface">
      <summary className="cursor-pointer rounded-xl p-5 font-semibold text-hcl-navy">
        <History className="mr-2 inline h-4 w-4" aria-hidden />
        Version history
      </summary>
      <div className="space-y-4 border-t border-border p-5">
        <p className="text-sm text-hcl-muted">
          Published versions for{' '}
          {tenantId === null ? 'the platform' : 'this tenant'}. History is
          read-only; each publication creates a new version.
        </p>
        {history.isPending ? (
          <p role="status">Loading history…</p>
        ) : history.isError ? (
          <div role="alert">
            Unable to load history.{' '}
            <Button variant="ghost" onClick={() => history.refetch()}>
              Retry history
            </Button>
          </div>
        ) : history.data.items.length === 0 ? (
          <p className="rounded-lg border border-dashed border-border p-5 text-sm text-hcl-muted">
            No versions published.
          </p>
        ) : (
          <ol className="space-y-4">
            {history.data.items.map((version) => (
              <li
                key={version.id}
                className="rounded-lg border border-border p-4"
              >
                <div className="flex flex-wrap items-center gap-2">
                  <h3 className="font-semibold">Version {version.version}</h3>
                  <Badge
                    variant={version.status === 'ACTIVE' ? 'success' : 'gray'}
                  >
                    {version.status}
                  </Badge>
                  <Badge variant="gray">{version.scope}</Badge>
                </div>
                <dl className="mt-3 grid gap-3 text-sm sm:grid-cols-2">
                  <div>
                    <dt className="text-hcl-muted">Published date</dt>
                    <dd>
                      {version.created_at ? (
                        <time
                          dateTime={version.created_at}
                          title={version.created_at}
                        >
                          {new Date(version.created_at).toLocaleString()}
                        </time>
                      ) : (
                        'Not recorded'
                      )}
                    </dd>
                  </div>
                  <div>
                    <dt className="text-hcl-muted">Published by</dt>
                    <dd className="break-words">
                      {version.created_by || 'Not recorded'}
                    </dd>
                  </div>
                  <div className="sm:col-span-2">
                    <dt className="text-hcl-muted">Reason for change</dt>
                    <dd className="mt-1 whitespace-pre-wrap break-words">
                      {version.reason || 'Not recorded'}
                    </dd>
                  </div>
                </dl>
                <details className="mt-3">
                  <summary className="cursor-pointer rounded py-2 text-sm font-medium">
                    Rules for version {version.version}
                  </summary>
                  <pre className="mt-2 max-h-80 overflow-auto whitespace-pre-wrap break-words rounded-lg border border-border bg-surface-muted p-4 text-xs">
                    {JSON.stringify(version.rules, null, 2)}
                  </pre>
                </details>
              </li>
            ))}
          </ol>
        )}
      </div>
    </details>
  );
}

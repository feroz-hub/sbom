'use client';

import { FormEvent, useState } from 'react';
import Link from 'next/link';
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query';
import { usePermission } from '@/hooks/usePermission';
import {
  HttpError,
  getPlatformAdministrators,
  grantPlatformAdministrator,
  revokePlatformAdministrator,
} from '@/lib/api';

const messageFor = (error: unknown) => error instanceof HttpError ? error.message : 'Platform administration failed.';

export default function PlatformAdministratorsPage() {
  const canRead = usePermission('platform:user:read');
  const canWrite = usePermission('platform:user:write');
  const queryClient = useQueryClient();
  const [subject, setSubject] = useState('');
  const [notice, setNotice] = useState<string | null>(null);
  const administrators = useQuery({
    queryKey: ['platform-administrators'],
    queryFn: getPlatformAdministrators,
    enabled: canRead,
  });
  const mutation = useMutation({
    mutationFn: (operation: () => Promise<unknown>) => operation(),
    onSuccess: async () => {
      setNotice('Platform administrator authority updated.');
      await queryClient.invalidateQueries({ queryKey: ['platform-administrators'] });
    },
    onError: (error) => setNotice(messageFor(error)),
  });

  if (!canRead) return <div className="p-8 text-center text-hcl-muted">Platform administrator permission is required.</div>;

  const submit = (event: FormEvent) => {
    event.preventDefault();
    const value = subject.trim();
    if (!value) return;
    mutation.mutate(async () => {
      await grantPlatformAdministrator(value);
      setSubject('');
    });
  };

  return (
    <div className="mx-auto max-w-4xl space-y-6 p-6">
      <div>
        <h1 className="text-2xl font-semibold">Platform administrators</h1>
        <p className="mt-1 text-sm text-hcl-muted">Explicit SBOM database grants. HCL.CS token roles cannot grant this authority.</p>
      </div>
      <nav aria-label="Platform administration" className="flex gap-2 border-b border-border pb-3 text-sm">
        <Link href="/settings/platform" aria-current="page" className="rounded-md bg-hcl-blue px-3 py-2 font-medium text-white">Administrators</Link>
        <Link href="/settings/platform/tenants" className="rounded-md px-3 py-2 font-medium text-hcl-blue hover:bg-surface-elevated">Tenants</Link>
      </nav>
      {notice && <div role="status" className="rounded-lg border border-border p-3 text-sm">{notice}</div>}
      {canWrite && (
        <form onSubmit={submit} className="flex gap-3 rounded-lg border border-border p-4">
          <input aria-label="HCL.CS subject" value={subject} onChange={(event) => setSubject(event.target.value)} placeholder="Exact existing HCL.CS sub" className="flex-1 rounded-md border border-border bg-background px-3 py-2" required />
          <button type="submit" disabled={mutation.isPending} className="rounded-md bg-hcl-blue px-4 py-2 text-white disabled:opacity-50">Grant</button>
        </form>
      )}
      {administrators.isLoading && <p>Loading platform administrators…</p>}
      {administrators.error && <p role="alert" className="text-red-600">{messageFor(administrators.error)}</p>}
      <div className="space-y-2">
        {administrators.data?.map((administrator) => (
          <div key={administrator.grant_id} className="flex items-center justify-between rounded-lg border border-border p-4">
            <div>
              <div className="font-medium">{administrator.display_name || administrator.external_iam_user_id}</div>
              <div className="text-sm text-hcl-muted">{administrator.email || 'No email'} · {administrator.status}</div>
            </div>
            {canWrite && administrator.status === 'ACTIVE' && (
              <button type="button" className="text-red-700 hover:underline" onClick={() => {
                if (window.confirm('Revoke this platform administrator grant immediately?')) {
                  mutation.mutate(() => revokePlatformAdministrator(administrator.grant_id));
                }
              }}>Revoke</button>
            )}
          </div>
        ))}
      </div>
    </div>
  );
}

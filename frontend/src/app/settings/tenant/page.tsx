'use client';

import { FormEvent, useState } from 'react';
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query';
import { useAuth } from '@/hooks/useAuth';
import { usePermission } from '@/hooks/usePermission';
import {
  HttpError,
  type TenantRole,
  activateTenantMember,
  addTenantMember,
  deactivateTenantMember,
  getAssignableTenantRoles,
  getTenantMembers,
  removeTenantMember,
  updateTenantMemberRole,
} from '@/lib/api';

function errorMessage(error: unknown): string {
  if (!(error instanceof HttpError)) return 'The operation could not be completed.';
  if (error.status === 401) return 'Your session expired. A safe sign-in flow has been started.';
  if (error.status === 403) return 'You are authenticated but do not have permission for this action.';
  if (error.status === 404) return 'This membership is not available in the current tenant.';
  if (error.status === 409) return error.message;
  if (error.status === 422) return `Invalid member data: ${error.message}`;
  return error.message;
}

export default function TenantUsersPage() {
  const { user } = useAuth();
  const canRead = usePermission('tenant:user:read');
  const canInvite = usePermission('tenant:user:invite');
  const canUpdate = usePermission('tenant:user:update');
  const tenantId = user?.tenantId ?? 0;
  const qc = useQueryClient();
  const [externalUserId, setExternalUserId] = useState('');
  const [initialRole, setInitialRole] = useState<TenantRole>('VIEWER');
  const [notice, setNotice] = useState<{ kind: 'success' | 'error'; message: string } | null>(null);

  const members = useQuery({
    queryKey: ['tenant-users', tenantId],
    queryFn: () => getTenantMembers(tenantId),
    enabled: canRead && tenantId > 0,
  });
  const roles = useQuery({
    queryKey: ['tenant-roles'],
    queryFn: getAssignableTenantRoles,
    enabled: canRead,
  });

  const action = useMutation({
    mutationFn: async (operation: () => Promise<unknown>) => operation(),
    onSuccess: async () => {
      setNotice({ kind: 'success', message: 'Tenant membership updated.' });
      await qc.invalidateQueries({ queryKey: ['tenant-users', tenantId] });
    },
    onError: (error) => setNotice({ kind: 'error', message: errorMessage(error) }),
  });

  const submitMember = (event: FormEvent) => {
    event.preventDefault();
    const subject = externalUserId.trim();
    if (!subject) return;
    action.mutate(async () => {
      await addTenantMember(tenantId, { external_user_id: subject, role: initialRole });
      setExternalUserId('');
    });
  };

  const confirmAction = (message: string, operation: () => Promise<unknown>) => {
    if (window.confirm(message)) action.mutate(operation);
  };

  if (!canRead) {
    return <div className="p-8 text-center text-hcl-muted">You do not have permission to view tenant users.</div>;
  }

  return (
    <div className="mx-auto max-w-5xl space-y-6 p-6">
      <div>
        <h1 className="text-2xl font-semibold text-foreground">Tenant users</h1>
        <p className="mt-1 text-sm text-hcl-muted">
          HCL.CS owns identity. This page manages SBOM onboarding, membership, and tenant roles.
        </p>
      </div>

      {notice && (
        <div role="status" className={`rounded-lg border p-3 text-sm ${notice.kind === 'error' ? 'border-red-300 text-red-700' : 'border-emerald-300 text-emerald-700'}`}>
          {notice.message}
        </div>
      )}

      {canInvite && (
        <form onSubmit={submitMember} className="grid gap-3 rounded-lg border border-border p-4 md:grid-cols-[1fr_220px_auto]">
          <label className="text-sm font-medium">
            HCL.CS subject
            <input
              aria-label="HCL.CS subject"
              value={externalUserId}
              onChange={(event) => setExternalUserId(event.target.value)}
              placeholder="Exact JWT sub"
              className="mt-1 w-full rounded-md border border-border bg-background px-3 py-2"
              required
            />
          </label>
          <label className="text-sm font-medium">
            Initial role
            <select
              aria-label="Initial role"
              value={initialRole}
              onChange={(event) => setInitialRole(event.target.value as TenantRole)}
              className="mt-1 w-full rounded-md border border-border bg-background px-3 py-2"
            >
              {(roles.data?.roles ?? ['VIEWER']).map((role) => <option key={role} value={role}>{role}</option>)}
            </select>
          </label>
          <button type="submit" disabled={action.isPending} className="self-end rounded-md bg-hcl-blue px-4 py-2 text-sm font-medium text-white disabled:opacity-50">
            Add member
          </button>
        </form>
      )}

      {members.isLoading && <p className="text-sm text-hcl-muted">Loading tenant members…</p>}
      {members.error && <p role="alert" className="text-sm text-red-600">{errorMessage(members.error)}</p>}
      {members.data?.length === 0 && <div className="rounded-lg border border-dashed border-border p-8 text-center text-hcl-muted">No tenant memberships.</div>}

      {members.data && members.data.length > 0 && (
        <div className="overflow-x-auto rounded-lg border border-border">
          <table className="min-w-full text-sm">
            <thead className="bg-surface-elevated">
              <tr>
                <th className="px-4 py-2 text-left font-medium">User</th>
                <th className="px-4 py-2 text-left font-medium">Role</th>
                <th className="px-4 py-2 text-left font-medium">Status</th>
                {canUpdate && <th className="px-4 py-2 text-right font-medium">Actions</th>}
              </tr>
            </thead>
            <tbody>
              {members.data.map((member) => (
                <tr key={member.membership_id} className="border-t border-border">
                  <td className="px-4 py-3">
                    <div className="font-medium">{member.display_name || member.external_iam_user_id}</div>
                    <div className="text-xs text-hcl-muted">{member.email || 'No email supplied by HCL.CS'}</div>
                  </td>
                  <td className="px-4 py-3">
                    {canUpdate ? (
                      <select
                        aria-label={`Role for ${member.display_name || member.external_iam_user_id}`}
                        value={member.role}
                        onChange={(event) => {
                          const nextRole = event.target.value as TenantRole;
                          confirmAction(`Change this member's role to ${nextRole}?`, () => updateTenantMemberRole(tenantId, member.membership_id, nextRole));
                        }}
                        className="rounded-md border border-border bg-background px-2 py-1"
                      >
                        {(roles.data?.roles ?? [member.role]).map((role) => <option key={role} value={role}>{role}</option>)}
                      </select>
                    ) : member.role}
                  </td>
                  <td className="px-4 py-3">{member.status}</td>
                  {canUpdate && (
                    <td className="space-x-3 px-4 py-3 text-right">
                      {member.status === 'ACTIVE' ? (
                        <button type="button" className="text-amber-700 hover:underline" onClick={() => confirmAction('Deactivate this membership immediately?', () => deactivateTenantMember(tenantId, member.membership_id))}>Deactivate</button>
                      ) : (
                        <button type="button" className="text-emerald-700 hover:underline" onClick={() => confirmAction('Activate this membership?', () => activateTenantMember(tenantId, member.membership_id))}>Activate</button>
                      )}
                      <button type="button" className="text-red-700 hover:underline" onClick={() => confirmAction('Remove this membership permanently?', () => removeTenantMember(tenantId, member.membership_id))}>Remove</button>
                    </td>
                  )}
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}
    </div>
  );
}

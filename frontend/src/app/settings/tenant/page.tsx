'use client';

import { FormEvent, useState } from 'react';
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query';
import { useAuth } from '@/hooks/useAuth';
import { usePermission } from '@/hooks/usePermission';
import {
  type TenantRole,
  activateTenantMember,
  addTenantMember,
  deactivateTenantMember,
  getAssignableTenantRoles,
  getTenantMembers,
  removeTenantMember,
  updateTenantMemberRole,
} from '@/lib/api';
import { useNotifications } from '@/hooks/useNotifications';
import { getApiErrorMessage } from '@/lib/notifications';
import { ConfirmationDialog } from '@/components/ui/ConfirmationDialog';

interface MemberAction {
  operation: () => Promise<unknown>;
  success: string;
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
  const { showSuccess, showError } = useNotifications();
  const [confirmation, setConfirmation] = useState<(MemberAction & { title: string; description: string; confirmLabel: string }) | null>(null);

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
    mutationFn: async ({ operation }: MemberAction) => operation(),
    onSuccess: async (_result, variables) => {
      showSuccess(variables.success);
      setConfirmation(null);
      await qc.invalidateQueries({ queryKey: ['tenant-users', tenantId] });
    },
    onError: (error) => showError(getApiErrorMessage(error, 'The tenant membership could not be updated.')),
  });

  const submitMember = (event: FormEvent) => {
    event.preventDefault();
    const subject = externalUserId.trim();
    if (!subject) return;
    action.mutate({
      operation: async () => { await addTenantMember(tenantId, { external_user_id: subject, role: initialRole }); setExternalUserId(''); },
      success: 'The user was added to the tenant successfully.',
    });
  };

  const confirmAction = (value: NonNullable<typeof confirmation>) => setConfirmation(value);

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
            {action.isPending ? 'Adding…' : 'Add member'}
          </button>
        </form>
      )}

      {members.isLoading && <p className="text-sm text-hcl-muted">Loading tenant members…</p>}
      {members.error && <p role="alert" className="text-sm text-red-600">{getApiErrorMessage(members.error, 'Tenant members could not be loaded.')}</p>}
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
                          confirmAction({
                            title: `Change role for “${member.display_name || member.external_iam_user_id}”?`,
                            description: `This changes the tenant role to ${nextRole} and takes effect immediately.`,
                            confirmLabel: 'Change role',
                            operation: () => updateTenantMemberRole(tenantId, member.membership_id, nextRole),
                            success: `The user’s role was changed to ${nextRole}.`,
                          });
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
                        <button type="button" className="text-amber-700 hover:underline" onClick={() => confirmAction({ title: `Deactivate “${member.display_name || member.external_iam_user_id}”?`, description: 'The user will lose tenant access immediately.', confirmLabel: 'Deactivate', operation: () => deactivateTenantMember(tenantId, member.membership_id), success: 'The tenant membership was deactivated.' })}>Deactivate</button>
                      ) : (
                        <button type="button" className="text-emerald-700 hover:underline" onClick={() => action.mutate({ operation: () => activateTenantMember(tenantId, member.membership_id), success: 'The tenant membership was activated.' })}>Activate</button>
                      )}
                      <button type="button" className="text-red-700 hover:underline" onClick={() => confirmAction({ title: `Remove “${member.display_name || member.external_iam_user_id}” from the tenant?`, description: 'The user will lose tenant access and this membership will be permanently removed.', confirmLabel: 'Remove member', operation: () => removeTenantMember(tenantId, member.membership_id), success: 'The user was removed from the tenant.' })}>Remove</button>
                    </td>
                  )}
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}
      <ConfirmationDialog
        open={confirmation !== null}
        title={confirmation?.title ?? ''}
        description={confirmation?.description ?? ''}
        confirmLabel={confirmation?.confirmLabel ?? 'Confirm'}
        loading={action.isPending}
        onClose={() => !action.isPending && setConfirmation(null)}
        onConfirm={() => confirmation && action.mutate(confirmation)}
      />
    </div>
  );
}

'use client';

import Link from 'next/link';
import { FormEvent, useState } from 'react';
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query';
import { useAuth } from '@/hooks/useAuth';
import {
  type UserSearchResult,
  getPlatformAdministrators,
  grantPlatformAdministrator,
  revokePlatformAdministrator,
} from '@/lib/api';
import { useNotifications } from '@/hooks/useNotifications';
import { getApiErrorMessage } from '@/lib/notifications';
import { ConfirmationDialog } from '@/components/ui/ConfirmationDialog';
import { UserSearchCombobox } from '@/components/admin/UserSearchCombobox';
import { VerificationBadge, UserStatusBadge, RoleBadge } from '@/components/admin/StatusBadges';
import { getRoleLabel } from '@/lib/roles';

export default function PlatformAdministratorsPage() {
  const { hasPermission, isLoading: authLoading } = useAuth();
  const canRead = hasPermission('platform:administrator:read');
  const canGrant = hasPermission('platform:administrator:grant');
  const canRevoke = hasPermission('platform:administrator:revoke');
  const qc = useQueryClient();
  const { showSuccess, showError } = useNotifications();

  const [selectedUser, setSelectedUser] = useState<UserSearchResult | null>(null);
  const [revokeTarget, setRevokeTarget] = useState<{ id: number; name: string } | null>(null);

  const administrators = useQuery({
    queryKey: ['platform-administrators'],
    queryFn: getPlatformAdministrators,
    enabled: !authLoading && canRead,
  });

  const grantAdmin = useMutation({
    mutationFn: (externalUserId: string) => grantPlatformAdministrator(externalUserId),
    onSuccess: async (_res) => {
      showSuccess(`Platform Administrator authority granted to “${selectedUser?.display_name || selectedUser?.email}”.`);
      setSelectedUser(null);
      await qc.invalidateQueries({ queryKey: ['platform-administrators'] });
    },
    onError: (error) => showError(getApiErrorMessage(error, 'Could not grant Platform Administrator.')),
  });

  const revokeAdmin = useMutation({
    mutationFn: (grantId: number) => revokePlatformAdministrator(grantId),
    onSuccess: async () => {
      showSuccess(`Platform Administrator authority revoked.`);
      setRevokeTarget(null);
      await qc.invalidateQueries({ queryKey: ['platform-administrators'] });
    },
    onError: (error) => showError(getApiErrorMessage(error, 'Could not revoke Platform Administrator authority.')),
  });

  const submitGrant = (event: FormEvent) => {
    event.preventDefault();
    if (!selectedUser) return;
    const identifier = selectedUser.external_subject || String(selectedUser.id);
    grantAdmin.mutate(identifier);
  };

  if (authLoading) {
    return <div className="p-8 text-center text-hcl-muted">Verifying platform permissions…</div>;
  }

  if (!canRead) {
    return <div role="alert" className="p-8 text-center text-red-700">You do not have permission to view platform administrators.</div>;
  }

  return (
    <div className="mx-auto max-w-6xl space-y-6 p-6">
      <div>
        <h1 className="text-2xl font-semibold">Platform Administrators</h1>
        <p className="mt-1 max-w-3xl text-sm text-hcl-muted">
          Platform administrators can manage tenants and platform-level access. HCL.CS roles alone do not grant this authority.
        </p>
      </div>

      <nav aria-label="Platform administration" className="flex gap-2 border-b border-border pb-3 text-sm">
        <Link href="/settings/platform" aria-current="page" className="rounded-md bg-hcl-blue px-3 py-2 font-medium text-white">Administrators</Link>
        <Link href="/settings/platform/tenants" className="rounded-md px-3 py-2 font-medium text-hcl-blue hover:bg-surface-elevated">Tenants</Link>
      </nav>

      {canGrant && (
        <section aria-labelledby="grant-heading" className="rounded-xl border border-border bg-surface p-5 shadow-elev-1 space-y-4">
          <div>
            <h2 id="grant-heading" className="text-lg font-semibold text-foreground">Grant Platform Administrator</h2>
            <p className="mt-1 text-xs text-hcl-muted">Search existing authenticated SBOM users to grant platform administration authority.</p>
          </div>

          <form onSubmit={submitGrant} className="space-y-4">
            <div>
              <label className="block text-sm font-medium mb-1">Select User</label>
              <UserSearchCombobox
                onSelect={(u) => setSelectedUser(u)}
                selectedUser={selectedUser}
                placeholder="Search existing SBOM users by email or name…"
              />
            </div>

            {selectedUser && (
              <div className="pt-2 flex justify-end">
                <button
                  type="submit"
                  disabled={grantAdmin.isPending}
                  className="rounded-md bg-hcl-blue px-4 py-2 text-sm font-medium text-white hover:bg-hcl-blue/90 disabled:opacity-50 transition-colors"
                >
                  {grantAdmin.isPending ? 'Granting…' : 'Grant Platform Administrator'}
                </button>
              </div>
            )}
          </form>
        </section>
      )}

      <section aria-labelledby="admins-heading" className="space-y-3">
        <h2 id="admins-heading" className="text-lg font-semibold text-foreground">Active Platform Administrators</h2>

        {administrators.isLoading && <p className="text-sm text-hcl-muted">Loading platform administrators…</p>}
        {administrators.error && <p role="alert" className="text-sm text-red-600">{getApiErrorMessage(administrators.error, 'Could not load administrators.')}</p>}
        {administrators.data?.length === 0 && (
          <div className="rounded-lg border border-dashed border-border p-8 text-center text-hcl-muted">
            No platform administrators found.
          </div>
        )}

        {administrators.data && administrators.data.length > 0 && (
          <div className="overflow-x-auto rounded-lg border border-border">
            <table className="min-w-full text-sm">
              <thead className="bg-surface-elevated">
                <tr>
                  <th className="px-4 py-2 text-left font-medium">User</th>
                  <th className="px-4 py-2 text-left font-medium">Verification</th>
                  <th className="px-4 py-2 text-left font-medium">Role</th>
                  <th className="px-4 py-2 text-left font-medium">Grant Status</th>
                  <th className="px-4 py-2 text-left font-medium">User Status</th>
                  {canRevoke && <th className="px-4 py-2 text-right font-medium">Actions</th>}
                </tr>
              </thead>
              <tbody>
                {administrators.data.map((administrator) => (
                  <tr key={administrator.grant_id} className="border-t border-border">
                    <td className="px-4 py-3">
                      <div className="font-medium text-foreground">{administrator.display_name || administrator.external_iam_user_id}</div>
                      <div className="text-xs text-hcl-muted">{administrator.email || 'No email'}</div>
                    </td>
                    <td className="px-4 py-3"><VerificationBadge verified={administrator.user_status === 'ACTIVE'} /></td>
                    <td className="px-4 py-3"><RoleBadge role={administrator.role} /></td>
                    <td className="px-4 py-3">
                      <span className="inline-flex items-center rounded-full bg-hcl-blue/10 px-2 py-0.5 text-xs font-medium text-hcl-blue">
                        {administrator.status}
                      </span>
                    </td>
                    <td className="px-4 py-3"><UserStatusBadge status={administrator.user_status} /></td>
                    {canRevoke && (
                      <td className="px-4 py-3 text-right">
                        <button
                          type="button"
                          className="text-red-700 hover:underline"
                          onClick={() => setRevokeTarget({
                            id: administrator.grant_id,
                            name: administrator.display_name || administrator.email || administrator.external_iam_user_id,
                          })}
                        >
                          Revoke
                        </button>
                      </td>
                    )}
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </section>

      <ConfirmationDialog
        open={revokeTarget !== null}
        title={`Revoke Platform Administrator for “${revokeTarget?.name ?? ''}”?`}
        description="The user will immediately lose platform administration privileges."
        confirmLabel="Revoke authority"
        loading={revokeAdmin.isPending}
        onClose={() => !revokeAdmin.isPending && setRevokeTarget(null)}
        onConfirm={() => revokeTarget && revokeAdmin.mutate(revokeTarget.id)}
      />
    </div>
  );
}

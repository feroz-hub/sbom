'use client';

import { use, useState, FormEvent } from 'react';
import Link from 'next/link';
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query';
import { useAuth } from '@/hooks/useAuth';
import {
  type TenantRole,
  type UserSearchResult,
  activateTenantMember,
  addTenantMember,
  deactivateTenantMember,
  getAssignableTenantRoles,
  getTenantMembers,
  listPlatformTenants,
  removeTenantMember,
  updateTenantMemberRole,
} from '@/lib/api';
import { useNotifications } from '@/hooks/useNotifications';
import { getApiErrorMessage } from '@/lib/notifications';
import { ConfirmationDialog } from '@/components/ui/ConfirmationDialog';
import { TenantContextHeader } from '@/components/admin/TenantContextHeader';
import { UserSearchCombobox } from '@/components/admin/UserSearchCombobox';
import { VerificationBadge, UserStatusBadge, MembershipStatusBadge } from '@/components/admin/StatusBadges';
import { getRoleCode, getRoleLabel } from '@/lib/roles';

interface MemberAction {
  operation: () => Promise<unknown>;
  success: string;
}

export default function PlatformTenantDetailPage({
  params,
}: {
  params: Promise<{ tenantId: string }>;
}) {
  const { tenantId: tenantIdStr } = use(params);
  const numericTenantId = Number.parseInt(tenantIdStr, 10);
  const { hasPermission, isLoading: authLoading } = useAuth();
  const canManage = hasPermission('platform:tenant:create');
  const qc = useQueryClient();
  const { showSuccess, showError } = useNotifications();

  const [selectedUser, setSelectedUser] = useState<UserSearchResult | null>(null);
  const [initialRole, setInitialRole] = useState<TenantRole>('VIEWER');
  const [confirmation, setConfirmation] = useState<(MemberAction & { title: string; description: string; confirmLabel: string }) | null>(null);

  const tenantsQuery = useQuery({
    queryKey: ['platform-tenants'],
    queryFn: listPlatformTenants,
    enabled: !authLoading && canManage,
  });

  const tenant = tenantsQuery.data?.find((t) => String(t.id) === tenantIdStr);

  const members = useQuery({
    queryKey: ['tenant-users', numericTenantId],
    queryFn: () => getTenantMembers(numericTenantId),
    enabled: !authLoading && canManage && !Number.isNaN(numericTenantId),
  });

  const roles = useQuery({
    queryKey: ['tenant-roles'],
    queryFn: getAssignableTenantRoles,
    enabled: !authLoading && canManage,
  });

  const action = useMutation({
    mutationFn: async ({ operation }: MemberAction) => operation(),
    onSuccess: async (_result, variables) => {
      showSuccess(variables.success);
      setConfirmation(null);
      setSelectedUser(null);
      await qc.invalidateQueries({ queryKey: ['tenant-users', numericTenantId] });
    },
    onError: (error) => showError(getApiErrorMessage(error, 'The tenant membership could not be updated.')),
  });

  const submitMember = (event: FormEvent) => {
    event.preventDefault();
    if (!selectedUser) return;
    action.mutate({
      operation: async () => {
        await addTenantMember(numericTenantId, {
          external_user_id: selectedUser.external_subject || String(selectedUser.id),
          role: initialRole,
        });
      },
      success: `User “${selectedUser.display_name || selectedUser.email}” was added to ${tenant?.name || 'the tenant'}.`,
    });
  };

  const confirmAction = (value: NonNullable<typeof confirmation>) => setConfirmation(value);

  if (authLoading) {
    return <div className="p-8 text-center text-hcl-muted">Verifying platform permission…</div>;
  }

  if (!canManage) {
    return <div role="alert" className="p-8 text-center text-red-700">Access denied.</div>;
  }

  return (
    <div className="mx-auto max-w-6xl space-y-6 p-6">
      <nav aria-label="Breadcrumb" className="text-sm text-hcl-muted">
        <Link href="/settings/platform/tenants" className="hover:underline text-hcl-blue">Platform Tenants</Link>
        <span className="mx-2">/</span>
        <span className="text-foreground font-medium">{tenant?.name || `Tenant #${tenantIdStr}`}</span>
      </nav>

      {tenant ? (
        <TenantContextHeader
          name={tenant.name}
          slug={tenant.slug}
          externalIamTenantId={tenant.external_iam_tenant_id}
          status={tenant.status}
          memberCount={members.data?.length}
        />
      ) : (
        <div className="rounded-xl border border-border bg-surface p-5 text-center text-hcl-muted">
          Loading tenant details…
        </div>
      )}

      {/* Add Member Section */}
      <section aria-labelledby="add-member-heading" className="rounded-xl border border-border bg-surface p-5 shadow-elev-1 space-y-4">
        <div>
          <h2 id="add-member-heading" className="text-lg font-semibold text-foreground">Add tenant member</h2>
          <p className="mt-1 text-xs text-hcl-muted">Search existing authenticated SBOM users to assign membership.</p>
        </div>

        <form onSubmit={submitMember} className="space-y-4">
          <div>
            <label className="block text-sm font-medium mb-1">Select User</label>
            <UserSearchCombobox
              tenantId={numericTenantId}
              onSelect={(user) => setSelectedUser(user)}
              selectedUser={selectedUser}
              placeholder="Search existing SBOM users by email or name…"
            />
          </div>

          {selectedUser && (
            <div className="grid gap-3 sm:grid-cols-[1fr_auto] items-end pt-2">
              <label className="text-sm font-medium">
                Tenant Role
                <select
                  aria-label="Initial role"
                  value={getRoleCode(initialRole)}
                  onChange={(event) => setInitialRole(event.target.value as TenantRole)}
                  className="mt-1 w-full rounded-md border border-border bg-background px-3 py-2"
                >
                  {(roles.data?.roles ?? ['VIEWER']).map((role) => {
                    const code = getRoleCode(role);
                    const label = getRoleLabel(role);
                    const key = code || (role && typeof role === 'object' ? String(role.id ?? '') : String(role));
                    return (
                      <option key={key} value={code}>
                        {label}
                      </option>
                    );
                  })}
                </select>
              </label>
              <button
                type="submit"
                disabled={action.isPending}
                className="rounded-md bg-hcl-blue px-4 py-2 text-sm font-medium text-white hover:bg-hcl-blue/90 disabled:opacity-50 transition-colors"
              >
                {action.isPending ? 'Adding…' : 'Add Member'}
              </button>
            </div>
          )}
        </form>
      </section>

      {/* Members Table */}
      <section aria-labelledby="members-heading" className="space-y-3">
        <h2 id="members-heading" className="text-lg font-semibold text-foreground">Tenant Members</h2>

        {members.isLoading && <p className="text-sm text-hcl-muted">Loading members…</p>}
        {members.error && <p role="alert" className="text-sm text-red-600">{getApiErrorMessage(members.error, 'Could not load members.')}</p>}
        {members.data?.length === 0 && (
          <div className="rounded-lg border border-dashed border-border p-8 text-center text-hcl-muted">
            No tenant memberships currently exist. Use the search form above to add a member.
          </div>
        )}

        {members.data && members.data.length > 0 && (
          <div className="overflow-x-auto rounded-lg border border-border">
            <table className="min-w-full text-sm">
              <thead className="bg-surface-elevated">
                <tr>
                  <th className="px-4 py-2 text-left font-medium">User</th>
                  <th className="px-4 py-2 text-left font-medium">Verification</th>
                  <th className="px-4 py-2 text-left font-medium">Role</th>
                  <th className="px-4 py-2 text-left font-medium">Membership Status</th>
                  <th className="px-4 py-2 text-left font-medium">User Status</th>
                  <th className="px-4 py-2 text-right font-medium">Actions</th>
                </tr>
              </thead>
              <tbody>
                {members.data.map((member) => (
                  <tr key={member.membership_id} className="border-t border-border">
                    <td className="px-4 py-3">
                      <div className="font-medium text-foreground">{member.display_name || member.external_iam_user_id}</div>
                      <div className="text-xs text-hcl-muted">{member.email || 'No email'}</div>
                    </td>
                    <td className="px-4 py-3">
                      <VerificationBadge verified={member.user_status === 'ACTIVE'} />
                    </td>
                    <td className="px-4 py-3">
                      <select
                        aria-label={`Role for ${member.display_name || member.external_iam_user_id}`}
                        value={getRoleCode(member.role)}
                        onChange={(event) => {
                          const nextRole = event.target.value as TenantRole;
                          confirmAction({
                            title: `Change role for “${member.display_name || member.external_iam_user_id}”?`,
                            description: `This changes the tenant role to ${getRoleLabel(nextRole)} immediately.`,
                            confirmLabel: 'Change role',
                            operation: () => updateTenantMemberRole(numericTenantId, member.membership_id, nextRole),
                            success: `Role updated to ${getRoleLabel(nextRole)}.`,
                          });
                        }}
                        className="rounded-md border border-border bg-background px-2 py-1"
                      >
                        {(roles.data?.roles ?? [member.role]).map((role) => {
                          const code = getRoleCode(role);
                          const label = getRoleLabel(role);
                          const key = code || (role && typeof role === 'object' ? String(role.id ?? '') : String(role));
                          return (
                            <option key={key} value={code}>
                              {label}
                            </option>
                          );
                        })}
                      </select>
                    </td>
                    <td className="px-4 py-3"><MembershipStatusBadge status={member.status} /></td>
                    <td className="px-4 py-3"><UserStatusBadge status={member.user_status} /></td>
                    <td className="space-x-3 px-4 py-3 text-right">
                      {member.status === 'ACTIVE' ? (
                        <button
                          type="button"
                          className="text-amber-700 hover:underline"
                          onClick={() => confirmAction({
                            title: `Deactivate “${member.display_name || member.external_iam_user_id}”?`,
                            description: 'The user will lose tenant access immediately.',
                            confirmLabel: 'Deactivate',
                            operation: () => deactivateTenantMember(numericTenantId, member.membership_id),
                            success: 'Membership deactivated.',
                          })}
                        >
                          Deactivate
                        </button>
                      ) : (
                        <button
                          type="button"
                          className="text-emerald-700 hover:underline"
                          onClick={() => action.mutate({
                            operation: () => activateTenantMember(numericTenantId, member.membership_id),
                            success: 'Membership activated.',
                          })}
                        >
                          Activate
                        </button>
                      )}
                      <button
                        type="button"
                        className="text-red-700 hover:underline"
                        onClick={() => confirmAction({
                          title: `Remove “${member.display_name || member.external_iam_user_id}”?`,
                          description: 'The membership will be permanently removed.',
                          confirmLabel: 'Remove member',
                          operation: () => removeTenantMember(numericTenantId, member.membership_id),
                          success: 'Member removed.',
                        })}
                      >
                        Remove
                      </button>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </section>

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

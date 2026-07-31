'use client';

import { useState, FormEvent } from 'react';
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
  removeTenantMember,
  replaceTenantMemberRoles,
} from '@/lib/api';
import { useNotifications } from '@/hooks/useNotifications';
import { getApiErrorMessage } from '@/lib/notifications';
import { ConfirmationDialog } from '@/components/ui/ConfirmationDialog';
import { TenantContextHeader } from '@/components/admin/TenantContextHeader';
import { UserSearchCombobox } from '@/components/admin/UserSearchCombobox';
import { TenantAuditHistory } from '@/components/admin/TenantAuditHistory';
import { VerificationBadge, UserStatusBadge, MembershipStatusBadge, RoleBadges } from '@/components/admin/StatusBadges';
import { getRoleCode, getRoleLabel } from '@/lib/roles';
import { resolveExternalTenantMapping } from '@/lib/identityMapping';

interface MemberAction {
  operation: () => Promise<unknown>;
  success: string;
}

export default function TenantUsersPage() {
  const { user, tenants, activeTenant, activeTenantId, isTenantContextLoading, isLoading: authLoading, hasPermission } = useAuth();
  const currentTenantId = activeTenantId ? Number(activeTenantId) : (user?.tenantId ? Number(user.tenantId) : null);
  const tenantsList = Array.isArray(tenants) ? tenants : [];
  const activeTenantObj = activeTenant ?? tenantsList.find((t) => t.id === currentTenantId);
  const canRead = hasPermission('tenant:user:read');
  const canUpdate = hasPermission('tenant:user:update');
  const canInvite = hasPermission('tenant:user:invite');
  const qc = useQueryClient();
  const { showSuccess, showError } = useNotifications();

  const [selectedUser, setSelectedUser] = useState<UserSearchResult | null>(null);
  const [initialRoles, setInitialRoles] = useState<TenantRole[]>(['VIEWER']);
  const [confirmation, setConfirmation] = useState<(MemberAction & { title: string; description: string; confirmLabel: string }) | null>(null);

  const members = useQuery({
    queryKey: ['tenant-users', currentTenantId],
    queryFn: () => (currentTenantId ? getTenantMembers(currentTenantId) : Promise.resolve([])),
    enabled: !(authLoading || isTenantContextLoading) && canRead && currentTenantId !== null,
  });

  const roles = useQuery({
    queryKey: ['tenant-roles', currentTenantId],
    queryFn: () => getAssignableTenantRoles(currentTenantId ?? undefined),
    enabled: !(authLoading || isTenantContextLoading) && canRead,
  });

  const action = useMutation({
    mutationFn: async ({ operation }: MemberAction) => operation(),
    onSuccess: async (_result, variables) => {
      showSuccess(variables.success);
      setConfirmation(null);
      setSelectedUser(null);
      await qc.invalidateQueries({ queryKey: ['tenant-users', currentTenantId] });
      await qc.invalidateQueries({ queryKey: ['tenant-audit-history', currentTenantId] });
    },
    onError: (error) => showError(getApiErrorMessage(error, 'The tenant membership action failed.')),
  });

  const submitMember = (event: FormEvent) => {
    event.preventDefault();
    if (!selectedUser || !currentTenantId) return;
    action.mutate({
      operation: async () => {
        await addTenantMember(currentTenantId, {
          user_id: selectedUser.id,
          roles: initialRoles,
        });
      },
      success: `User “${selectedUser.display_name || selectedUser.email}” was added to the tenant.`,
    });
  };


  const confirmAction = (value: NonNullable<typeof confirmation>) => setConfirmation(value);

  if (isTenantContextLoading) {
    return <div className="p-8 text-center text-hcl-muted">Verifying tenant permission…</div>;
  }

  if (!canRead) {
    return <div role="alert" className="p-8 text-center text-red-700">You do not have permission to view tenant members.</div>;
  }

  if (!currentTenantId) {
    if (tenantsList.length === 0) {
      return (
        <div className="mx-auto max-w-4xl p-6 text-center space-y-3">
          <div className="rounded-xl border border-amber-200 bg-amber-50 p-6 text-amber-800 dark:border-amber-900/50 dark:bg-amber-950/20 dark:text-amber-300">
            <h2 className="text-lg font-bold">No active tenant memberships</h2>
            <p className="mt-1 text-sm">Your account does not currently have access to any active tenant.</p>
          </div>
        </div>
      );
    }
    if (tenantsList.length > 1) {
      return (
        <div className="mx-auto max-w-4xl p-6 text-center space-y-3">
          <div className="rounded-xl border border-blue-200 bg-blue-50 p-6 text-blue-800 dark:border-blue-900/50 dark:bg-blue-950/20 dark:text-blue-300">
            <h2 className="text-lg font-bold">Multiple tenants available</h2>
            <p className="mt-1 text-sm">Please select an active tenant from the tenant switcher before managing members.</p>
          </div>
        </div>
      );
    }
    return (
      <div className="mx-auto max-w-4xl p-6 text-center space-y-3">
        <div className="rounded-xl border border-amber-200 bg-amber-50 p-6 text-amber-800 dark:border-amber-900/50 dark:bg-amber-950/20 dark:text-amber-300">
          <h2 className="text-lg font-bold">Select a tenant</h2>
          <p className="mt-1 text-sm">Choose an active tenant to view tenant-specific projects, SBOMs, findings and administration.</p>
        </div>
      </div>
    );
  }

  return (
    <div className="mx-auto max-w-6xl space-y-6 p-6">
      <TenantContextHeader
        name={activeTenantObj?.name || `Tenant #${currentTenantId}`}
        slug={activeTenantObj?.slug || 'Unavailable'}
        externalIamTenantId={activeTenantObj?.externalIamTenantId}
        identityMapping={activeTenantObj?.identity_mapping ?? activeTenantObj?.identityMapping}
        isPlatformAdmin={user?.isPlatformAdmin}
        status={activeTenantObj?.status || 'ACTIVE'}
        memberCount={members.data?.length}
      />

      {canInvite && (
        <section aria-labelledby="add-member-heading" className="rounded-xl border border-border bg-surface p-5 shadow-elev-1 space-y-4">
          <div>
            <h2 id="add-member-heading" className="text-lg font-semibold text-foreground">Add tenant member</h2>
            <p className="mt-1 text-xs text-hcl-muted">Search existing authenticated SBOM users to add to this tenant.</p>
          </div>

          <form onSubmit={submitMember} className="space-y-4">
            <div>
              <label className="block text-sm font-medium mb-1">Select User</label>
              <UserSearchCombobox
                tenantId={currentTenantId}
                onSelect={(u) => setSelectedUser(u)}
                selectedUser={selectedUser}
                placeholder="Search existing SBOM users by email or name…"
              />
            </div>

            {selectedUser && (
              <div className="grid gap-3 sm:grid-cols-[1fr_auto] items-end pt-2">
                <label className="text-sm font-medium">
                  Tenant Roles
                  <select
                    aria-label="Initial roles"
                    multiple
                    value={initialRoles.map(getRoleCode)}
                    onChange={(event) => {
                      const selected = Array.from(
                        event.target.selectedOptions,
                        (option) => option.value as TenantRole,
                      );
                      if (selected.length > 0) setInitialRoles(selected);
                    }}
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
      )}

      {/* Members Table */}
      <section aria-labelledby="members-heading" className="space-y-3">
        <h2 id="members-heading" className="text-lg font-semibold text-foreground">Members</h2>

        {members.isLoading && <p className="text-sm text-hcl-muted">Loading members…</p>}
        {members.error && <p role="alert" className="text-sm text-red-600">{getApiErrorMessage(members.error, 'Could not load members.')}</p>}
        {members.data?.length === 0 && (
          <div className="rounded-lg border border-dashed border-border p-8 text-center text-hcl-muted">
            No tenant members found.
          </div>
        )}

        {members.data && members.data.length > 0 && (
          <div className="overflow-x-auto rounded-lg border border-border">
            <table className="min-w-full text-sm">
              <thead className="bg-surface-elevated">
                <tr>
                  <th className="px-4 py-2 text-left font-medium">User</th>
                  <th className="px-4 py-2 text-left font-medium">Verification</th>
                  <th className="px-4 py-2 text-left font-medium">Roles</th>
                  <th className="px-4 py-2 text-left font-medium">Membership Status</th>
                  <th className="px-4 py-2 text-left font-medium">User Status</th>
                  {canUpdate && <th className="px-4 py-2 text-right font-medium">Actions</th>}
                </tr>
              </thead>
              <tbody>
                {members.data.map((member) => (
                  <tr key={member.membership_id} className="border-t border-border">
                    <td className="px-4 py-3">
                      <div className="font-medium text-foreground">{member.display_name || member.email || `User #${member.user_id}`}</div>
                      <div className="text-xs text-hcl-muted">{member.email || 'No email'}</div>
                    </td>
                    <td className="px-4 py-3">
                      <VerificationBadge verified={member.email_verified && !member.verification_required} />
                    </td>
                    <td className="px-4 py-3">
                      {canUpdate ? (
                        <select
                          aria-label={`Roles for ${member.display_name || member.email || `User #${member.user_id}`}`}
                          multiple
                          value={(member.roles ?? [member.role]).map(getRoleCode)}
                          onChange={(event) => {
                            const nextRoles = Array.from(
                              event.target.selectedOptions,
                              (option) => option.value as TenantRole,
                            );
                            if (nextRoles.length === 0) return;
                            confirmAction({
                              title: `Change roles for “${member.display_name || member.email || `User #${member.user_id}`}”?`,
                              description: `This replaces the complete tenant role set with ${nextRoles.map(getRoleLabel).join(', ')} immediately.`,
                              confirmLabel: 'Replace roles',
                              operation: () => replaceTenantMemberRoles(
                                currentTenantId,
                                member.user_id,
                                nextRoles,
                                member.role_assignment_version,
                              ),
                              success: `Roles updated to ${nextRoles.map(getRoleLabel).join(', ')}.`,
                            });
                          }}
                          className="rounded-md border border-border bg-background px-2 py-1"
                        >
                          {(roles.data?.roles ?? member.roles ?? [member.role]).map((role) => {
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
                      ) : (
                        <RoleBadges roles={member.roles ?? [member.role]} />
                      )}
                    </td>
                    <td className="px-4 py-3"><MembershipStatusBadge status={member.status} /></td>
                    <td className="px-4 py-3"><UserStatusBadge status={member.user_status} /></td>
                    {canUpdate && (
                      <td className="space-x-3 px-4 py-3 text-right">
                        {member.status === 'ACTIVE' ? (
                          <button
                            type="button"
                            className="text-amber-700 hover:underline"
                            onClick={() => confirmAction({
                              title: `Disable membership for “${member.display_name || member.email || `User #${member.user_id}`}”?`,
                              description: 'The user will lose access to this tenant immediately.',
                              confirmLabel: 'Disable membership',
                              operation: () => deactivateTenantMember(currentTenantId, member.membership_id),
                              success: 'Membership disabled.',
                            })}
                          >
                            Disable membership
                          </button>
                        ) : (
                          <button
                            type="button"
                            className="text-emerald-700 hover:underline"
                            onClick={() => action.mutate({
                              operation: () => activateTenantMember(currentTenantId, member.membership_id),
                              success: 'Membership enabled.',
                            })}
                          >
                            Enable membership
                          </button>
                        )}
                        <button
                          type="button"
                          className="text-red-700 hover:underline"
                          onClick={() => confirmAction({
                            title: `Remove “${member.display_name || member.email || `User #${member.user_id}`}” from tenant?`,
                            description: 'The tenant membership will be permanently removed.',
                            confirmLabel: 'Remove from tenant',
                            operation: () => removeTenantMember(currentTenantId, member.membership_id),
                            success: 'Member removed from tenant.',
                          })}
                        >
                          Remove from tenant
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

      <section aria-labelledby="tenant-settings-heading" className="rounded-xl border border-border bg-surface p-5">
        <h2 id="tenant-settings-heading" className="text-lg font-semibold">Tenant Settings</h2>
        <dl className="mt-3 grid gap-2 text-sm sm:grid-cols-[14rem_1fr]">
          <dt className="text-hcl-muted">Tenant</dt>
          <dd>{activeTenantObj?.name || `Tenant #${currentTenantId}`}</dd>
          <dt className="text-hcl-muted">Status</dt>
          <dd>{activeTenantObj?.status || 'ACTIVE'}</dd>
          <dt className="text-hcl-muted">Authentication</dt>
          <dd>HCL.CS</dd>
          <dt className="text-hcl-muted">Tenant access</dt>
          <dd>Managed in SBOM</dd>
          <dt className="text-hcl-muted">External tenant mapping</dt>
          <dd>
            {resolveExternalTenantMapping(
              activeTenantObj?.identity_mapping ?? activeTenantObj?.identityMapping,
              activeTenantObj?.externalIamTenantId,
            ).displayStatus}
          </dd>
        </dl>
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

      <TenantAuditHistory tenantId={currentTenantId} />
    </div>
  );
}

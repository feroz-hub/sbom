'use client';

import { useState, FormEvent } from 'react';
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query';
import { useRouter } from 'next/navigation';
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
import { TenantContextHeader } from '@/components/admin/TenantContextHeader';
import { UserSearchCombobox } from '@/components/admin/UserSearchCombobox';
import { TenantAuditHistory } from '@/components/admin/TenantAuditHistory';
import { TenantMembersTable } from '@/components/admin/TenantMembersTable';
import { getRoleCode, getRoleLabel } from '@/lib/roles';
import { ManageRolesModal } from '@/components/admin/ManageRolesModal';
import { DisableMembershipDialog, EnableMembershipDialog, RemoveMemberDialog } from '@/components/admin/MembershipConfirmDialogs';

type MemberItem = Awaited<ReturnType<typeof getTenantMembers>>[number];

export default function TenantUsersPage() {
  const { user, tenants, activeTenant, activeTenantId, isTenantContextLoading, isLoading: authLoading, hasPermission, refreshSession } = useAuth();
  const router = useRouter();
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

  // Modal states
  const [rolesModalMember, setRolesModalMember] = useState<MemberItem | null>(null);
  const [disableModalMember, setDisableModalMember] = useState<MemberItem | null>(null);
  const [enableModalMember, setEnableModalMember] = useState<MemberItem | null>(null);
  const [removeModalMember, setRemoveModalMember] = useState<MemberItem | null>(null);

  const [actionLoading, setActionLoading] = useState(false);

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

  const addMemberMutation = useMutation({
    mutationFn: async () => {
      if (!selectedUser || !currentTenantId) return;
      await addTenantMember(currentTenantId, {
        user_id: selectedUser.id,
        roles: initialRoles,
      });
    },
    onSuccess: async () => {
      showSuccess(`User “${selectedUser?.display_name || selectedUser?.email}” was added to the tenant.`);
      setSelectedUser(null);
      await qc.invalidateQueries({ queryKey: ['tenant-users', currentTenantId] });
      await qc.invalidateQueries({ queryKey: ['tenant-audit-history', currentTenantId] });
    },
    onError: (error) => showError(getApiErrorMessage(error, 'Failed to add member to tenant.')),
  });

  const submitMember = (event: FormEvent) => {
    event.preventDefault();
    if (!selectedUser || !currentTenantId) return;
    addMemberMutation.mutate();
  };

  const handleSaveRoles = async (selectedRoles: TenantRole[]) => {
    if (!rolesModalMember || !currentTenantId) return;
    setActionLoading(true);
    try {
      await replaceTenantMemberRoles(
        currentTenantId,
        rolesModalMember.user_id,
        selectedRoles,
        rolesModalMember.role_assignment_version,
      );
      showSuccess('Roles updated successfully.');
      await qc.invalidateQueries({ queryKey: ['tenant-users', currentTenantId] });
      await qc.invalidateQueries({ queryKey: ['tenant-audit-history', currentTenantId] });

      if (user?.userId === rolesModalMember.user_id) {
        await refreshSession();
      }
      setRolesModalMember(null);
    } catch (err: unknown) {
      showError(getApiErrorMessage(err, 'Failed to update roles.'));
      throw err;
    } finally {
      setActionLoading(false);
    }
  };

  const handleConfirmDisable = async () => {
    if (!disableModalMember || !currentTenantId) return;
    setActionLoading(true);
    try {
      await deactivateTenantMember(currentTenantId, disableModalMember.membership_id);
      showSuccess('Membership disabled.');
      await qc.invalidateQueries({ queryKey: ['tenant-users', currentTenantId] });
      await qc.invalidateQueries({ queryKey: ['tenant-audit-history', currentTenantId] });

      if (user?.userId === disableModalMember.user_id) {
        await refreshSession();
        router.push('/access-pending');
        return;
      }
      setDisableModalMember(null);
    } catch (err: unknown) {
      showError(getApiErrorMessage(err, 'Failed to disable membership.'));
      throw err;
    } finally {
      setActionLoading(false);
    }
  };

  const handleConfirmEnable = async () => {
    if (!enableModalMember || !currentTenantId) return;
    setActionLoading(true);
    try {
      await activateTenantMember(currentTenantId, enableModalMember.membership_id);
      showSuccess('Membership enabled.');
      await qc.invalidateQueries({ queryKey: ['tenant-users', currentTenantId] });
      await qc.invalidateQueries({ queryKey: ['tenant-audit-history', currentTenantId] });
      setEnableModalMember(null);
    } catch (err: unknown) {
      showError(getApiErrorMessage(err, 'Failed to enable membership.'));
      throw err;
    } finally {
      setActionLoading(false);
    }
  };

  const handleConfirmRemove = async () => {
    if (!removeModalMember || !currentTenantId) return;
    setActionLoading(true);
    try {
      await removeTenantMember(currentTenantId, removeModalMember.membership_id);
      showSuccess('User removed from tenant.');
      await qc.invalidateQueries({ queryKey: ['tenant-users', currentTenantId] });
      await qc.invalidateQueries({ queryKey: ['tenant-audit-history', currentTenantId] });

      if (user?.userId === removeModalMember.user_id) {
        await refreshSession();
        router.push('/access-pending');
        return;
      }
      setRemoveModalMember(null);
    } catch (err: unknown) {
      showError(getApiErrorMessage(err, 'Failed to remove member.'));
      throw err;
    } finally {
      setActionLoading(false);
    }
  };

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

  const tenantName = activeTenantObj?.name || `Tenant #${currentTenantId}`;

  return (
    <div className="mx-auto max-w-6xl space-y-6 p-6">
      <TenantContextHeader
        name={tenantName}
        slug={activeTenantObj?.slug || 'Unavailable'}
        tenantStatus={activeTenantObj?.status || 'ACTIVE'}
        membershipStatus={activeTenantObj?.membershipStatus || 'ACTIVE'}
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
                  Initial Roles
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
                  disabled={addMemberMutation.isPending}
                  className="rounded-lg bg-[var(--btn-primary)] px-4 py-2 text-sm font-medium text-white hover:bg-[var(--btn-primary-hover)] disabled:opacity-50 transition-colors"
                >
                  {addMemberMutation.isPending ? 'Adding…' : 'Add Member'}
                </button>
              </div>
            )}
          </form>
        </section>
      )}

      {/* Read-Only Table & Responsive Card View — shared with the platform
          tenant detail page so the two surfaces cannot drift. */}
      <TenantMembersTable
        members={members.data}
        isLoading={members.isLoading}
        error={members.error}
        canUpdate={canUpdate}
        onManageRoles={setRolesModalMember}
        onDisableMembership={setDisableModalMember}
        onEnableMembership={setEnableModalMember}
        onRemoveFromTenant={setRemoveModalMember}
      />

      <section aria-labelledby="tenant-settings-heading" className="rounded-xl border border-border bg-surface p-5">
        <h2 id="tenant-settings-heading" className="text-lg font-semibold">Tenant Settings</h2>
        <dl className="mt-3 grid gap-2 text-sm sm:grid-cols-[14rem_1fr]">
          <dt className="text-hcl-muted">Tenant</dt>
          <dd>{tenantName}</dd>
          <dt className="text-hcl-muted">Tenant status</dt>
          <dd>{activeTenantObj?.status || 'ACTIVE'}</dd>
          <dt className="text-hcl-muted">Current membership</dt>
          <dd>{activeTenantObj?.membershipStatus || 'ACTIVE'}</dd>
          <dt className="text-hcl-muted">Authentication</dt>
          <dd>HCL.CS</dd>
          <dt className="text-hcl-muted">Tenant access</dt>
          <dd>Managed in SBOM</dd>
        </dl>
      </section>

      {/* Modals & Dialogs */}
      {rolesModalMember && (
        <ManageRolesModal
          open={rolesModalMember !== null}
          onClose={() => !actionLoading && setRolesModalMember(null)}
          displayName={rolesModalMember.display_name || rolesModalMember.email || `User #${rolesModalMember.user_id}`}
          tenantName={tenantName}
          currentRoles={rolesModalMember.roles ?? [rolesModalMember.role]}
          membershipVersion={rolesModalMember.role_assignment_version}
          isMembershipActive={rolesModalMember.status === 'ACTIVE'}
          loading={actionLoading}
          onSave={handleSaveRoles}
        />
      )}

      {disableModalMember && (
        <DisableMembershipDialog
          open={disableModalMember !== null}
          onClose={() => !actionLoading && setDisableModalMember(null)}
          displayName={disableModalMember.display_name || disableModalMember.email || `User #${disableModalMember.user_id}`}
          tenantName={tenantName}
          isSelf={user?.userId === disableModalMember.user_id}
          loading={actionLoading}
          onConfirm={handleConfirmDisable}
        />
      )}

      {enableModalMember && (
        <EnableMembershipDialog
          open={enableModalMember !== null}
          onClose={() => !actionLoading && setEnableModalMember(null)}
          displayName={enableModalMember.display_name || enableModalMember.email || `User #${enableModalMember.user_id}`}
          tenantName={tenantName}
          isSelf={user?.userId === enableModalMember.user_id}
          loading={actionLoading}
          onConfirm={handleConfirmEnable}
        />
      )}

      {removeModalMember && (
        <RemoveMemberDialog
          open={removeModalMember !== null}
          onClose={() => !actionLoading && setRemoveModalMember(null)}
          displayName={removeModalMember.display_name || removeModalMember.email || `User #${removeModalMember.user_id}`}
          tenantName={tenantName}
          isSelf={user?.userId === removeModalMember.user_id}
          loading={actionLoading}
          onConfirm={handleConfirmRemove}
        />
      )}

      <TenantAuditHistory tenantId={currentTenantId} />
    </div>
  );
}

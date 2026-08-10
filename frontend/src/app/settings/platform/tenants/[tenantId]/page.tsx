'use client';

import { use, useState, FormEvent } from 'react';
import Link from 'next/link';
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query';
import { useAuth } from '@/hooks/useAuth';
import {
  type TenantMember,
  type TenantRole,
  type UserSearchResult,
  activateTenantMember,
  addTenantMember,
  deactivateTenantMember,
  getAssignableTenantRoles,
  getTenantMembers,
  listPlatformTenants,
  removeTenantMember,
  replaceTenantMemberRoles,
  updatePlatformTenantStatus,
} from '@/lib/api';
import { useNotifications } from '@/hooks/useNotifications';
import { getApiErrorMessage } from '@/lib/notifications';
import { TenantContextHeader } from '@/components/admin/TenantContextHeader';
import { UserSearchCombobox } from '@/components/admin/UserSearchCombobox';
import { TenantAuditHistory } from '@/components/admin/TenantAuditHistory';
import { TenantMembersTable, memberDisplayName } from '@/components/admin/TenantMembersTable';
import { ManageRolesModal } from '@/components/admin/ManageRolesModal';
import { DisableMembershipDialog, EnableMembershipDialog, RemoveMemberDialog } from '@/components/admin/MembershipConfirmDialogs';
import { getRoleCode, getRoleLabel } from '@/lib/roles';

/**
 * Platform → Tenants → Manage.
 *
 * Member and role management is the SAME UX as `/settings/tenant`: the shared
 * {@link TenantMembersTable} (role badges + per-row action menu), the
 * {@link ManageRolesModal} and the membership confirm dialogs. What differs is
 * the context, and only the context: every operation targets
 * `numericTenantId` from the route, so a
 * platform admin manages a tenant WITHOUT switching their active tenant, and
 * the platform-only affordances (breadcrumb, tenant overview, tenant
 * enable/disable) stay on this page.
 */
export default function PlatformTenantDetailPage({
  params,
}: {
  params: Promise<{ tenantId: string }>;
}) {
  const { tenantId: tenantIdStr } = use(params);
  const numericTenantId = Number.parseInt(tenantIdStr, 10);
  const { user, hasPermission, isLoading: authLoading, refreshSession } = useAuth();
  const canManage = hasPermission('platform:tenant:create');
  const qc = useQueryClient();
  const { showSuccess, showError } = useNotifications();

  const [selectedUser, setSelectedUser] = useState<UserSearchResult | null>(null);
  const [initialRoles, setInitialRoles] = useState<TenantRole[]>(['VIEWER']);

  // Modal states — same set the tenant page drives.
  const [rolesModalMember, setRolesModalMember] = useState<TenantMember | null>(null);
  const [disableModalMember, setDisableModalMember] = useState<TenantMember | null>(null);
  const [enableModalMember, setEnableModalMember] = useState<TenantMember | null>(null);
  const [removeModalMember, setRemoveModalMember] = useState<TenantMember | null>(null);

  const [actionLoading, setActionLoading] = useState(false);

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
    queryKey: ['tenant-roles', numericTenantId],
    queryFn: () => getAssignableTenantRoles(numericTenantId),
    enabled: !authLoading && canManage,
  });

  const tenantName = tenant?.name || `Tenant #${tenantIdStr}`;

  /**
   * Membership changes alter this tenant's member list, its audit trail and
   * the member counts the platform tenant list renders.
   */
  const invalidateMembershipCaches = async () => {
    await qc.invalidateQueries({ queryKey: ['tenant-users', numericTenantId] });
    await qc.invalidateQueries({ queryKey: ['tenant-audit-history', numericTenantId] });
    await qc.invalidateQueries({ queryKey: ['platform-tenants'] });
  };

  const addMemberMutation = useMutation({
    mutationFn: async () => {
      if (!selectedUser) return;
      await addTenantMember(numericTenantId, {
        user_id: selectedUser.id,
        roles: initialRoles,
      });
    },
    onSuccess: async () => {
      showSuccess(`User “${selectedUser?.display_name || selectedUser?.email}” was added to ${tenantName}.`);
      setSelectedUser(null);
      await invalidateMembershipCaches();
    },
    onError: (error) => showError(getApiErrorMessage(error, 'Failed to add member to tenant.')),
  });

  const tenantStatus = useMutation({
    mutationFn: (status: 'ACTIVE' | 'DISABLED') =>
      updatePlatformTenantStatus(numericTenantId, status),
    onSuccess: async (_result, status) => {
      showSuccess(`Tenant ${status === 'ACTIVE' ? 'enabled' : 'disabled'} successfully.`);
      await qc.invalidateQueries({ queryKey: ['platform-tenants'] });
    },
    onError: (error) => showError(getApiErrorMessage(error, 'The tenant status could not be changed.')),
  });

  const submitMember = (event: FormEvent) => {
    event.preventDefault();
    if (!selectedUser) return;
    addMemberMutation.mutate();
  };

  /** A platform admin may be editing their own membership in this tenant —
   *  refresh the session so their permissions stay accurate. No redirect:
   *  platform context does not depend on membership in the managed tenant. */
  const refreshSessionIfSelf = async (member: TenantMember) => {
    if (user?.userId === member.user_id) {
      await refreshSession();
    }
  };

  const handleSaveRoles = async (selectedRoles: TenantRole[]) => {
    if (!rolesModalMember) return;
    setActionLoading(true);
    try {
      await replaceTenantMemberRoles(
        numericTenantId,
        rolesModalMember.user_id,
        selectedRoles,
        rolesModalMember.role_assignment_version,
      );
      showSuccess('Roles updated successfully.');
      await invalidateMembershipCaches();
      await refreshSessionIfSelf(rolesModalMember);
      setRolesModalMember(null);
    } catch (err: unknown) {
      showError(getApiErrorMessage(err, 'Failed to update roles.'));
      throw err;
    } finally {
      setActionLoading(false);
    }
  };

  const handleConfirmDisable = async () => {
    if (!disableModalMember) return;
    setActionLoading(true);
    try {
      await deactivateTenantMember(numericTenantId, disableModalMember.membership_id);
      showSuccess('Membership disabled.');
      await invalidateMembershipCaches();
      await refreshSessionIfSelf(disableModalMember);
      setDisableModalMember(null);
    } catch (err: unknown) {
      showError(getApiErrorMessage(err, 'Failed to disable membership.'));
      throw err;
    } finally {
      setActionLoading(false);
    }
  };

  const handleConfirmEnable = async () => {
    if (!enableModalMember) return;
    setActionLoading(true);
    try {
      await activateTenantMember(numericTenantId, enableModalMember.membership_id);
      showSuccess('Membership enabled.');
      await invalidateMembershipCaches();
      await refreshSessionIfSelf(enableModalMember);
      setEnableModalMember(null);
    } catch (err: unknown) {
      showError(getApiErrorMessage(err, 'Failed to enable membership.'));
      throw err;
    } finally {
      setActionLoading(false);
    }
  };

  const handleConfirmRemove = async () => {
    if (!removeModalMember) return;
    setActionLoading(true);
    try {
      await removeTenantMember(numericTenantId, removeModalMember.membership_id);
      showSuccess('User removed from tenant.');
      await invalidateMembershipCaches();
      await refreshSessionIfSelf(removeModalMember);
      setRemoveModalMember(null);
    } catch (err: unknown) {
      showError(getApiErrorMessage(err, 'Failed to remove member.'));
      throw err;
    } finally {
      setActionLoading(false);
    }
  };

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
        <span className="text-foreground font-medium">{tenantName}</span>
      </nav>

      {tenant ? (
        <TenantContextHeader
          name={tenant.name}
          slug={tenant.slug}
          tenantStatus={tenant.status}
          membershipStatus="ACTIVE"
          memberCount={tenant.member_count ?? members.data?.length}
          initialAdministrator={
            tenant.initial_administrator
              ? `${tenant.initial_administrator.display_name || 'Unnamed user'} (${tenant.initial_administrator.email || 'no email'})`
              : undefined
          }
          currentAdministrators={(tenant.current_administrators ?? []).map(
            (administrator) => administrator.display_name || administrator.email || `User #${administrator.user_id}`,
          )}
        />
      ) : (
        <div className="rounded-xl border border-border bg-surface p-5 text-center text-hcl-muted">
          Loading tenant details…
        </div>
      )}

      <section aria-labelledby="overview-heading" className="rounded-xl border border-border bg-surface p-5">
        <h2 id="overview-heading" className="text-lg font-semibold">Overview</h2>
        <p className="mt-1 text-sm text-hcl-muted">
          You are managing {tenant?.name || `tenant #${tenantIdStr}`} in explicit platform context.
          Access is controlled by SBOM tenant memberships and assigned roles.
        </p>
      </section>

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
              onSelect={(candidate) => setSelectedUser(candidate)}
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

      {/* Members — identical to /settings/tenant, scoped to the route tenant. */}
      <TenantMembersTable
        members={members.data}
        isLoading={members.isLoading}
        error={members.error}
        canUpdate={canManage}
        onManageRoles={setRolesModalMember}
        onDisableMembership={setDisableModalMember}
        onEnableMembership={setEnableModalMember}
        onRemoveFromTenant={setRemoveModalMember}
      />

      <section aria-labelledby="tenant-settings-heading" className="rounded-xl border border-border bg-surface p-5">
        <h2 id="tenant-settings-heading" className="text-lg font-semibold">Tenant Settings</h2>
        <p className="mt-1 text-sm text-hcl-muted">
          Current status: <strong>{tenant?.status || 'Loading'}</strong>
        </p>
        {tenant && (
          <button
            type="button"
            disabled={tenantStatus.isPending}
            onClick={() => tenantStatus.mutate(tenant.status === 'ACTIVE' ? 'DISABLED' : 'ACTIVE')}
            className="mt-3 rounded-md border border-border px-3 py-2 text-sm font-medium disabled:opacity-50"
          >
            {tenantStatus.isPending
              ? 'Updating…'
              : tenant.status === 'ACTIVE'
                ? 'Disable Tenant'
                : 'Enable Tenant'}
          </button>
        )}
      </section>

      {/* Modals & Dialogs */}
      {rolesModalMember && (
        <ManageRolesModal
          open={rolesModalMember !== null}
          onClose={() => !actionLoading && setRolesModalMember(null)}
          displayName={memberDisplayName(rolesModalMember)}
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
          displayName={memberDisplayName(disableModalMember)}
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
          displayName={memberDisplayName(enableModalMember)}
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
          displayName={memberDisplayName(removeModalMember)}
          tenantName={tenantName}
          isSelf={user?.userId === removeModalMember.user_id}
          loading={actionLoading}
          onConfirm={handleConfirmRemove}
        />
      )}

      <TenantAuditHistory tenantId={numericTenantId} />
    </div>
  );
}

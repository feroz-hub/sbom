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
  replaceTenantMemberRoles,
  updatePlatformTenantStatus,
} from '@/lib/api';
import { useNotifications } from '@/hooks/useNotifications';
import { getApiErrorMessage } from '@/lib/notifications';
import { ConfirmationDialog } from '@/components/ui/ConfirmationDialog';
import { TenantContextHeader } from '@/components/admin/TenantContextHeader';
import { UserSearchCombobox } from '@/components/admin/UserSearchCombobox';
import { TenantAuditHistory } from '@/components/admin/TenantAuditHistory';
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
  const [initialRoles, setInitialRoles] = useState<TenantRole[]>(['VIEWER']);
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
    queryKey: ['tenant-roles', numericTenantId],
    queryFn: () => getAssignableTenantRoles(numericTenantId),
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
    action.mutate({
      operation: async () => {
        await addTenantMember(numericTenantId, {
          user_id: selectedUser.id,
          roles: initialRoles,
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
          identityMapping={tenant.identity_mapping}
          isPlatformAdmin={true}
          status={tenant.status}
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
          SBOM validates this target using the Platform Administrator grant; HCL.CS tenant claims are not authorization.
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
              onSelect={(user) => setSelectedUser(user)}
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
                  <th className="px-4 py-2 text-left font-medium">Roles</th>
                  <th className="px-4 py-2 text-left font-medium">Membership Status</th>
                  <th className="px-4 py-2 text-left font-medium">User Status</th>
                  <th className="px-4 py-2 text-right font-medium">Actions</th>
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
                              numericTenantId,
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
                    </td>
                    <td className="px-4 py-3"><MembershipStatusBadge status={member.status} /></td>
                    <td className="px-4 py-3"><UserStatusBadge status={member.user_status} /></td>
                    <td className="space-x-3 px-4 py-3 text-right">
                      {member.status === 'ACTIVE' ? (
                        <button
                          type="button"
                          className="text-amber-700 hover:underline"
                          onClick={() => confirmAction({
                            title: `Deactivate “${member.display_name || member.email || `User #${member.user_id}`}”?`,
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
                          title: `Remove “${member.display_name || member.email || `User #${member.user_id}`}”?`,
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

      <ConfirmationDialog
        open={confirmation !== null}
        title={confirmation?.title ?? ''}
        description={confirmation?.description ?? ''}
        confirmLabel={confirmation?.confirmLabel ?? 'Confirm'}
        loading={action.isPending}
        onClose={() => !action.isPending && setConfirmation(null)}
        onConfirm={() => confirmation && action.mutate(confirmation)}
      />

      <TenantAuditHistory tenantId={numericTenantId} />
    </div>
  );
}

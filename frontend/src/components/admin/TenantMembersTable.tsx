'use client';

import { type ReactNode } from 'react';
import { Users } from 'lucide-react';
import { type TenantMember } from '@/lib/api';
import { getRoleLabel } from '@/lib/roles';
import { getApiErrorMessage } from '@/lib/notifications';
import { MemberActionMenu } from './MemberActionMenu';
import { VerificationBadge, UserStatusBadge, RoleBadges } from './StatusBadges';

interface TenantMembersTableProps {
  title?: string;
  totalMemberCount?: number;
  toolbar?: ReactNode;
  emptyMessage?: string;
  members: TenantMember[] | undefined;
  isLoading: boolean;
  error: unknown;
  /** Gates the actions menu. Tenant admins pass `tenant:user:update`; the
   *  platform tenant detail page passes its platform-admin permission. */
  canUpdate: boolean;
  onManageRoles: (member: TenantMember) => void;
  onDisableMembership: (member: TenantMember) => void;
  onEnableMembership: (member: TenantMember) => void;
  onRemoveFromTenant: (member: TenantMember) => void;
}

export function memberDisplayName(member: TenantMember): string {
  return member.display_name || member.email || 'Member';
}

/**
 * The Tenant Members section — one implementation for both places tenant
 * memberships are managed:
 *
 *   * `/settings/users` — the acting user's own tenant.
 *   * `/settings/platform/tenants/[tenantId]` — an arbitrary tenant in
 *     explicit platform context, without switching the active tenant.
 *
 * Shared with TenantUsersAccess so the two surfaces
 * cannot drift again: the platform page had kept an older inline
 * `<select multiple>` + text-button flow long after this one replaced it.
 * The component owns presentation only — every mutation, tenant id and
 * cache invalidation stays with the page, which is what differs between
 * the two contexts.
 */
export function TenantMembersTable({
  title = 'Tenant Members',
  totalMemberCount,
  toolbar,
  emptyMessage = 'No tenant memberships currently exist.',
  members,
  isLoading,
  error,
  canUpdate,
  onManageRoles,
  onDisableMembership,
  onEnableMembership,
  onRemoveFromTenant,
}: TenantMembersTableProps) {
  return (
    <section aria-labelledby="members-heading" className="min-w-0 rounded-xl border border-border bg-surface shadow-elev-1">
      <div className="space-y-4 p-4 sm:p-5">
        <div className="flex items-center gap-2.5">
          <h2 id="members-heading" className="text-lg font-semibold text-foreground">{title}</h2>
          {typeof (totalMemberCount ?? members?.length) === 'number' && <span className="rounded-full border border-border bg-surface-muted px-2.5 py-0.5 text-xs font-medium text-hcl-muted" aria-label={`${totalMemberCount ?? members?.length} total members`}>{totalMemberCount ?? members?.length}</span>}
        </div>
        {toolbar}
      </div>

      {isLoading && <p role="status" className="border-t border-border p-8 text-center text-sm text-hcl-muted">Loading members…</p>}
      {error ? (
        <p role="alert" className="border-t border-border p-5 text-sm text-red-700 dark:text-red-300">{getApiErrorMessage(error, 'Could not load members.')}</p>
      ) : null}
      {!isLoading && !error && members?.length === 0 && (
        <div className="border-t border-border p-8 text-center text-hcl-muted">
          <Users className="mx-auto mb-3 h-7 w-7" aria-hidden="true" />
          {emptyMessage}
        </div>
      )}

      {!isLoading && !error && members && members.length > 0 && (
        <>
          {/* Desktop Read-Only Table */}
          <div className="hidden md:block overflow-x-auto border-t border-border">
            <table className="w-full min-w-[960px] table-fixed text-sm">
              <caption className="sr-only">Tenant membership directory with verification, effective roles, membership and user account status</caption>
              <colgroup><col className="w-[24%]" /><col className="w-[17%]" /><col className="w-[20%]" /><col className="w-[12%]" /><col className="w-[19%]" /><col className="w-[8%]" /></colgroup>
              <thead className="bg-surface-elevated border-b border-border">
                <tr>
                  <th scope="col" className="px-4 py-3 text-left text-xs font-semibold text-hcl-muted">User</th>
                  <th scope="col" className="px-4 py-3 text-left text-xs font-semibold text-hcl-muted">Verification</th>
                  <th scope="col" className="px-4 py-3 text-left text-xs font-semibold text-hcl-muted">Effective roles</th>
                  <th scope="col" className="px-4 py-3 text-left text-xs font-semibold text-hcl-muted">Membership</th>
                  <th scope="col" className="px-4 py-3 text-left text-xs font-semibold text-hcl-muted">User account</th>
                  <th scope="col" className="px-4 py-3 text-right text-xs font-semibold text-hcl-muted">Actions</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-border">
                {members.map((member) => {
                  const isMemberActive = member.status === 'ACTIVE';
                  const activeRoles = member.roles ?? [member.role];
                  const displayName = memberDisplayName(member);

                  return (
                    <tr key={member.membership_id} className="hover:bg-surface-elevated/50 transition-colors">
                      <td className="px-4 py-3.5">
                        <div className="flex min-w-0 items-center gap-3">
                          <span aria-hidden="true" className="flex h-9 w-9 shrink-0 items-center justify-center rounded-full bg-hcl-blue/10 text-xs font-semibold text-hcl-blue">{displayName.split(/\s+/).slice(0, 2).map(part => part[0]).join('').toUpperCase()}</span>
                          <div className="min-w-0">
                            <div title={displayName} className="truncate font-semibold text-foreground">{displayName}</div>
                            <div title={member.email || 'No email'} className="mt-0.5 truncate text-xs text-hcl-muted">{member.email || 'No email'}</div>
                          </div>
                        </div>
                      </td>
                      <td className="px-4 py-3.5">
                        <VerificationBadge verified={member.email_verified && !member.verification_required} required={member.verification_required} />
                      </td>
                      <td className="px-4 py-3.5">
                        <div className="space-y-1">
                          <RoleBadges roles={activeRoles} membershipActive={isMemberActive} />
                          {!isMemberActive && activeRoles.length > 0 && (
                            <p className="text-[11px] text-hcl-muted">
                              Assigned roles: {activeRoles.map(getRoleLabel).join(', ')} | Effective access: None — membership disabled
                            </p>
                          )}
                        </div>
                      </td>
                      <td className="px-4 py-3.5">
                        <span
                          className={`inline-flex items-center rounded-full px-2.5 py-0.5 text-xs font-medium border ${
                            isMemberActive
                              ? 'bg-emerald-50 text-emerald-700 border-emerald-200 dark:bg-emerald-950/20 dark:text-emerald-400 dark:border-emerald-800/50'
                              : 'bg-zinc-100 text-zinc-600 border-zinc-200 dark:bg-zinc-800 dark:text-zinc-400 dark:border-zinc-700'
                          }`}
                        >
                          {isMemberActive ? 'Active' : 'Disabled'}
                        </span>
                      </td>
                      <td className="px-4 py-3.5">
                        <UserStatusBadge status={member.user_status} />
                      </td>
                      <td className="px-4 py-3.5 text-right">
                        <MemberActionMenu
                          displayName={displayName}
                          membershipStatus={member.status}
                          canUpdate={canUpdate}
                          onManageRoles={() => onManageRoles(member)}
                          onDisableMembership={() => onDisableMembership(member)}
                          onEnableMembership={() => onEnableMembership(member)}
                          onRemoveFromTenant={() => onRemoveFromTenant(member)}
                        />
                      </td>
                    </tr>
                  );
                })}
              </tbody>
            </table>
          </div>

          {/* Mobile Cards Layout */}
          <div className="grid gap-3 border-t border-border bg-surface-muted/30 p-3 md:hidden">
            {members.map((member) => {
              const isMemberActive = member.status === 'ACTIVE';
              const activeRoles = member.roles ?? [member.role];
              const displayName = memberDisplayName(member);

              return (
                <div key={member.membership_id} className="rounded-xl border border-border bg-surface p-4 space-y-3 shadow-elev-1">
                  <div className="flex items-start justify-between gap-3">
                    <div className="min-w-0">
                      <div className="break-words font-semibold text-foreground">{displayName}</div>
                      <div className="break-all text-xs text-hcl-muted">{member.email || 'No email'}</div>
                    </div>
                    <MemberActionMenu
                      displayName={displayName}
                      membershipStatus={member.status}
                      canUpdate={canUpdate}
                      onManageRoles={() => onManageRoles(member)}
                      onDisableMembership={() => onDisableMembership(member)}
                      onEnableMembership={() => onEnableMembership(member)}
                      onRemoveFromTenant={() => onRemoveFromTenant(member)}
                    />
                  </div>

                  <div className="space-y-2 pt-1 text-xs">
                    <div>
                      <span className="text-hcl-muted font-medium block mb-1">Effective roles:</span>
                      <RoleBadges roles={activeRoles} membershipActive={isMemberActive} />
                      {!isMemberActive && activeRoles.length > 0 && (
                        <p className="mt-1 text-[11px] text-hcl-muted">
                          Assigned roles: {activeRoles.map(getRoleLabel).join(', ')} | Effective access: None — membership disabled
                        </p>
                      )}
                    </div>

                    <div className="flex flex-wrap items-center gap-2 pt-1">
                      <VerificationBadge verified={member.email_verified && !member.verification_required} required={member.verification_required} />
                      <span
                        className={`inline-flex items-center rounded-full px-2.5 py-0.5 text-xs font-medium border ${
                          isMemberActive
                            ? 'bg-emerald-50 text-emerald-700 border-emerald-200 dark:bg-emerald-950/20 dark:text-emerald-400 dark:border-emerald-800/50'
                            : 'bg-zinc-100 text-zinc-600 border-zinc-200 dark:bg-zinc-800 dark:text-zinc-400 dark:border-zinc-700'
                        }`}
                      >
                        Membership: {isMemberActive ? 'Active' : 'Disabled'}
                      </span>
                      <UserStatusBadge status={member.user_status} />
                    </div>
                  </div>
                </div>
              );
            })}
          </div>
        </>
      )}
    </section>
  );
}

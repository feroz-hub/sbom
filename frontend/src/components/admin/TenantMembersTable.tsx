'use client';

import { type TenantMember } from '@/lib/api';
import { getRoleLabel } from '@/lib/roles';
import { getApiErrorMessage } from '@/lib/notifications';
import { MemberActionMenu } from './MemberActionMenu';
import { VerificationBadge, UserStatusBadge, RoleBadges } from './StatusBadges';

interface TenantMembersTableProps {
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
  return member.display_name || member.email || `User #${member.user_id}`;
}

/**
 * The Tenant Members section — one implementation for both places tenant
 * memberships are managed:
 *
 *   * `/settings/tenant` — the acting user's own tenant.
 *   * `/settings/platform/tenants/[tenantId]` — an arbitrary tenant in
 *     explicit platform context, without switching the active tenant.
 *
 * Extracted from the `/settings/tenant` page verbatim so the two surfaces
 * cannot drift again: the platform page had kept an older inline
 * `<select multiple>` + text-button flow long after this one replaced it.
 * The component owns presentation only — every mutation, tenant id and
 * cache invalidation stays with the page, which is what differs between
 * the two contexts.
 */
export function TenantMembersTable({
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
    <section aria-labelledby="members-heading" className="space-y-3">
      <h2 id="members-heading" className="text-lg font-semibold text-foreground">Tenant Members</h2>

      {isLoading && <p className="text-sm text-hcl-muted">Loading members…</p>}
      {error ? (
        <p role="alert" className="text-sm text-red-600">{getApiErrorMessage(error, 'Could not load members.')}</p>
      ) : null}
      {members?.length === 0 && (
        <div className="rounded-lg border border-dashed border-border p-8 text-center text-hcl-muted">
          No tenant memberships currently exist. Use the search form above to add a member.
        </div>
      )}

      {members && members.length > 0 && (
        <>
          {/* Desktop Read-Only Table */}
          <div className="hidden md:block overflow-x-auto rounded-xl border border-border bg-surface shadow-elev-1">
            <table className="min-w-full text-sm">
              <thead className="bg-surface-elevated border-b border-border">
                <tr>
                  <th className="px-4 py-3 text-left font-semibold text-foreground">User</th>
                  <th className="px-4 py-3 text-left font-semibold text-foreground">Verification</th>
                  <th className="px-4 py-3 text-left font-semibold text-foreground">Effective roles</th>
                  <th className="px-4 py-3 text-left font-semibold text-foreground">Membership</th>
                  <th className="px-4 py-3 text-left font-semibold text-foreground">User account</th>
                  <th className="px-4 py-3 text-right font-semibold text-foreground">Actions</th>
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
                        <div className="font-medium text-foreground">{displayName}</div>
                        <div className="text-xs text-hcl-muted">{member.email || 'No email'}</div>
                      </td>
                      <td className="px-4 py-3.5">
                        <VerificationBadge verified={member.email_verified && !member.verification_required} />
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
                              ? 'bg-emerald-50 text-emerald-700 border-emerald-200 dark:bg-emerald-950/20 dark:text-emerald-400 border-emerald-800/50'
                              : 'bg-zinc-100 text-zinc-600 border-zinc-200 dark:bg-zinc-800 dark:text-zinc-400 border-zinc-700'
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
          <div className="grid gap-3 md:hidden">
            {members.map((member) => {
              const isMemberActive = member.status === 'ACTIVE';
              const activeRoles = member.roles ?? [member.role];
              const displayName = memberDisplayName(member);

              return (
                <div key={member.membership_id} className="rounded-xl border border-border bg-surface p-4 space-y-3 shadow-elev-1">
                  <div className="flex items-start justify-between gap-3">
                    <div>
                      <div className="font-semibold text-foreground">{displayName}</div>
                      <div className="text-xs text-hcl-muted">{member.email || 'No email'}</div>
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
                      <VerificationBadge verified={member.email_verified && !member.verification_required} />
                      <span
                        className={`inline-flex items-center rounded-full px-2.5 py-0.5 text-xs font-medium border ${
                          isMemberActive
                            ? 'bg-emerald-50 text-emerald-700 border-emerald-200 dark:bg-emerald-950/20 dark:text-emerald-400 border-emerald-800/50'
                            : 'bg-zinc-100 text-zinc-600 border-zinc-200 dark:bg-zinc-800 dark:text-zinc-400 border-zinc-700'
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

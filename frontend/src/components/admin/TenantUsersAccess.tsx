'use client';

import { useRef, useState, useId, FormEvent } from 'react';
import { Search, X, UserPlus, MailPlus, Users } from 'lucide-react';
import { Button } from '@/components/ui/Button';
import { ROLE_DESCRIPTIONS } from './StatusBadges';
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query';
import { useRouter } from 'next/navigation';
import { usePermissions } from '@/hooks/usePermission';
import { invalidateTenantMembershipSurfaces } from '@/lib/queryInvalidation';
import { useMutationScope } from '@/hooks/useMutationScope';
import { useAuth } from '@/hooks/useAuth';
import NativeUserInviteForm from './NativeUserInviteForm';
import { Dialog, DialogBody } from '@/components/ui/Dialog';
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
import { TenantContextHeader, TenantAccessInformation } from '@/components/admin/TenantContextHeader';
import { UserSearchCombobox } from '@/components/admin/UserSearchCombobox';
import { TenantAuditHistory } from '@/components/admin/TenantAuditHistory';
import { TenantMembersTable } from '@/components/admin/TenantMembersTable';
import { getRoleCode, getRoleLabel } from '@/lib/roles';
import { ManageRolesModal } from '@/components/admin/ManageRolesModal';
import { DisableMembershipDialog, EnableMembershipDialog, RemoveMemberDialog } from '@/components/admin/MembershipConfirmDialogs';

type MemberItem = Awaited<ReturnType<typeof getTenantMembers>>[number];

export default function TenantUsersAccess() {
  const { activeTenantId, user } = useAuth();
  // Reset search, candidate selection and open dialogs on every tenant/account switch,
  // including consumers that do not key this component at the route level.
  return <TenantUsersAccessContent key={`${activeTenantId ?? user?.tenantId ?? 'none'}:${user?.userId ?? 'anonymous'}`} />;
}

function TenantUsersAccessContent() {
  const addFormId = useId();
  const { user, tenants, activeTenant, activeTenantId, isTenantContextLoading, isLoading: authLoading,  refreshSession } = useAuth();
  const { can: hasPermission } = usePermissions();
  const router = useRouter();
  const currentTenantId = activeTenantId ? activeTenantId : (user?.tenantId ? user.tenantId : null);
  const tenantsList = Array.isArray(tenants) ? tenants : [];
  const activeTenantObj = activeTenant ?? tenantsList.find((t) => t.id === currentTenantId);
  const canRead = hasPermission('tenant:user:read');
  const canUpdate = hasPermission('tenant:user:update');
  const canInvite = hasPermission('tenant:user:invite');
  const qc = useQueryClient();
  const mutationScope = useMutationScope();
  const { showSuccess, showError } = useNotifications();

  const memberSearchRef = useRef<HTMLInputElement>(null);
  const [memberSearch, setMemberSearch] = useState('');
  const [addOpen, setAddOpen] = useState(false);
  const [directoryRevision, setDirectoryRevision] = useState(0);
  const [selectedUser, setSelectedUser] = useState<UserSearchResult | null>(null);
  const [initialRoles, setInitialRoles] = useState<TenantRole[]>(['VIEWER']);

  // Modal states
  const [rolesModalMember, setRolesModalMember] = useState<MemberItem | null>(null);
  const [disableModalMember, setDisableModalMember] = useState<MemberItem | null>(null);
  const [enableModalMember, setEnableModalMember] = useState<MemberItem | null>(null);
  const [removeModalMember, setRemoveModalMember] = useState<MemberItem | null>(null);

  const [actionLoading, setActionLoading] = useState(false);
  const [inviteOpen, setInviteOpen] = useState(false);
  const [inviteBusy, setInviteBusy] = useState(false);

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
        roles: assignableInitialRoles,
      });
    },
    onMutate: () => mutationScope.capture(),
    onSuccess: async (_result, _variables, isCurrent) => {
      if (!isCurrent?.()) return;
      showSuccess(`User “${selectedUser?.display_name || selectedUser?.email}” was added to the tenant.`);
      if (user?.userId === selectedUser?.id) await refreshSession({ authorizationChanged: true });
      setSelectedUser(null);
      setAddOpen(false);
      await invalidateTenantMembershipSurfaces(qc, currentTenantId!);
      setDirectoryRevision(n => n + 1);
    },
    onError: (error, _variables, isCurrent) => {
      if (isCurrent?.()) showError(getApiErrorMessage(error, 'Failed to add member to tenant.'));
    },
  });

  const assignableRoles = roles.data?.roles ?? [];
  const assignableInitialRoles = initialRoles.filter(role => assignableRoles.some(allowed => getRoleCode(allowed) === role));
  const validInitialRoles = !roles.isPending && !roles.error && assignableInitialRoles.length > 0;

  const submitMember = (event: FormEvent) => {
    event.preventDefault();
    if (!selectedUser || !currentTenantId || !canInvite || addMemberMutation.isPending || !validInitialRoles) return;
    addMemberMutation.mutate();
  };

  const handleSaveRoles = async (selectedRoles: TenantRole[]) => {
    if (!rolesModalMember || !currentTenantId) return;
    const isCurrent = mutationScope.capture();
    setActionLoading(true);
    try {
      await replaceTenantMemberRoles(
        currentTenantId,
        rolesModalMember.user_id,
        selectedRoles,
        rolesModalMember.role_assignment_version,
      );
      if (!isCurrent()) return;
      showSuccess('Roles updated successfully.');
      if (user?.userId === rolesModalMember.user_id) await refreshSession({ authorizationChanged: true });
      await invalidateTenantMembershipSurfaces(qc, currentTenantId!);
      setDirectoryRevision(n => n + 1);
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
    const isCurrent = mutationScope.capture();
    setActionLoading(true);
    try {
      await deactivateTenantMember(currentTenantId, disableModalMember.membership_id);
      if (!isCurrent()) return;
      showSuccess('Membership disabled.');
      if (user?.userId === disableModalMember.user_id) {
        await refreshSession({ authorizationChanged: true });
        router.push('/access-pending');
        return;
      }
      await invalidateTenantMembershipSurfaces(qc, currentTenantId!);
      setDirectoryRevision(n => n + 1);
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
    const isCurrent = mutationScope.capture();
    setActionLoading(true);
    try {
      await activateTenantMember(currentTenantId, enableModalMember.membership_id);
      if (!isCurrent()) return;
      showSuccess('Membership enabled.');
      if (user?.userId === enableModalMember.user_id) await refreshSession({ authorizationChanged: true });
      await invalidateTenantMembershipSurfaces(qc, currentTenantId!);
      setDirectoryRevision(n => n + 1);
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
    const isCurrent = mutationScope.capture();
    setActionLoading(true);
    try {
      await removeTenantMember(currentTenantId, removeModalMember.membership_id);
      if (!isCurrent()) return;
      showSuccess('User removed from tenant.');
      if (user?.userId === removeModalMember.user_id) {
        await refreshSession({ authorizationChanged: true });
        router.push('/access-pending');
        return;
      }
      await invalidateTenantMembershipSurfaces(qc, currentTenantId!);
      setDirectoryRevision(n => n + 1);
      setRemoveModalMember(null);
    } catch (err: unknown) {
      showError(getApiErrorMessage(err, 'Failed to remove member.'));
      throw err;
    } finally {
      setActionLoading(false);
    }
  };

  if (authLoading || isTenantContextLoading) {
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

  const searchTerm = memberSearch.trim().toLocaleLowerCase();
  const filteredMembers = searchTerm ? members.data?.filter(member =>
    [member.display_name, member.email].some(value => value?.toLocaleLowerCase().includes(searchTerm)),
  ) : members.data;
  const closeAdd = () => { if (!addMemberMutation.isPending) setAddOpen(false); };

  return (
    <div className="min-w-0 space-y-5">
      <TenantContextHeader
        name={tenantName}
        slug={activeTenantObj?.slug || 'Unavailable'}
        tenantStatus={activeTenantObj?.status || 'ACTIVE'}
        membershipStatus={activeTenantObj?.membershipStatus || 'ACTIVE'}
        memberCount={members.data?.length}
      />

      <TenantMembersTable
        title="Member Directory"
        totalMemberCount={members.data?.length}
        toolbar={
          <div className="space-y-4">
            <div className="flex flex-col gap-3 xl:flex-row xl:items-center xl:justify-between">
              <div className="relative w-full xl:max-w-sm">
                <Search className="pointer-events-none absolute left-3 top-3 h-4 w-4 text-hcl-muted" aria-hidden="true" />
                <input ref={memberSearchRef} type="search" aria-label="Search members" placeholder="Search members by name or email…"
                  value={memberSearch} onChange={event => setMemberSearch(event.target.value)}
                  className="h-11 w-full rounded-lg border border-border bg-background pl-9 pr-11 text-sm text-foreground placeholder:text-hcl-muted focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-hcl-blue [&::-webkit-search-cancel-button]:appearance-none" />
                {memberSearch && <button type="button" aria-label="Clear member search" title="Clear member search"
                  onClick={() => { setMemberSearch(''); memberSearchRef.current?.focus(); }}
                  className="absolute right-0 top-0 flex h-11 w-11 items-center justify-center rounded-lg text-hcl-muted hover:bg-surface-muted focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-hcl-blue">
                  <X className="h-4 w-4" aria-hidden="true" />
                </button>}
              </div>
              {canInvite && <div className="flex flex-col gap-2 sm:flex-row">
                <Button variant="secondary" className="min-h-11" onClick={() => {
                  setSelectedUser(null); setInitialRoles(['VIEWER']); addMemberMutation.reset(); setAddOpen(true);
                }}><UserPlus className="h-4 w-4" aria-hidden="true" />Add Existing Member</Button>
                <Button className="min-h-11" onClick={() => setInviteOpen(true)}><MailPlus className="h-4 w-4" aria-hidden="true" />Invite New User</Button>
              </div>}
            </div>
            {!members.isLoading && !members.error && members.data && (searchTerm || (!canUpdate && !canInvite)) && <p role="status" className="flex items-center gap-2 text-xs text-hcl-muted">
              <Users className="h-4 w-4" aria-hidden="true" />
              {searchTerm && `${filteredMembers?.length ?? 0} of ${members.data.length} members match your search`}
              {!canUpdate && !canInvite && <span>{searchTerm ? '· ' : ''}Read-only access</span>}
            </p>}
          </div>
        }
        emptyMessage={searchTerm ? 'No matching members. Try another name or email, or clear your search.' : undefined}
        members={filteredMembers}
        isLoading={members.isLoading}
        error={members.error}
        canUpdate={canUpdate}
        onManageRoles={setRolesModalMember}
        onDisableMembership={setDisableModalMember}
        onEnableMembership={setEnableModalMember}
        onRemoveFromTenant={setRemoveModalMember}
      />

      <TenantAccessInformation />
      <TenantAuditHistory tenantId={currentTenantId} />

      {canInvite && <>
        <Dialog open={addOpen} title="Add Existing Member" maxWidth="lg" dismissOnBackdrop={!addMemberMutation.isPending} onClose={closeAdd} footer={
          <div className="flex justify-end gap-3 px-6 py-4">
            <Button variant="secondary" onClick={closeAdd} disabled={addMemberMutation.isPending}>Cancel</Button>
            <Button type="submit" form={addFormId} loading={addMemberMutation.isPending} loadingLabel="Adding member" disabled={!selectedUser || !validInitialRoles}>{addMemberMutation.isPending ? 'Adding…' : 'Add Member'}</Button>
          </div>
        }>
          <form id={addFormId} onSubmit={submitMember}>
            <DialogBody className="space-y-5">
              <p className="text-sm leading-6 text-hcl-muted">Add an existing SBOM Analyzer account to <strong className="text-foreground">{tenantName}</strong>. This does not create a new user account.</p>
              {addMemberMutation.error && <p role="alert" className="rounded-lg border border-red-200 bg-red-50 p-3 text-sm text-red-700 dark:border-red-900/50 dark:bg-red-950/20 dark:text-red-300">{getApiErrorMessage(addMemberMutation.error, 'Failed to add member to tenant.')}</p>}
              <fieldset disabled={addMemberMutation.isPending} className="min-w-0 space-y-4">
                <legend className="mb-2 text-sm font-semibold">Search existing user</legend>
                <UserSearchCombobox tenantId={currentTenantId} revision={directoryRevision} onSelect={setSelectedUser} selectedUser={selectedUser} placeholder="Search existing users by name or email…" />
              </fieldset>
              {selectedUser && <fieldset disabled={addMemberMutation.isPending} className="space-y-3">
                <legend className="text-sm font-semibold">Initial roles</legend>
                <p className="text-xs text-hcl-muted">Select one or more tenant roles. Viewer is selected by default when assignable.</p>
                {roles.isPending && <p role="status" className="text-sm text-hcl-muted">Loading assignable roles…</p>}
                {roles.error && <p role="alert" className="text-sm text-red-700 dark:text-red-300">Could not load assignable roles. <button type="button" className="underline focus-visible:ring-2 focus-visible:ring-hcl-blue" onClick={() => void roles.refetch()}>Try again</button></p>}
                <div className="grid gap-2 sm:grid-cols-2">
                  {assignableRoles.map(role => {
                    const code = getRoleCode(role);
                    return <label key={code} className="flex cursor-pointer items-start gap-3 rounded-lg border border-border p-3 hover:bg-surface-muted has-[:checked]:border-hcl-blue/50 has-[:checked]:bg-hcl-blue/5">
                      <input type="checkbox" checked={initialRoles.includes(code)}
                        onChange={event => setInitialRoles(previous => event.target.checked ? [...previous, code] : previous.filter(item => item !== code))}
                        className="mt-0.5 h-4 w-4 shrink-0 accent-hcl-blue focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-hcl-blue" />
                      <span className="text-sm font-medium">{getRoleLabel(role)}<span className="mt-1 block text-xs font-normal leading-5 text-hcl-muted">{ROLE_DESCRIPTIONS[code]}</span></span>
                    </label>;
                  })}
                </div>
                {!roles.isPending && !roles.error && !validInitialRoles && <p className="text-xs text-amber-700 dark:text-amber-300">Select at least one assignable role. Unavailable roles cannot be assigned.</p>}
              </fieldset>}
            </DialogBody>

          </form>
        </Dialog>
        <Dialog open={inviteOpen} title="Invite new user" maxWidth="xl" dismissOnBackdrop={!inviteBusy} onClose={() => { if (!inviteBusy) setInviteOpen(false); }}><DialogBody>
          <NativeUserInviteForm onBusyChange={setInviteBusy} onCancel={() => setInviteOpen(false)} onCreated={() => {
            setInviteOpen(false);
            setDirectoryRevision(n => n + 1);
          }} />
        </DialogBody></Dialog>
      </>}

      {/* Modals & Dialogs */}
      {rolesModalMember && (
        <ManageRolesModal
          open={rolesModalMember !== null}
          onClose={() => !actionLoading && setRolesModalMember(null)}
          displayName={rolesModalMember.display_name || rolesModalMember.email || `User #${rolesModalMember.user_id}`}
          tenantName={tenantName}
          assignableRoles={(roles.data?.roles ?? []).map(role => getRoleCode(role)).filter((code): code is string => Boolean(code))}
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

    </div>
  );
}

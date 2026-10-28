'use client';

import { useId, useRef, useState } from 'react';
import { ShieldCheck, UserMinus, UserX } from 'lucide-react';
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query';
import { useAuth } from '@/hooks/useAuth';
import { usePermissions } from '@/hooks/usePermission';
import { useMutationScope } from '@/hooks/useMutationScope';
import { useNotifications } from '@/hooks/useNotifications';
import {
  ApiError, getPlatformTenantAdministrators, revokePlatformTenantAdministrator,
  deactivatePlatformTenantAdministrator, removePlatformTenantAdministrator,
  type TenantAdministratorMembership,
} from '@/lib/api';
import { getApiErrorMessage, normalizeNotificationMessage } from '@/lib/notifications';
import { getRoleLabel } from '@/lib/roles';
import { invalidatePlatformTenantSurfaces, invalidateTenantMembershipSurfaces } from '@/lib/queryInvalidation';
import { Button } from '@/components/ui/Button';
import { Dialog, DialogBody, DialogFooter } from '@/components/ui/Dialog';

type Operation = 'revoke' | 'deactivate' | 'remove';
const labels: Record<Operation, string> = {
  revoke: 'Revoke Admin Role', deactivate: 'Deactivate Membership', remove: 'Remove From Tenant',
};
const descriptions: Record<Operation, string> = {
  revoke: 'Tenant Administrator privileges will be revoked. Other assigned tenant roles and the current membership status are retained. When the administrator role is primary, explicitly select an ordinary replacement primary role.',
  deactivate: 'Deactivating this membership prevents the administrator from accessing this tenant. Their global account and other tenant memberships remain unchanged. Assigned tenant roles are preserved.',
  remove: "Removing this membership removes the user's association with this tenant. Their global account and memberships in other tenants are not deleted.",
};

function governanceError(error: unknown): string {
  if (error instanceof ApiError) {
    if (error.status === 404) return 'This tenant or administrator membership is no longer available. Refresh the administrator list.';
    if (error.status === 409 && /VERSION_CONFLICT/.test(error.code ?? '')) {
      return 'Administrator information has changed. Review the refreshed state before submitting a new request.';
    }
    if (error.status === 409 && /LAST_.*ADMIN/.test(error.code ?? '')) {
      return 'This change is blocked because the tenant must retain an effective Tenant Administrator.';
    }
    if (error.status === 422) {
      const fields = Object.values(error.fieldErrors ?? {}).flat().join(' ');
      return normalizeNotificationMessage(fields || error.message, 'Review the selected replacement role and reason.');
    }
  }
  return getApiErrorMessage(error, 'The administrator change could not be completed.');
}

export function TenantAdministratorGovernance({ tenantId, tenantName }: { tenantId: string; tenantName: string }) {
  const auth = useAuth();
  const { can } = usePermissions();
  if (!auth.isPlatformContext || !can('platform:tenant_admin:manage')) return null;
  // Drop open confirmations and tenant data when either identity or scope changes.
  return <GovernanceContent key={`${tenantId}:${auth.user?.userId}`} tenantId={tenantId} tenantName={tenantName} />;
}

function GovernanceContent({ tenantId, tenantName }: { tenantId: string; tenantName: string }) {
  const { user, refreshSession } = useAuth();
  const scope = useMutationScope();
  const qc = useQueryClient();
  const { showSuccess, showError } = useNotifications();
  const formId = useId();
  const inFlight = useRef(false);
  const [selection, setSelection] = useState<{ admin: TenantAdministratorMembership; operation: Operation } | null>(null);
  const [replacement, setReplacement] = useState('');
  const [reason, setReason] = useState('');
  const [error, setError] = useState<string | null>(null);
  const [mustReview, setMustReview] = useState(false);
  const [forbidden, setForbidden] = useState(false);
  const directory = useQuery({
    queryKey: ['platform-tenant-administrators', tenantId, user?.userId],
    queryFn: ({ signal }) => getPlatformTenantAdministrators(tenantId, signal),
    retry: false,
    staleTime: 0,
  });
  const mutation = useMutation({
    retry: false,
    mutationFn: async (action: { admin: TenantAdministratorMembership; operation: Operation; replacement: string; reason: string; current: () => boolean }) => {
      if (!action.current()) throw new Error('The administration context has changed.');
      const { admin, operation } = action;
      const note = action.reason.trim() || undefined;
      if (operation === 'revoke') return revokePlatformTenantAdministrator(tenantId, admin.membership_id, {
        expected_version: admin.role_assignment_version,
        ...(action.replacement ? { replacement_primary_role_code: action.replacement } : {}),
        ...(note ? { reason: note } : {}),
      });
      if (operation === 'deactivate') return deactivatePlatformTenantAdministrator(tenantId, admin.membership_id, note);
      return removePlatformTenantAdministrator(tenantId, admin.membership_id, note);
    },
    onSuccess: async (_, action) => {
      if (action.current()) {
        setSelection(null);
        showSuccess(action.operation === 'revoke' ? 'Tenant Administrator role revoked.'
          : action.operation === 'deactivate' ? 'Tenant membership is now disabled. Assigned roles are preserved.' : 'Membership removed from this tenant.');
      }
      await Promise.all([invalidatePlatformTenantSurfaces(qc, tenantId), invalidateTenantMembershipSurfaces(qc, tenantId)]);
      if (action.current() && action.admin.user_id === user?.userId) {
        try { await refreshSession({ authorizationChanged: true }); }
        catch { showError('The change succeeded. Refresh your session to reload your access information.'); }
      }
    },
    onError: async (failure, action) => {
      if (!action.current()) return;
      setError(governanceError(failure));
      if (failure instanceof ApiError) {
        if ([401, 403].includes(failure.status)) setForbidden(true);
        if ([404, 409].includes(failure.status)) {
          setMustReview(true);
          await invalidatePlatformTenantSurfaces(qc, tenantId);
        }
      }
    },
    onSettled: () => { inFlight.current = false; },
  });
  const selected = selection?.admin;
  const current = directory.data?.administrators.find(admin => admin.membership_id === selected?.membership_id);
  const changed = !!selected && !!directory.data && (!current || current.role_assignment_version !== selected.role_assignment_version
    || current.status !== selected.status || current.primary_role !== selected.primary_role
    || current.is_effective !== selected.is_effective || current.roles.join() !== selected.roles.join());
  const reviewRequired = mustReview || changed;
  const needsReplacement = selection?.operation === 'revoke' && selected?.primary_role === 'TENANT_ADMIN';
  const replacementRoles = (directory.data?.replacement_roles ?? []).filter(role =>
    role.scope === 'TENANT' && !['TENANT_ADMIN', 'PLATFORM_ADMIN'].includes(role.code));
  const validReplacement = replacementRoles.some(role => role.code === replacement);
  const close = () => { if (!inFlight.current) setSelection(null); };
  const choose = (admin: TenantAdministratorMembership, operation: Operation) => {
    if (inFlight.current) return;
    setSelection({ admin, operation }); setReplacement(''); setReason(''); setError(null); setMustReview(false); setForbidden(false);
  };

  return <section aria-labelledby={`${formId}-heading`} className="rounded-xl border border-border bg-surface p-4 sm:p-6 space-y-4">
    <div className="flex flex-wrap items-start justify-between gap-3">
      <div className="space-y-1">
        <h2 id={`${formId}-heading`} className="text-lg font-semibold flex items-center gap-2"><ShieldCheck aria-hidden="true" className="h-5 w-5 text-hcl-blue" />Tenant Administrators</h2>
        <p className="text-sm text-hcl-muted max-w-3xl">Govern administrator authority for {tenantName}. These controls do not grant access to tenant business data or ordinary user management.</p>
      </div>
      <Button variant="secondary" size="sm" disabled={directory.isFetching || mutation.isPending} onClick={() => void directory.refetch()}>Refresh administrators</Button>
    </div>
    {directory.isPending && <p role="status">Loading administrator memberships…</p>}
    {directory.isError && <div role="alert" className="text-sm text-red-700 dark:text-red-300">{governanceError(directory.error)}</div>}
    {!directory.isError && directory.data && directory.data.administrators.length === 0 && <p className="text-sm text-hcl-muted">No administrator memberships with active administrator assignments were found. Use administrator recovery to assign an eligible account.</p>}
    {!directory.isError && <ul className="space-y-3" aria-label="Administrator memberships">
      {directory.data?.administrators.map(admin => <li key={admin.membership_id} className="rounded-lg border border-border p-4 space-y-3">
        <div className="flex flex-wrap items-start justify-between gap-3">
          <div className="min-w-0">
            <h3 className="font-semibold break-words">{admin.display_name || admin.email || 'Tenant Administrator'}</h3>
            {admin.email && <p className="text-sm text-hcl-muted break-all">{admin.email}</p>}
          </div>
          <span className={`rounded-full px-2.5 py-1 text-xs font-medium ${admin.is_effective ? 'bg-emerald-50 text-emerald-800 dark:bg-emerald-950 dark:text-emerald-200' : 'bg-amber-50 text-amber-900 dark:bg-amber-950 dark:text-amber-200'}`}>
            {admin.is_effective ? 'Effective administrator' : 'Administrator assignment preserved · not effective'}
          </span>
        </div>
        <dl className="grid gap-2 text-sm sm:grid-cols-3">
          <div><dt className="text-hcl-muted">Membership</dt><dd>{admin.status}</dd></div>
          <div><dt className="text-hcl-muted">Primary role</dt><dd>{getRoleLabel(admin.primary_role)}</dd></div>
          <div><dt className="text-hcl-muted">Other assigned roles</dt><dd>{admin.roles.filter(role => role !== admin.primary_role).map(getRoleLabel).join(', ') || 'None'}</dd></div>
        </dl>
        {!admin.is_effective && <p className="text-xs text-hcl-muted">This membership does not currently provide effective administrator access. Account status: {admin.account_status}.</p>}
        <div className="flex flex-wrap gap-2" role="group" aria-label={`Actions for ${admin.display_name || admin.email || 'administrator'}`}>
          <Button variant="secondary" size="sm" disabled={forbidden || mutation.isPending || directory.isFetching} onClick={() => choose(admin, 'revoke')}>Revoke Admin Role</Button>
          {admin.status === 'ACTIVE' && <Button variant="secondary" size="sm" disabled={forbidden || mutation.isPending || directory.isFetching} onClick={() => choose(admin, 'deactivate')}><UserX className="h-3.5 w-3.5" aria-hidden="true" />Deactivate Membership</Button>}
          <Button variant="ghost" size="sm" className="text-red-700 dark:text-red-300" disabled={forbidden || mutation.isPending || directory.isFetching} onClick={() => choose(admin, 'remove')}><UserMinus className="h-3.5 w-3.5" aria-hidden="true" />Remove From Tenant</Button>
        </div>
      </li>)}
    </ul>}
    {selection && <Dialog open onClose={close} title={labels[selection.operation]} maxWidth="lg" dismissOnBackdrop={!mutation.isPending} describedBy={`${formId}-description`}>
      <DialogBody className="space-y-4">
        <p className="text-sm"><strong>{selected?.display_name || selected?.email || 'Tenant Administrator'}</strong> · {tenantName}</p>
        <p id={`${formId}-description`} className="text-sm text-hcl-muted">{descriptions[selection.operation]}</p>
        <dl className="text-sm space-y-1">
          <div><dt className="inline text-hcl-muted">Membership status: </dt><dd className="inline">{selected?.status}</dd></div>
          <div><dt className="inline text-hcl-muted">Primary role: </dt><dd className="inline">{getRoleLabel(selected?.primary_role)}</dd></div>
          <div><dt className="inline text-hcl-muted">Other assigned roles: </dt><dd className="inline">{selected?.roles.filter(role => role !== selected.primary_role).map(getRoleLabel).join(', ') || 'None'}</dd></div>
          {selection.operation === 'remove' && <div><dt className="text-hcl-muted">Membership ID</dt><dd className="break-all font-mono text-xs">{selected?.membership_id}</dd></div>}
        </dl>
        {error && <p role="alert" className="text-sm text-red-700 dark:text-red-300">{error}</p>}
        {reviewRequired && <div className="rounded-lg border border-amber-300 bg-amber-50 p-3 text-sm text-amber-900 dark:border-amber-800 dark:bg-amber-950 dark:text-amber-100">
          <p>Administrator information changed. Review the current state before making another change.</p>
          {directory.isError ? <p>The current state could not be loaded. Close this dialog and refresh the list.</p>
            : directory.isFetching ? <p role="status">Refreshing administrator information…</p>
              : !current ? <p>This membership no longer has a discoverable administrator assignment.</p>
                : <><p className="mt-2">Current membership: {current.status} · Primary: {getRoleLabel(current.primary_role)} · Version: {current.role_assignment_version}</p>
                  <Button variant="secondary" size="sm" className="mt-2" onClick={() => { setSelection({ ...selection, admin: current }); setReplacement(''); setMustReview(false); setError(null); }}>Review updated administrator</Button></>}
        </div>}
        {needsReplacement && <div className="space-y-2">
          <label className="block text-sm font-medium" htmlFor={`${formId}-role`}>Replacement primary role (required)</label>
          <select id={`${formId}-role`} value={replacement} onChange={event => setReplacement(event.target.value)} disabled={mutation.isPending || reviewRequired} required className="w-full rounded-lg border border-border bg-surface p-2 text-sm focus-visible:outline-hcl-blue">
            <option value="">Select an ordinary tenant role</option>
            {replacementRoles.map(role => <option key={role.code} value={role.code}>{role.name}{selected?.roles.includes(role.code) ? ' (already assigned)' : ''}</option>)}
          </select>
          {replacementRoles.length === 0 && <p className="text-sm text-amber-700 dark:text-amber-300">No assignable ordinary tenant roles are available. Ask an authorization catalogue administrator to review the catalogue.</p>}
        </div>}
        <div className="space-y-2">
          <label htmlFor={`${formId}-reason`} className="block text-sm font-medium">Administrative reason (optional)</label>
          <textarea id={`${formId}-reason`} value={reason} onChange={event => setReason(event.target.value)} maxLength={512} rows={3} disabled={mutation.isPending} className="w-full resize-y rounded-lg border border-border bg-surface p-2 text-sm focus-visible:outline-hcl-blue" />
          <p className="text-xs text-hcl-muted">Recorded in the authorization audit. Do not include credentials or secrets.</p>
        </div>
      </DialogBody>
      <DialogFooter>
        <Button variant="secondary" onClick={close} disabled={mutation.isPending}>Cancel</Button>
        <Button variant="danger" loading={mutation.isPending} disabled={reviewRequired || forbidden || directory.isFetching || directory.isError || (needsReplacement && !validReplacement)} onClick={() => {
          if (inFlight.current || reviewRequired || forbidden || directory.isFetching || directory.isError || (needsReplacement && !validReplacement)) return;
          inFlight.current = true;
          mutation.mutate({ ...selection, replacement, reason, current: scope.capture() });
        }}>{labels[selection.operation]}</Button>
      </DialogFooter>
    </Dialog>}
  </section>;
}

'use client';

import { use, useState } from 'react';
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query';
import { usePermissions } from '@/hooks/usePermission';
import { useAuth } from '@/hooks/useAuth';
import { getPlatformTenant, recoverPlatformTenantAdmin, updatePlatformTenantStatus, type UserSearchResult } from '@/lib/api';
import { PlatformTenantOverview } from '@/components/admin/PlatformTenantOverview';
import { Breadcrumb } from '@/components/layout/Breadcrumb';
import { UserSearchCombobox } from '@/components/admin/UserSearchCombobox';
import { ConfirmationDialog } from '@/components/ui/ConfirmationDialog';
import { getApiErrorMessage } from '@/lib/notifications';
import { useNotifications } from '@/hooks/useNotifications';

export default function PlatformTenantDetailPage({ params }: { params: Promise<{ tenantId: string }> }) {
  const { tenantId } = use(params);
  const id = Number(tenantId);
  const valid = /^\d+$/.test(tenantId) && Number.isSafeInteger(id) && id > 0;
  const {  isLoading } = useAuth();
  const { can: hasPermission } = usePermissions();
  const canRead = hasPermission('platform:tenant:read');
  const canStatus = hasPermission('platform:tenant:update_status');
  const canRecover = hasPermission('platform:tenant:recover_admin');
  const qc = useQueryClient();
  const { showSuccess, showError } = useNotifications();
  const [candidate, setCandidate] = useState<UserSearchResult | null>(null);
  const [confirm, setConfirm] = useState(false);
  const tenant = useQuery({ queryKey: ['platform-tenant', id], queryFn: () => getPlatformTenant(id), enabled: !isLoading && canRead && valid, retry: false });
  const invalidateTenantSummary = async () => {
    await qc.invalidateQueries({ queryKey: ['platform-tenant', id] });
    await qc.invalidateQueries({ queryKey: ['platform-tenants'] });
    await qc.invalidateQueries({ queryKey: ['platform-summary'] });
  };
  const recovery = useMutation({
    mutationFn: () => recoverPlatformTenantAdmin(id, candidate!.id),
    onSuccess: async () => { setCandidate(null); showSuccess('Tenant Administrator recovery completed.'); await invalidateTenantSummary(); },
    onError: error => showError(getApiErrorMessage(error, 'Administrator recovery failed.')),
  });
  const status = useMutation({
    mutationFn: () => updatePlatformTenantStatus(id, tenant.data?.status === 'ACTIVE' ? 'DISABLED' : 'ACTIVE'),
    onSuccess: async () => { setConfirm(false); await invalidateTenantSummary(); },
    onError: error => showError(getApiErrorMessage(error, 'Tenant status could not be updated.')),
  });
  if (!valid) return <p role="alert">Invalid tenant.</p>;
  if (isLoading) return <p>Verifying platform access…</p>;
  if (!canRead) return <p role="alert">Platform tenant read permission is required.</p>;
  if (tenant.isLoading) return <p>Loading tenant summary…</p>;
  if (tenant.error || !tenant.data) return <p role="alert">Unable to load tenant summary.</p>;
  const value = tenant.data;
  return <main className="mx-auto max-w-6xl space-y-6 p-6">
    <Breadcrumb items={[
      { label: 'Platform', href: '/platform' },
      { label: 'Tenants', href: '/settings/platform/tenants' },
      { label: value.name },
    ]} />
    <PlatformTenantOverview tenant={value} canManageUsers={false} canResend={hasPermission('platform:tenant:bootstrap_admin')} />
    <section className="rounded-xl border p-5">
      <h2 className="text-lg font-semibold">Tenant Administrator governance</h2>
      <p>{value.member_count ?? 0} memberships · {value.current_administrators?.length ?? 0} active Tenant Administrators</p>
      <ul>{value.current_administrators?.map(admin => <li key={admin.user_id}>{admin.display_name} — {admin.email}</li>)}</ul>
      {canRecover && value.status !== 'DISABLED' && <div className="mt-4 space-y-3">
        <h3 className="font-medium">Recover Tenant Administrator access</h3>
        <p className="text-sm text-hcl-muted">Add a new active administrator. This does not grant you tenant access or provide a generic tenant-user editor.</p>
        <UserSearchCombobox governance requireEligible selectedUser={candidate} onSelect={setCandidate} placeholder="Search administrator by name or email…" />
        <button disabled={!candidate || recovery.isPending} onClick={() => recovery.mutate()} className="rounded bg-hcl-blue px-4 py-2 text-white disabled:opacity-50">{recovery.isPending ? 'Recovering…' : 'Assign Tenant Administrator'}</button>
      </div>}
    </section>
    {canStatus && <button onClick={() => setConfirm(true)}>{value.status === 'ACTIVE' ? 'Disable tenant' : 'Enable tenant'}</button>}
    <ConfirmationDialog open={confirm} onClose={() => setConfirm(false)} onConfirm={() => status.mutate()} title="Change tenant status?" description="This changes tenant availability, not global accounts." confirmLabel="Confirm" loading={status.isPending} />
  </main>;
}

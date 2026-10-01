'use client';

import { useAuth } from '@/hooks/useAuth';
import TenantUsersAccess from '@/components/admin/TenantUsersAccess';

export default function UsersAccessPage() {
  const { user, activeTenantId, isLoading } = useAuth();
  if (isLoading) return <p className="p-8">Verifying access…</p>;
  return <main className="mx-auto max-w-[1600px] space-y-5 p-4 sm:p-6">
    <header><h1 className="text-3xl font-semibold">Users & Access</h1><p className="mt-1 text-sm text-hcl-muted">Manage tenant membership, roles and access for the selected tenant.</p></header>
    <TenantUsersAccess key={activeTenantId ?? user?.tenantId ?? 'no-tenant'} />
  </main>;
}

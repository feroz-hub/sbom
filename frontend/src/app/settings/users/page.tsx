'use client';

import { useState } from 'react';
import { useAuth } from '@/hooks/useAuth';
import UserLifecycle from '@/components/admin/UserLifecycle';
import TenantUsersAccess from '@/components/admin/TenantUsersAccess';
import NativeUserInviteForm from '@/components/admin/NativeUserInviteForm';
import { Dialog, DialogBody } from '@/components/ui/Dialog';

export default function UsersAccessPage() {
  const { user, activeTenantId, hasPermission, isLoading } = useAuth();
  const isPlatformUserAdmin = Boolean(user?.isPlatformAdmin && hasPermission('platform:user:read'));
  const canInvite = isPlatformUserAdmin && hasPermission('platform:user:manage_status');
  const [open, setOpen] = useState(false);
  const [busy, setBusy] = useState(false);
  const [revision, setRevision] = useState(0);
  if (isLoading) return <p className="p-8">Verifying access…</p>;
  return <main className="mx-auto max-w-[1600px] space-y-5 p-4 sm:p-6">
    <header><h1 className="text-3xl font-semibold">Users & Access</h1><p className="mt-1 text-sm text-hcl-muted">Manage user accounts, tenant membership, roles and access.</p></header>
    {isPlatformUserAdmin ? <>
      <p className="text-sm font-medium">Platform / global context</p>
      <UserLifecycle refreshKey={revision} onAdd={canInvite ? () => setOpen(true) : undefined} />
      {canInvite && <Dialog open={open} title="Invite native user" maxWidth="xl" dismissOnBackdrop={!busy} onClose={() => { if (!busy) setOpen(false); }}><DialogBody>
        <NativeUserInviteForm onBusyChange={setBusy} onCancel={() => setOpen(false)} onCreated={() => { setRevision(n => n + 1); setOpen(false); }} />
      </DialogBody></Dialog>}
    </> : <TenantUsersAccess key={activeTenantId ?? user?.tenantId ?? 'no-tenant'} />}
  </main>;
}

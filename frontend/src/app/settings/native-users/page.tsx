'use client';
import { useState } from 'react';
import NativeUserInviteForm from '@/components/admin/NativeUserInviteForm';
import UserLifecycle from '@/components/admin/UserLifecycle';
import { Dialog, DialogBody } from '@/components/ui/Dialog';
import { useAuth } from '@/hooks/useAuth';

export default function NativeUsersPage() {
  const { hasPermission } = useAuth();
  const canInvite = hasPermission('platform:user:manage_status') || hasPermission('tenant:user:invite');
  const [open, setOpen] = useState(false);
  const [revision, setRevision] = useState(0);
  const [busy, setBusy] = useState(false);
  return <main className="mx-auto max-w-[1600px] space-y-8 p-4 sm:p-8"><UserLifecycle refreshKey={revision} onAdd={canInvite ? () => setOpen(true) : undefined} />{canInvite && <Dialog open={open} title="Add native user" maxWidth="xl" dismissOnBackdrop={!busy} onClose={() => { if (!busy) setOpen(false); }}><DialogBody><NativeUserInviteForm onBusyChange={setBusy} onCancel={() => setOpen(false)} onCreated={() => { setRevision(n => n + 1); setOpen(false); }} /></DialogBody></Dialog>}</main>;
}

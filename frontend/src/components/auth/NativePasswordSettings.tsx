'use client';
import Link from 'next/link';
import { ConfirmationDialog } from '@/components/ui/ConfirmationDialog';
import { useEffect, useState } from 'react';
export function NativePasswordSettings() {
  const [confirm, setConfirm] = useState(false);
  const [native, setNative] = useState(false);
  const [error, setError] = useState('');
  useEffect(() => { void fetch('/api/auth/session').then(r => r.json()).then(s => setNative(s.authenticated && s.provider === 'NATIVE')).catch(() => setNative(false)); }, []);
  async function logoutAll() {
    try {
      const response = await fetch('/api/auth/native/logout-all', { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: '{}' });
      if (!response.ok) throw new Error();
      window.location.assign('/native-sign-in');
    } catch { setError('Unable to sign out all sessions. Please try again.'); }
  }
  if (!native) return null;
  return <section className="rounded border p-4 space-y-3"><Link className="underline" href="/change-password">Change password</Link><button className="block" onClick={() => setConfirm(true)}>Sign out all native sessions</button><p>Native sessions expire after 15 minutes by default. Sign in again when your session expires.</p><p role="status">{error}</p><ConfirmationDialog open={confirm} title="Sign out all native sessions?" description="This signs you out on all devices and across all tenant memberships." confirmLabel="Sign out all" onClose={() => setConfirm(false)} onConfirm={() => { setConfirm(false); void logoutAll(); }} /></section>;
}

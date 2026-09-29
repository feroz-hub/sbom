'use client';
import { NativeAuthLayout } from './NativeAuthLayout';
import { PasswordField } from './PasswordField';
import { Input } from '@/components/ui/Input';
import { Button } from '@/components/ui/Button';
import Link from 'next/link';
import { FormEvent, useEffect, useState } from 'react';

export function PasswordLifecycleForm({ mode }: { mode: 'forgot' | 'reset' | 'change' }) {
  const [forced, setForced] = useState(false);
  const [native, setNative] = useState(false);
  const [message, setMessage] = useState('');
  const [busy, setBusy] = useState(false);
  useEffect(() => {
    setForced(new URLSearchParams(window.location.search).get('forced') === '1');
    if (mode === 'change') void fetch('/api/auth/session').then(r => r.json()).then(s => setNative(s.authenticated && s.provider === 'NATIVE')).catch(() => setNative(false));
  }, [mode]);
  async function submit(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    if (busy) return;
    const element = event.currentTarget;
    const data = new FormData(element);
    if (mode !== 'forgot' && data.get('new_password') !== data.get('confirm')) { setMessage('Passwords must match.'); return; }
    const action = mode === 'change' ? (forced ? 'force-change-password' : 'change-password') : `${mode}-password`;
    const body = mode === 'forgot' ? { email: data.get('email') } : mode === 'reset' ? { token: new URLSearchParams(window.location.hash.slice(1)).get('token'), new_password: data.get('new_password') } : { ...(forced ? { email: data.get('email') } : {}), current_password: data.get('current_password'), new_password: data.get('new_password') };
    setBusy(true); setMessage('');
    try {
      const response = await fetch(`/api/auth/native/${action}`, { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(body) });
      if (!response.ok) { setMessage('Unable to complete the request. Check the credential, link, and password requirements, or try again later.'); return; }
      element.reset();
      if (mode === 'forgot') setMessage('If an eligible account exists, password reset instructions will be sent.');
      else { window.history.replaceState(null, '', window.location.pathname); setMessage('Password updated. All previous native sessions are revoked. Sign in again.'); }
    } catch { setMessage('Authentication service unavailable. Please try again.'); }
    finally { setBusy(false); }
  }
  if (mode === 'change' && !forced && !native) return <main className="p-8"><p>Native sign-in is required to change your password.</p><Link href="/native-sign-in">Native sign in</Link></main>;
  return <NativeAuthLayout><div className="space-y-6"><h1 className="text-2xl">{mode === 'forgot' ? 'Forgot password' : mode === 'reset' ? 'Reset password' : 'Change password'}</h1>
    <p>{forced ? 'Your account requires a new password before application access can resume.' : 'Native SBOM Analyser accounts only.'}</p>
    <form onSubmit={submit} className="space-y-4">
      {(mode === 'forgot' || forced) && <Input label="Email" className="h-12" name="email" type="email" autoComplete="username" required />}
      {mode === 'change' && <PasswordField label="Current password" name="current_password" type="password" autoComplete="current-password" required />}
      {mode !== 'forgot' && <><p>Use at least 12 characters, or your deployment’s higher minimum. Choose a password different from your current password.</p><PasswordField label="New password" name="new_password" type="password" autoComplete="new-password" minLength={12} required /><PasswordField label="Confirm new password" name="confirm" type="password" autoComplete="new-password" required /></>}
      <Button type="submit" className="h-12 w-full" loading={busy}>{busy ? 'Please wait…' : mode === 'forgot' ? 'Send reset instructions' : 'Update password'}</Button>
    </form><p role="status">{message}</p><Link className="underline" href="/native-sign-in">Native sign in</Link>
  </div></NativeAuthLayout>;
}

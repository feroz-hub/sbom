'use client';
import Link from 'next/link';
import { FormEvent, useState } from 'react';

export function NativeAuthForm({ activation = false }: { activation?: boolean }) {
  const [message, setMessage] = useState('');
  const [busy, setBusy] = useState(false);
  async function submit(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    const form = new FormData(event.currentTarget);
    const password = String(form.get('password'));
    if (activation && password !== form.get('confirm')) { setMessage('Passwords must match.'); return; }
    setBusy(true);
    try {
      const token = new URLSearchParams(window.location.hash.slice(1)).get('token');
      const response = await fetch(`/api/auth/native/${activation ? 'activate' : 'login'}`, {
        method: 'POST', headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(activation ? { token, password } : { email: form.get('email'), password }),
      });
      const data = await response.json();
      if (!response.ok) { setMessage(data.detail); return; }
      if (activation) {
        window.history.replaceState(null, '', window.location.pathname);
        setMessage('Account activated. You can now sign in.');
      } else window.location.assign('/');
    } catch { setMessage('Unable to reach the authentication service.'); }
    finally { setBusy(false); }
  }
  return <main className="mx-auto max-w-md p-8 space-y-6">
    <h1 className="text-2xl font-semibold">{activation ? 'Activate account' : 'Native sign in'}</h1>
    <p>{activation ? 'Set a password of at least 12 characters. Your invitation is valid for five hours.' : 'Sign in with your SBOM Analyser account.'}</p>
    <form onSubmit={submit} className="space-y-4">
      {!activation && <label className="block">Email<input className="block w-full rounded border p-2 text-foreground bg-background" name="email" type="email" autoComplete="username" required /></label>}
      <label className="block">Password<input className="block w-full rounded border p-2 text-foreground bg-background" name="password" type="password" autoComplete={activation ? 'new-password' : 'current-password'} minLength={activation ? 12 : 1} required /></label>
      {activation && <label className="block">Confirm password<input className="block w-full rounded border p-2 text-foreground bg-background" name="confirm" type="password" autoComplete="new-password" required /></label>}
      <button className="rounded bg-hcl-blue text-white px-4 py-2" disabled={busy}>{busy ? 'Please wait…' : activation ? 'Activate account' : 'Sign in'}</button>
    </form>
    <p role="status">{message}</p>
    <Link className="underline" href={activation ? '/native-sign-in' : '/api/auth/login'}>{activation ? 'Native sign in' : 'Sign in with HCL.CS'}</Link>
  </main>;
}

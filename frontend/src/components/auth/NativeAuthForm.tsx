'use client';
import Link from 'next/link';
import { useRouter } from 'next/navigation';
import { FormEvent, useState } from 'react';
import { Mail } from 'lucide-react';
import { Input } from '@/components/ui/Input';
import { Button } from '@/components/ui/Button';
import { NativeAuthLayout } from './NativeAuthLayout';
import { PasswordField } from './PasswordField';
import { MicrosoftSignIn } from './MicrosoftSignIn';

export function NativeAuthForm({ activation = false, initialEmail = '', activated = false }: { activation?: boolean; initialEmail?: string; activated?: boolean }) {
  const router = useRouter();
  const [message, setMessage] = useState(activated ? 'Account activated. Sign in with your new password.' : '');
  const [busy, setBusy] = useState(false);
  async function submit(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    if (busy) return;
    setMessage('');
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
      if (!response.ok) { setMessage(activation ? 'Unable to activate account. Check your invitation link and password requirements.' : response.status === 401 ? 'The email address or password you entered is incorrect.' : 'Unable to sign in. Please try again later or contact your administrator.'); return; }
      if (activation) {
        window.history.replaceState(null, '', window.location.pathname);
        router.replace(`/native-sign-in?${new URLSearchParams({ email: data.email, activated: '1' })}`);
      } else window.location.assign(data.password_change_required ? '/change-password?forced=1' : '/');
    } catch { setMessage('Unable to reach the authentication service.'); }
    finally { setBusy(false); }
  }
  return <NativeAuthLayout>
    <p className="text-xs font-semibold tracking-[0.2em] text-hcl-muted">SBOM ANALYZER</p>
    <span className="mt-8 inline-flex rounded-full border border-border bg-surface-muted px-3 py-1 text-xs font-semibold tracking-widest text-hcl-muted">NATIVE ACCOUNT</span>
    <h1 className="mt-4 text-3xl font-semibold tracking-tight">{activation ? 'Activate account' : 'Welcome back'}</h1>
    <p className="mb-8 mt-3 text-sm leading-6 text-hcl-muted">{activation ? 'Set a password of at least 12 characters. Your invitation is valid for five hours.' : 'Sign in to continue to your secure SBOM workspace.'}</p>
    <form onSubmit={submit} className="space-y-5" aria-busy={busy}>
      {!activation && <div className="relative"><Input label="Email address" className="h-12 pl-10" name="email" type="email" defaultValue={initialEmail} placeholder="Enter your email address" autoComplete="username" required /><Mail aria-hidden="true" className="pointer-events-none absolute bottom-4 left-3 h-4 w-4 text-hcl-muted" /></div>}
      <div className="relative">{!activation && <Link className="absolute right-0 top-0 text-xs font-medium text-link hover:underline" href="/forgot-password">Forgot password?</Link>}<PasswordField label="Password" name="password" placeholder="Enter your password" autoComplete={activation ? 'new-password' : 'current-password'} minLength={activation ? 12 : 1} required /></div>
      {activation && <PasswordField label="Confirm password" name="confirm" autoComplete="new-password" required />}
      {message && <div role="status" className="rounded-lg border border-border bg-surface-muted p-4 text-sm leading-6">{message}</div>}
      <Button type="submit" className="h-12 w-full" loading={busy}>{busy ? (activation ? 'Activating…' : 'Signing in…') : activation ? 'Activate account' : 'Sign in'}</Button>
    </form>
    {!activation && process.env.NEXT_PUBLIC_HCL_AUTH_ENABLED !== 'false' && <><div className="my-6 flex items-center gap-4 text-xs text-hcl-muted"><span className="h-px flex-1 bg-border" />OR<span className="h-px flex-1 bg-border" /></div><Link className="flex min-h-12 items-center justify-center rounded-lg border border-border px-4 text-sm font-semibold text-hcl-navy hover:bg-surface-muted focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-primary" href="/api/auth/login?provider=hcl">Sign in with HCL.CS Identity</Link></>}
    {!activation && <div className="mt-4"><MicrosoftSignIn /></div>}
    {activation && <Link className="mt-6 block text-sm text-link hover:underline" href="/native-sign-in">Native sign in</Link>}
    <p className="mt-10 text-center text-xs text-hcl-muted">Software Supply Chain Security</p>
  </NativeAuthLayout>;
}

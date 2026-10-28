'use client';

import { useEffect, useState } from 'react';
import { PublicClientApplication, BrowserCacheLocation } from '@azure/msal-browser';

type Configuration = { enabled: boolean; clientId: string; authority: string; redirectUri: string; scope: string };

export function MicrosoftSignIn() {
  const [client, setClient] = useState<PublicClientApplication | null>(null);
  const [scope, setScope] = useState('');
  const [error, setError] = useState('');
  const [busy, setBusy] = useState(false);
  useEffect(() => {
    let cancelled = false;
    void (async () => {
      try {
        const response = await fetch('/api/auth/entra', { cache: 'no-store' });
        if (!response.ok) throw new Error();
        const config: Configuration = await response.json();
        if (!config.enabled) return;
        const instance = new PublicClientApplication({
          auth: { clientId: config.clientId, authority: config.authority, redirectUri: config.redirectUri },
          cache: { cacheLocation: BrowserCacheLocation.MemoryStorage },
          system: { loggerOptions: { piiLoggingEnabled: false, loggerCallback: () => {} } },
        });
        await instance.initialize();
        if (!cancelled) { setScope(config.scope); setClient(instance); }
      } catch { if (!cancelled) setError('Microsoft sign-in is currently unavailable.'); }
    })();
    return () => { cancelled = true; };
  }, []);

  async function signIn() {
    if (!client) return;
    setBusy(true); setError('');
    try {
      const result = await client.loginPopup({ scopes: [scope], prompt: 'select_account' });
      const response = await fetch('/api/auth/entra', { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ accessToken: result.accessToken }) });
      if (!response.ok) throw new Error();
      await client.clearCache();
      window.location.assign('/');
    } catch {
      await client.clearCache().catch(() => undefined);
      setError('Microsoft sign-in did not complete. Try again or contact your administrator.');
    } finally { setBusy(false); }
  }
  return <div className="space-y-3">
    {client && <button type="button" disabled={busy} onClick={() => void signIn()} className="w-full rounded-lg border border-border bg-hcl-blue px-4 py-3 font-semibold text-white focus-visible:ring-2">{busy ? 'Signing in…' : 'Sign in with Microsoft'}</button>}
    {error && <p role="alert" className="text-sm">{error}</p>}
  </div>;
}

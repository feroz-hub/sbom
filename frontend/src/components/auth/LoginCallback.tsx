'use client';

import { useEffect, useRef, useState } from 'react';
import { useRouter } from 'next/navigation';
import { useAuth } from '@/hooks/useAuth';
import { useNotifications } from '@/hooks/useNotifications';

type CallbackStatus = 'processing' | 'error';

function sanitizeReturnUrl(url?: string | null): string {
  if (!url || typeof url !== 'string') return '/';
  if (url.startsWith('/') && !url.startsWith('//') && !url.startsWith('/\\')) {
    return url;
  }
  return '/';
}

export function LoginCallback() {
  const router = useRouter();
  const { setBootstrapState, refreshSession, login, retryBootstrap } = useAuth();
  const { showError } = useNotifications();
  const [status, setStatus] = useState<CallbackStatus>('processing');
  const [errorMessage, setErrorMessage] = useState('');
  const hasExchangedRef = useRef(false);

  useEffect(() => {
    if (hasExchangedRef.current) return;
    hasExchangedRef.current = true;

    async function handleCallback() {
      try {
        setBootstrapState('processing-callback');
        const url = new URL(window.location.href);
        const code = url.searchParams.get('code');
        const state = url.searchParams.get('state');
        const error = url.searchParams.get('error');

        // Handle IdP errors
        if (error) {
          setStatus('error');
          const msg = 'Sign-in could not be completed (Identity Provider error).';
          setErrorMessage(msg);
          showError(msg);
          setBootstrapState('error', msg);
          return;
        }

        if (!code || !state) {
          setStatus('error');
          const msg = 'Sign-in could not be completed (Callback state validation failed).';
          setErrorMessage(msg);
          showError(msg);
          setBootstrapState('error', msg);
          return;
        }

        const response = await fetch('/api/auth/callback', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ code, state }),
        });

        const body = await response.json().catch(() => null);

        if (!response.ok) {
          const detail = body?.detail || body?.error || 'Token exchange failed.';
          setStatus('error');
          setErrorMessage(detail);
          showError(detail);
          setBootstrapState('error', detail);
          return;
        }

        // Clean query parameters from address bar immediately after successful exchange
        if (typeof window !== 'undefined' && window.history?.replaceState) {
          window.history.replaceState({}, document.title, window.location.pathname);
        }

        const returnUrl = sanitizeReturnUrl(body?.returnTo);

        // Load authoritative auth context & resolve active tenant
        await refreshSession();

        // Navigate once using router.replace
        router.replace(returnUrl);
      } catch (err: unknown) {
        setStatus('error');
        const msg = err instanceof Error ? err.message : 'Sign-in session creation failed.';
        setErrorMessage(msg);
        showError(msg);
        setBootstrapState('error', msg);
      }
    }

    void handleCallback();
  }, [login, refreshSession, router, setBootstrapState, showError]);

  if (status === 'error') {
    return (
      <div className="flex min-h-screen items-center justify-center bg-background px-4">
        <div className="w-full max-w-md rounded-2xl border border-border bg-surface p-8 shadow-elev-3 text-center space-y-5">
          <div className="mx-auto flex h-14 w-14 items-center justify-center rounded-full bg-red-100 dark:bg-red-950/30 text-red-600">
            <svg className="h-7 w-7" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={2}>
              <path strokeLinecap="round" strokeLinejoin="round" d="M6 18L18 6M6 6l12 12" />
            </svg>
          </div>
          <div className="space-y-2">
            <h2 className="text-lg font-bold text-foreground">Authentication Failed</h2>
            <p className="text-sm text-hcl-muted">{errorMessage}</p>
          </div>
          <div className="flex flex-col gap-3 pt-2">
            <button
              type="button"
              onClick={() => retryBootstrap()}
              className="w-full rounded-lg bg-hcl-blue py-2.5 text-sm font-semibold text-white hover:bg-hcl-blue/90 transition-colors shadow-elev-1"
            >
              Retry Status
            </button>
            <button
              type="button"
              onClick={() => login()}
              className="w-full rounded-lg border border-border bg-transparent py-2.5 text-sm font-medium text-foreground hover:bg-surface-elevated transition-colors"
            >
              Sign in again
            </button>
          </div>
        </div>
      </div>
    );
  }

  return (
    <div className="flex min-h-screen flex-col items-center justify-center bg-background px-4">
      <div className="flex flex-col items-center text-center space-y-4">
        <div className="flex h-12 w-12 items-center justify-center rounded-xl border border-white/20 bg-hcl-blue text-white shadow-lg">
          <span className="text-sm font-bold tracking-tight">HCL</span>
        </div>
        <div className="h-10 w-10 animate-spin rounded-full border-4 border-hcl-blue border-t-transparent" />
        <div className="space-y-1">
          <h2 className="text-base font-semibold text-foreground">SBOM Analyzer</h2>
          <p className="text-sm text-hcl-muted">Establishing your secure session…</p>
        </div>
      </div>
    </div>
  );
}

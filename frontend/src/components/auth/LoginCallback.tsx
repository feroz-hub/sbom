'use client';

/**
 * OIDC callback handler — /auth/callback page.
 *
 * After HCL IAM redirects back with an authorization code, this component:
 * The server route validates state/nonce/PKCE, exchanges the code, validates
 * the ID token, and creates an HttpOnly session. No token reaches this component.
 */

import { useEffect, useRef, useState } from 'react';

type CallbackStatus = 'processing' | 'success' | 'error';

export function LoginCallback() {
  const [status, setStatus] = useState<CallbackStatus>('processing');
  const [errorMessage, setErrorMessage] = useState('');
  const processedRef = useRef(false);

  useEffect(() => {
    if (processedRef.current) return;
    processedRef.current = true;

    async function handleCallback() {
      try {
        const url = new URL(window.location.href);
        const code = url.searchParams.get('code');
        const state = url.searchParams.get('state');
        const error = url.searchParams.get('error');

        // Handle IdP errors
        if (error) {
          setStatus('error');
          setErrorMessage('The identity provider could not complete authentication.');
          return;
        }

        if (!code) {
          setStatus('error');
          setErrorMessage('No authorization code received from the identity provider.');
          return;
        }

        if (!state) {
          setStatus('error');
          setErrorMessage('Invalid state parameter — possible CSRF attack. Please try again.');
          return;
        }

        const response = await fetch('/api/auth/callback', {
          method: 'POST', headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ code, state }),
        });
        const body = await response.json();
        if (!response.ok) throw new Error(body.error || 'Authentication could not be completed.');

        setStatus('success');

        // Redirect to return URL or home
        const returnUrl = typeof body.returnTo === 'string' ? body.returnTo : '/';

        // Small delay so the success state is visible
        setTimeout(() => {
          window.location.href = returnUrl;
        }, 300);
      } catch (err) {
        setStatus('error');
        setErrorMessage(err instanceof Error ? err.message : 'An unexpected error occurred.');
      }
    }

    handleCallback();
  }, []);

  return (
    <div className="flex min-h-screen items-center justify-center bg-background">
      <div className="w-full max-w-md rounded-xl border border-border bg-surface p-8 shadow-elev-2">
        {status === 'processing' && (
          <div className="text-center">
            <div className="mb-4 h-10 w-10 animate-spin rounded-full border-4 border-hcl-blue border-t-transparent mx-auto" />
            <h2 className="text-lg font-semibold text-foreground mb-1">Completing sign in…</h2>
            <p className="text-sm text-hcl-muted">Establishing your secure session.</p>
          </div>
        )}

        {status === 'success' && (
          <div className="text-center">
            <div className="mx-auto mb-4 flex h-12 w-12 items-center justify-center rounded-full bg-emerald-100 dark:bg-emerald-900/20">
              <svg className="h-6 w-6 text-emerald-500" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={2}>
                <path strokeLinecap="round" strokeLinejoin="round" d="M5 13l4 4L19 7" />
              </svg>
            </div>
            <h2 className="text-lg font-semibold text-foreground mb-1">Authenticated</h2>
            <p className="text-sm text-hcl-muted">Redirecting to the application…</p>
          </div>
        )}

        {status === 'error' && (
          <div className="text-center">
            <div className="mx-auto mb-4 flex h-12 w-12 items-center justify-center rounded-full bg-red-100 dark:bg-red-900/20">
              <svg className="h-6 w-6 text-red-500" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={2}>
                <path strokeLinecap="round" strokeLinejoin="round" d="M6 18L18 6M6 6l12 12" />
              </svg>
            </div>
            <h2 className="text-lg font-semibold text-foreground mb-2">Authentication Failed</h2>
            <p className="text-sm text-hcl-muted mb-4">{errorMessage}</p>
            <button
              type="button"
              onClick={() => (window.location.href = '/')}
              className="inline-flex items-center gap-2 rounded-lg bg-hcl-blue px-4 py-2 text-sm font-medium text-white hover:bg-hcl-blue/90 transition-colors"
            >
              Return to Home
            </button>
          </div>
        )}
      </div>
    </div>
  );
}

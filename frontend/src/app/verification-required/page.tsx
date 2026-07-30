'use client';

import { useEffect } from 'react';
import { useAuth } from '@/hooks/useAuth';

export default function VerificationRequiredPage() {
  const { logout, reloadAuth } = useAuth();

  useEffect(() => {
    document.title = 'Verification Required — SBOM Analyzer';
  }, []);

  return (
    <div className="flex min-h-screen items-center justify-center bg-background px-4">
      <div className="w-full max-w-md rounded-xl border border-border bg-surface p-8 shadow-elev-2 text-center">
        <div className="mx-auto mb-6 flex h-20 w-20 items-center justify-center rounded-full bg-amber-100 dark:bg-amber-900/20">
          <svg
            className="h-10 w-10 text-amber-500"
            fill="none"
            viewBox="0 0 24 24"
            stroke="currentColor"
            strokeWidth={1.5}
          >
            <path
              strokeLinecap="round"
              strokeLinejoin="round"
              d="M21.75 6.75v10.5a2.25 2.25 0 01-2.25 2.25h-15a2.25 2.25 0 01-2.25-2.25V6.75m19.5 0A2.25 2.25 0 0019.5 4.5h-15a2.25 2.25 0 00-2.25 2.25m19.5 0v.243a2.25 2.25 0 01-1.07 1.916l-7.5 4.615a2.25 2.25 0 01-2.36 0L3.32 8.91a2.25 2.25 0 01-1.07-1.916V6.75"
            />
          </svg>
        </div>

        <h1 className="text-2xl font-bold text-foreground mb-2">Email Verification Required</h1>
        <p className="text-sm text-hcl-muted mb-6">
          Your HCL.CS authentication succeeded, but your SBOM account requires email verification before application access can be granted.
        </p>

        <div className="flex flex-col gap-3 sm:flex-row sm:justify-center">
          <button
            type="button"
            onClick={() => reloadAuth()}
            className="inline-flex items-center justify-center gap-2 rounded-lg bg-hcl-blue px-4 py-2.5 text-sm font-medium text-white hover:bg-hcl-blue/90 transition-colors"
          >
            Retry Status
          </button>
          <button
            type="button"
            onClick={() => logout()}
            className="inline-flex items-center justify-center gap-2 rounded-lg border border-border bg-surface px-4 py-2.5 text-sm font-medium text-foreground hover:bg-surface-muted transition-colors"
          >
            Sign Out
          </button>
        </div>
      </div>
    </div>
  );
}

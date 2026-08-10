'use client';

import { useEffect } from 'react';
import { useAuth } from '@/hooks/useAuth';

export default function AccessDeniedPage() {
  const { activeTenant, logout, reloadAuth } = useAuth();

  const isMembershipDisabled = activeTenant?.membershipStatus === 'DISABLED';
  const title = isMembershipDisabled ? 'Tenant access disabled' : 'SBOM account disabled';
  const description = isMembershipDisabled
    ? 'Your HCL.CS sign-in is valid, but your membership in this tenant is currently disabled.'
    : 'Your HCL.CS identity is valid, but your SBOM account has been disabled.';

  useEffect(() => {
    document.title = `${title} — SBOM Analyzer`;
  }, [title]);

  return (
    <div className="flex min-h-screen items-center justify-center bg-background px-4">
      <div className="w-full max-w-md rounded-xl border border-border bg-surface p-8 shadow-elev-2 text-center">
        <div className="mx-auto mb-6 flex h-20 w-20 items-center justify-center rounded-full bg-red-100 dark:bg-red-900/20">
          <svg
            className="h-10 w-10 text-red-500"
            fill="none"
            viewBox="0 0 24 24"
            stroke="currentColor"
            strokeWidth={1.5}
          >
            <path
              strokeLinecap="round"
              strokeLinejoin="round"
              d="M12 9v3.75m-9.303 3.376c-.866 1.5.217 3.374 1.948 3.374h14.71c1.73 0 2.813-1.874 1.948-3.374L13.949 3.378c-.866-1.5-3.032-1.5-3.898 0L2.697 16.126zM12 15.75h.007v.008H12v-.008z"
            />
          </svg>
        </div>

        <h1 className="text-2xl font-bold text-foreground mb-2">{title}</h1>
        <p className="text-sm text-hcl-muted mb-6">
          {description}
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

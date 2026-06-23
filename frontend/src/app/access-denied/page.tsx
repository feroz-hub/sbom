'use client';

import { useEffect } from 'react';
import Link from 'next/link';

export default function AccessDeniedPage() {
  useEffect(() => {
    document.title = 'Access Denied — SBOM Analyzer';
  }, []);
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

        <h1 className="text-2xl font-bold text-foreground mb-2">Access Denied</h1>
        <p className="text-sm text-hcl-muted mb-6">
          You do not have the required permissions to view this page. If you believe this is an
          error, contact your administrator or switch to a tenant where you have the appropriate
          role.
        </p>

        <div className="flex flex-col gap-3 sm:flex-row sm:justify-center">
          <Link
            href="/"
            className="inline-flex items-center justify-center gap-2 rounded-lg bg-hcl-blue px-4 py-2.5 text-sm font-medium text-white hover:bg-hcl-blue/90 transition-colors"
          >
            Go to Dashboard
          </Link>
          <button
            type="button"
            onClick={() => window.history.back()}
            className="inline-flex items-center justify-center gap-2 rounded-lg border border-border bg-surface px-4 py-2.5 text-sm font-medium text-foreground hover:bg-surface-muted transition-colors"
          >
            Go Back
          </button>
        </div>
      </div>
    </div>
  );
}

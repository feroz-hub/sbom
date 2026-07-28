'use client';

import { useAuth } from '@/hooks/useAuth';
import { useRouter } from 'next/navigation';

export default function AccessPendingPage() {
  const { user, refreshSession, logout, authStatus } = useAuth();
  const router = useRouter();

  const handleRetry = async () => {
    await refreshSession();
    if (authStatus === 'authenticated') {
      router.push('/');
    }
  };

  return (
    <div className="flex min-h-screen flex-col items-center justify-center bg-background px-4 text-center">
      <div className="w-full max-w-md space-y-6 rounded-2xl border border-border bg-surface p-8 shadow-elev-3">
        <div className="mx-auto flex h-16 w-16 items-center justify-center rounded-full bg-amber-500/10 text-amber-500">
          <svg className="h-8 w-8" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={2}>
            <path strokeLinecap="round" strokeLinejoin="round" d="M12 9v3.75m9-.75a9 9 0 11-18 0 9 9 0 0118 0zm-9 3.75h.008v.008H12v-.008z" />
          </svg>
        </div>

        <div className="space-y-2">
          <h1 className="text-xl font-bold text-foreground">Access Pending</h1>
          <p className="text-sm text-hcl-muted">
            Your identity is verified, but you have not yet been assigned access to an SBOM tenant.
          </p>
          <p className="text-xs text-hcl-muted">
            Contact a Platform Administrator or Tenant Administrator to grant you membership.
          </p>
        </div>

        {user && (
          <div className="rounded-lg bg-surface-elevated p-4 text-xs space-y-1 text-left border border-border">
            <p><strong>Signed-in Email:</strong> {user.email || 'No email'}</p>
            <p><strong>User ID:</strong> {user.userId ?? 'Pending'}</p>
            <p><strong>Email Verification:</strong> Verified</p>
          </div>
        )}

        <div className="flex flex-col gap-3 pt-2">
          <button
            type="button"
            onClick={handleRetry}
            className="w-full rounded-lg bg-hcl-blue py-2.5 text-sm font-semibold text-white shadow-elev-1 hover:bg-hcl-blue/90 transition-colors"
          >
            Retry Access
          </button>
          <button
            type="button"
            onClick={() => logout()}
            className="w-full rounded-lg border border-border bg-transparent py-2.5 text-sm font-medium text-hcl-muted hover:bg-surface-elevated hover:text-foreground transition-colors"
          >
            Sign Out
          </button>
        </div>
      </div>
    </div>
  );
}

'use client';

/**
 * AuthGuard — wraps protected pages with authentication check.
 *
 * When auth is enabled and user is not authenticated, redirects to HCL IAM
 * login. Shows a loading state during token validation. When auth is disabled
 * (dev mode), renders children immediately.
 */

import { useEffect, type ReactNode } from 'react';
import { useAuth } from '@/hooks/useAuth';

interface AuthGuardProps {
  children: ReactNode;
  /** Optional minimum permission required to view this page. */
  requiredPermission?: string;
  /** Optional minimum role(s) required. */
  requiredRoles?: string[];
}

export function AuthGuard({ children, requiredPermission, requiredRoles }: AuthGuardProps) {
  const { isAuthenticated, isLoading, config, login, hasPermission, hasAnyRole } = useAuth();

  useEffect(() => {
    if (!isLoading && config.enabled && !isAuthenticated) {
      login();
    }
  }, [isLoading, config.enabled, isAuthenticated, login]);

  // Loading state
  if (isLoading) {
    return (
      <div className="flex min-h-screen items-center justify-center bg-background">
        <div className="text-center">
          <div className="mb-4 h-10 w-10 animate-spin rounded-full border-4 border-hcl-blue border-t-transparent mx-auto" />
          <p className="text-sm text-hcl-muted">Verifying authentication…</p>
        </div>
      </div>
    );
  }

  // Not authenticated (auth enabled)
  if (config.enabled && !isAuthenticated) {
    return (
      <div className="flex min-h-screen items-center justify-center bg-background">
        <div className="text-center">
          <div className="mb-4 h-10 w-10 animate-spin rounded-full border-4 border-hcl-blue border-t-transparent mx-auto" />
          <p className="text-sm text-hcl-muted">Redirecting to login…</p>
        </div>
      </div>
    );
  }

  // Permission check
  if (requiredPermission && !hasPermission(requiredPermission)) {
    return <AccessDeniedInline message={`Missing permission: ${requiredPermission}`} />;
  }

  // Role check
  if (requiredRoles && requiredRoles.length > 0 && !hasAnyRole(...requiredRoles)) {
    return <AccessDeniedInline message="You do not have the required role to access this page." />;
  }

  return <>{children}</>;
}

function AccessDeniedInline({ message }: { message: string }) {
  return (
    <div className="flex min-h-[50vh] items-center justify-center">
      <div className="rounded-xl border border-border bg-surface p-8 text-center shadow-elev-1 max-w-md">
        <div className="mx-auto mb-4 flex h-16 w-16 items-center justify-center rounded-full bg-red-100 dark:bg-red-900/20">
          <svg className="h-8 w-8 text-red-500" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={2}>
            <path strokeLinecap="round" strokeLinejoin="round" d="M18.364 18.364A9 9 0 005.636 5.636m12.728 12.728A9 9 0 015.636 5.636m12.728 12.728L5.636 5.636" />
          </svg>
        </div>
        <h2 className="text-lg font-semibold text-foreground mb-2">Access Denied</h2>
        <p className="text-sm text-hcl-muted">{message}</p>
      </div>
    </div>
  );
}

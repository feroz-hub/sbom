'use client';

/**
 * AuthGuard — wraps protected pages with authentication check.
 *
 * When auth is enabled and user is not authenticated, redirects to HCL IAM
 * login. Shows a loading state during token validation. When auth is disabled
 * (dev mode), renders children immediately.
 *
 * Switches strictly on authStatus from useAuth to prevent redirect loops.
 */

import { useEffect, type ReactNode } from 'react';
import { usePathname, useRouter } from 'next/navigation';
import { useAuth } from '@/hooks/useAuth';

const PUBLIC_PATHS = ['/auth/callback', '/access-denied', '/verification-required', '/access-pending'];

interface AuthGuardProps {
  children: ReactNode;
  /** Optional minimum permission required to view this page. */
  requiredPermission?: string;
  /** Optional minimum role(s) required. */
  requiredRoles?: string[];
}

export function AuthGuard({ children, requiredPermission, requiredRoles }: AuthGuardProps) {
  const pathname = usePathname();
  const router = useRouter();
  const { authStatus, config, login, reloadAuth, hasPermission, hasAnyRole } = useAuth();

  const isPublicPath = PUBLIC_PATHS.some((p) => pathname?.startsWith(p));

  useEffect(() => {
    if (isPublicPath) return;

    if (authStatus === 'loading') {
      return;
    }

    if (config.enabled && authStatus === 'unauthenticated') {
      login();
      return;
    }

    if (
      authStatus === 'verification-required' &&
      pathname !== '/verification-required'
    ) {
      router.replace('/verification-required');
      return;
    }

    if (
      authStatus === 'access-pending' &&
      pathname !== '/access-pending'
    ) {
      router.replace('/access-pending');
      return;
    }

    if (
      authStatus === 'access-denied' &&
      pathname !== '/access-denied'
    ) {
      router.replace('/access-denied');
      return;
    }

    if (
      authStatus === 'authenticated' &&
      (pathname === '/verification-required' || pathname === '/access-denied')
    ) {
      router.replace('/');
      return;
    }
  }, [authStatus, config.enabled, isPublicPath, login, pathname, router]);

  if (isPublicPath) {
    return <>{children}</>;
  }

  // Loading state
  if (authStatus === 'loading') {
    return (
      <div className="flex min-h-screen items-center justify-center bg-background">
        <div className="text-center">
          <div className="mb-4 h-10 w-10 animate-spin rounded-full border-4 border-hcl-blue border-t-transparent mx-auto" />
          <p className="text-sm text-hcl-muted">Verifying authentication…</p>
        </div>
      </div>
    );
  }

  // Unauthenticated (auth enabled)
  if (config.enabled && authStatus === 'unauthenticated') {
    return (
      <div className="flex min-h-screen items-center justify-center bg-background">
        <div className="text-center">
          <div className="mb-4 h-10 w-10 animate-spin rounded-full border-4 border-hcl-blue border-t-transparent mx-auto" />
          <p className="text-sm text-hcl-muted">Redirecting to login…</p>
        </div>
      </div>
    );
  }

  // Service unavailable state — show message with Retry button
  if (authStatus === 'service-unavailable') {
    return (
      <div className="flex min-h-screen items-center justify-center bg-background px-4">
        <div className="w-full max-w-md rounded-xl border border-border bg-surface p-8 shadow-elev-2 text-center">
          <div className="mx-auto mb-4 flex h-12 w-12 items-center justify-center rounded-full bg-amber-100 dark:bg-amber-900/20 text-amber-600">
            <svg className="h-6 w-6" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={2}>
              <path strokeLinecap="round" strokeLinejoin="round" d="M12 9v3.75m9-.75a9 9 0 11-18 0 9 9 0 0118 0zm-9 3.75h.008v.008H12v-.008z" />
            </svg>
          </div>
          <h2 className="text-lg font-semibold text-foreground mb-2">Service Temporarily Unavailable</h2>
          <p className="text-sm text-hcl-muted mb-6">
            Authentication service or identity validation is currently unreachable. Please try again in a few moments.
          </p>
          <button
            type="button"
            onClick={() => reloadAuth()}
            className="inline-flex items-center justify-center gap-2 rounded-lg bg-hcl-blue px-4 py-2 text-sm font-medium text-white hover:bg-hcl-blue/90 transition-colors"
          >
            Retry Status
          </button>
        </div>
      </div>
    );
  }

  // Intermediate routing state (verification-required or access-denied)
  if (authStatus === 'verification-required' || authStatus === 'access-denied') {
    return (
      <div className="flex min-h-screen items-center justify-center bg-background">
        <div className="text-center">
          <div className="mb-4 h-10 w-10 animate-spin rounded-full border-4 border-hcl-blue border-t-transparent mx-auto" />
          <p className="text-sm text-hcl-muted">Redirecting…</p>
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

'use client';

import { Suspense, useEffect } from 'react';
import { usePathname, useRouter } from 'next/navigation';
import { Sidebar } from './Sidebar';
import { SidebarProvider, useSidebar } from './SidebarContext';
import { GlobalAiBatchBanner } from '@/components/ai-fixes/GlobalAiBatchProgress';
import { useAuth } from '@/hooks/useAuth';
import { cn } from '@/lib/utils';

const PUBLIC_PATHS = ['/auth/callback', '/access-denied', '/verification-required', '/access-pending'];

function FullScreenBrandedLoader({ message = 'Verifying authentication…' }: { message?: string }) {
  return (
    <div className="flex min-h-screen flex-col items-center justify-center bg-background px-4">
      <div className="flex flex-col items-center text-center space-y-4">
        <div className="flex h-12 w-12 items-center justify-center rounded-xl border border-white/20 bg-hcl-blue text-white shadow-lg">
          <span className="text-sm font-bold tracking-tight">HCL</span>
        </div>
        <div className="h-10 w-10 animate-spin rounded-full border-4 border-hcl-blue border-t-transparent" />
        <div className="space-y-1">
          <h2 className="text-base font-semibold text-foreground">SBOM Analyzer</h2>
          <p className="text-sm text-hcl-muted">{message}</p>
        </div>
      </div>
    </div>
  );
}

function BootstrapTimeoutRecovery({ message, onRetry, onLogin }: { message: string; onRetry: () => void; onLogin: () => void }) {
  return (
    <div className="flex min-h-screen flex-col items-center justify-center bg-background px-4">
      <div className="w-full max-w-md rounded-2xl border border-border bg-surface p-8 shadow-elev-3 text-center space-y-5">
        <div className="mx-auto flex h-14 w-14 items-center justify-center rounded-full bg-amber-100 dark:bg-amber-950/30 text-amber-600">
          <svg className="h-7 w-7" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={2}>
            <path strokeLinecap="round" strokeLinejoin="round" d="M12 9v3.75m9-.75a9 9 0 11-18 0 9 9 0 0118 0zm-9 3.75h.008v.008H12v-.008z" />
          </svg>
        </div>
        <div className="space-y-2">
          <h2 className="text-lg font-bold text-foreground">Sign-in is taking longer than expected</h2>
          <p className="text-sm text-hcl-muted">{message}</p>
        </div>
        <div className="flex flex-col gap-3 pt-2">
          <button
            type="button"
            onClick={onRetry}
            className="w-full rounded-lg bg-hcl-blue py-2.5 text-sm font-semibold text-white hover:bg-hcl-blue/90 transition-colors shadow-elev-1"
          >
            Retry
          </button>
          <button
            type="button"
            onClick={onLogin}
            className="w-full rounded-lg border border-border bg-transparent py-2.5 text-sm font-medium text-foreground hover:bg-surface-elevated transition-colors"
          >
            Sign in again
          </button>
        </div>
      </div>
    </div>
  );
}

function Shell({ children }: { children: React.ReactNode }) {
  const { collapsed } = useSidebar();
  return (
    <div className="flex min-h-screen">
      {/* Skip link — WCAG 2.4.1 Bypass Blocks. First focusable element so
          keyboard users can jump past the nav on every page load. */}
      <a href="#main-content" className="skip-link">
        Skip to main content
      </a>

      <Suspense fallback={null}>
        <Sidebar />
      </Suspense>

      <main
        id="main-content"
        tabIndex={-1}
        className={cn(
          'flex-1 flex flex-col min-h-screen w-full',
          'transition-[margin-left] duration-300 ease-in-out motion-reduce:transition-none',
          // Mobile: sidebar is overlay, no margin offset
          'ml-0',
          // Desktop: reserve space for the fixed sidebar rail
          collapsed ? 'md:ml-[68px]' : 'md:ml-60',
          'focus-visible:outline-none',
        )}
      >
        <div className="mx-auto flex w-full max-w-[1600px] flex-1 flex-col min-h-0">
          <GlobalAiBatchBanner />
          {children}
        </div>
      </main>
    </div>
  );
}

export function AppShell({ children }: { children: React.ReactNode }) {
  const pathname = usePathname();
  const router = useRouter();
  const { bootstrapState, bootstrapError, config, login, retryBootstrap } = useAuth();

  const isPublicPath = PUBLIC_PATHS.some((p) => pathname?.startsWith(p));

  // Redirect handling for verification-required / access-pending / unauthenticated
  useEffect(() => {
    if (isPublicPath) return;

    if (config.enabled && bootstrapState === 'unauthenticated') {
      void login();
      return;
    }

    if (bootstrapState === 'verification-required' && pathname !== '/verification-required') {
      router.replace('/verification-required');
      return;
    }

    if (bootstrapState === 'access-pending' && pathname !== '/access-pending') {
      router.replace('/access-pending');
      return;
    }
  }, [bootstrapState, config.enabled, isPublicPath, login, pathname, router]);

  // Public/Auth routes -> render children directly without sidebar or main shell
  if (isPublicPath) {
    return <>{children}</>;
  }

  // Loading/Bootstrap states -> render ONE shared full-screen branded loader
  if (
    bootstrapState === 'checking-session' ||
    bootstrapState === 'processing-callback' ||
    bootstrapState === 'loading-auth-context' ||
    bootstrapState === 'loading-tenant-context'
  ) {
    const loaderMessage =
      bootstrapState === 'processing-callback'
        ? 'Establishing your secure session…'
        : bootstrapState === 'loading-tenant-context'
          ? 'Loading workspace context…'
          : 'Verifying authentication…';

    return <FullScreenBrandedLoader message={loaderMessage} />;
  }

  // Timeout / Error state -> render recovery UX
  if (bootstrapState === 'error') {
    return (
      <BootstrapTimeoutRecovery
        message={bootstrapError || 'Authentication service or identity validation is currently unreachable.'}
        onRetry={retryBootstrap}
        onLogin={login}
      />
    );
  }

  // Unauthenticated -> full-screen redirect loader
  if (config.enabled && bootstrapState === 'unauthenticated') {
    return <FullScreenBrandedLoader message="Redirecting to sign in…" />;
  }

  // Intermediate transition states -> full-screen redirect loader
  if (bootstrapState === 'verification-required' || bootstrapState === 'access-pending') {
    return <FullScreenBrandedLoader message="Redirecting to access assignment…" />;
  }

  // Ready -> render full protected application shell with sidebar
  return (
    <SidebarProvider>
      <Shell>{children}</Shell>
    </SidebarProvider>
  );
}

'use client';

import { useRef, useState, useEffect, useId } from 'react';
import { usePathname, useRouter } from 'next/navigation';
import {
  Building2,
  Check,
  ChevronDown,
  Globe2,
  LogOut,
  Shield,
  User,
} from 'lucide-react';
import { useAuth } from '@/hooks/useAuth';
import { cn } from '@/lib/utils';
import { getRoleLabel } from '@/lib/roles';

const actionClass =
  'flex w-full items-center gap-3 rounded-lg px-3 py-2.5 text-left text-sm text-foreground hover:bg-surface-muted focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-hcl-blue disabled:opacity-60';

/** One account menu; logout and context changes remain separate existing auth actions. */
export function UserMenu() {
  const {
    user,
    logout,
    config,
    activeTenant,
    activeTenantId,
    tenants = [],
    selectTenant,
    clearTenantSelection,
    bootstrapState,
  } = useAuth();
  const router = useRouter();
  const pathname = usePathname();
  const [open, setOpen] = useState(false);
  const [choosingTenant, setChoosingTenant] = useState(false);
  const [signingOut, setSigningOut] = useState(false);
  const logoutStarted = useRef(false);
  const menuRef = useRef<HTMLDivElement>(null);
  const triggerRef = useRef<HTMLButtonElement>(null);
  const menuId = useId();
  const memberships = tenants.filter(
    (tenant) =>
      tenant.status === 'ACTIVE' && tenant.membershipStatus === 'ACTIVE',
  );
  const currentTenant =
    activeTenant ??
    memberships.find((tenant) => String(tenant.id) === activeTenantId);
  const inTenant = Boolean(activeTenantId || user?.tenantId);
  const platformContext = Boolean(user?.isPlatformAdmin) && !inTenant;
  const busy = signingOut || bootstrapState === 'logging-out';

  useEffect(() => {
    if (!open) return;
    const closeOutside = (event: MouseEvent) => {
      if (!menuRef.current?.contains(event.target as Node)) setOpen(false);
    };
    const handleKey = (event: KeyboardEvent) => {
      if (event.key === 'Escape') {
        setOpen(false);
        triggerRef.current?.focus();
      }
      if (
        event.key === 'ArrowDown' ||
        event.key === 'ArrowUp' ||
        event.key === 'Home' ||
        event.key === 'End'
      ) {
        const items = Array.from(
          menuRef.current?.querySelectorAll<HTMLButtonElement>(
            '[role="menuitem"]:not(:disabled)',
          ) ?? [],
        );
        if (!items.length) return;
        event.preventDefault();
        const index = items.indexOf(
          document.activeElement as HTMLButtonElement,
        );
        const next =
          event.key === 'Home'
            ? 0
            : event.key === 'End'
              ? items.length - 1
              : (index + (event.key === 'ArrowDown' ? 1 : -1) + items.length) %
                items.length;
        items[next]?.focus();
      }
    };
    document.addEventListener('mousedown', closeOutside);
    document.addEventListener('keydown', handleKey);
    return () => {
      document.removeEventListener('mousedown', closeOutside);
      document.removeEventListener('keydown', handleKey);
    };
  }, [open]);

  if (!user) return null;
  const name = user.displayName || user.email || 'User';
  const initials = name
    .split(/[\s@]+/)
    .slice(0, 2)
    .map((word) => word[0]?.toUpperCase() ?? '')
    .join('');
  const roles = user.roles
    .filter((role) => role !== 'PLATFORM_ADMIN')
    .map(getRoleLabel)
    .join(' · ');
  const openMenu = () => {
    setChoosingTenant(false);
    setOpen((value) => !value);
  };
  const signOut = () => {
    if (logoutStarted.current || busy) return;
    logoutStarted.current = true;
    setSigningOut(true);
    // The hook owns query clearing, session termination and provider redirects.
    logout();
  };
  const chooseTenant = async (id: string) => {
    setOpen(false);
    if (id === activeTenantId) return;
    if (pathname === '/') router.replace('/', { scroll: false });
    await selectTenant(id);
    if (!inTenant) router.replace('/');
  };

  return (
    <div
      ref={menuRef}
      className="relative"
      onBlur={(event) => {
        if (!event.currentTarget.contains(event.relatedTarget as Node | null))
          setOpen(false);
      }}
    >
      <button
        ref={triggerRef}
        type="button"
        onClick={openMenu}
        onKeyDown={(event) => {
          if (!open && (event.key === 'ArrowDown' || event.key === 'ArrowUp')) {
            event.preventDefault();
            setChoosingTenant(false);
            setOpen(true);
          }
        }}
        aria-label={`Account menu for ${name}`}
        aria-expanded={open}
        aria-haspopup="menu"
        aria-controls={open ? menuId : undefined}
        className={cn(
          'flex min-w-0 items-center gap-2 rounded-lg px-2 py-1.5 text-sm hover:bg-surface-muted focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-hcl-blue',
          open && 'bg-surface-muted',
        )}
      >
        <span
          className="flex h-8 w-8 shrink-0 items-center justify-center rounded-full bg-gradient-to-br from-hcl-blue to-hcl-cyan text-xs font-bold text-white"
          aria-hidden
        >
          {initials}
        </span>
        <span className="hidden max-w-[140px] truncate font-medium text-foreground md:block">
          {name}
        </span>
        <ChevronDown className="h-3.5 w-3.5 text-foreground/70" aria-hidden />
      </button>
      {open && (
        <div
          id={menuId}
          role="menu"
          aria-label="Account"
          className="absolute right-0 top-full z-50 mt-2 w-80 max-w-[calc(100vw-2rem)] overflow-hidden rounded-2xl border border-border bg-surface shadow-elev-3"
        >
          <div className="border-b border-border px-4 py-4">
            <div className="flex items-center gap-3">
              <span
                className="flex h-10 w-10 shrink-0 items-center justify-center rounded-full bg-gradient-to-br from-hcl-blue to-hcl-cyan text-sm font-bold text-white"
                aria-hidden
              >
                {initials}
              </span>
              <div className="min-w-0">
                <p className="truncate text-sm font-semibold text-foreground">
                  {name}
                </p>
                {user.email && (
                  <p className="mt-0.5 truncate text-xs text-foreground/70">
                    {user.email}
                  </p>
                )}
              </div>
            </div>
            <div className="mt-3 rounded-lg bg-surface-muted px-3 py-2 text-xs text-foreground">
              <div className="flex items-center gap-2">
                {platformContext ? (
                  <Globe2 className="h-3.5 w-3.5 shrink-0" aria-hidden />
                ) : (
                  <Building2 className="h-3.5 w-3.5 shrink-0" aria-hidden />
                )}
                <span className="truncate font-medium">
                  {platformContext
                    ? 'Platform context'
                    : currentTenant?.name || 'Tenant workspace'}
                </span>
              </div>
              <p className="mt-1 flex items-center gap-2 text-foreground/70">
                <Shield className="h-3 w-3 shrink-0" aria-hidden />
                {platformContext
                  ? 'Platform Administrator'
                  : roles || 'Tenant member'}
              </p>
            </div>
          </div>
          <div className="p-1.5">
            {((platformContext && memberships.length > 0) ||
              (!platformContext && memberships.length > 1)) && (
              <button
                type="button"
                role="menuitem"
                className={actionClass}
                onClick={() => setChoosingTenant((value) => !value)}
                aria-expanded={choosingTenant}
              >
                <Building2 className="h-4 w-4" aria-hidden />
                {platformContext ? 'Open tenant workspace' : 'Switch tenant'}
              </button>
            )}
            {choosingTenant && (
              <div className="max-h-56 overflow-y-auto border-y border-border py-1">
                {memberships.map((tenant) => (
                  <button
                    type="button"
                    role="menuitem"
                    key={tenant.id}
                    className={actionClass}
                    onClick={() => void chooseTenant(String(tenant.id))}
                  >
                    <span className="min-w-0 flex-1">
                      <span className="block truncate text-sm">
                        {tenant.name}
                      </span>
                      <span className="block text-xs text-foreground/70">
                        {tenant.roles.map(getRoleLabel).join(' · ')}
                      </span>
                    </span>
                    {String(tenant.id) === activeTenantId && (
                      <Check
                        className="h-4 w-4 shrink-0"
                        aria-label="Current tenant"
                      />
                    )}
                  </button>
                ))}
              </div>
            )}
            {user.isPlatformAdmin && inTenant && (
              <button
                type="button"
                role="menuitem"
                className={actionClass}
                onClick={() => {
                  setOpen(false);
                  clearTenantSelection();
                  router.replace('/platform');
                }}
              >
                <Globe2 className="h-4 w-4" aria-hidden />
                Return to Platform
              </button>
            )}
          </div>
          <div className="border-t border-border p-1.5">
            {config.enabled ? (
              <button
                type="button"
                role="menuitem"
                disabled={busy}
                onClick={signOut}
                className={cn(
                  actionClass,
                  'text-red-700 hover:bg-red-50 dark:text-red-300 dark:hover:bg-red-950/30',
                )}
              >
                <LogOut className="h-4 w-4" aria-hidden />
                {busy ? 'Signing out…' : 'Sign Out'}
              </button>
            ) : (
              <p className="flex items-center gap-2 px-3 py-2 text-xs text-foreground/70">
                <User className="h-3.5 w-3.5" aria-hidden />
                Development mode — no sign out
              </p>
            )}
          </div>
        </div>
      )}
    </div>
  );
}

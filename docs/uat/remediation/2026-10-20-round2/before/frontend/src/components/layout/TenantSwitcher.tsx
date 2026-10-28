'use client';

/**
 * TenantSwitcher — dropdown for switching between tenants.
 *
 * Shows the current tenant name and a list of available tenants.
 * On switch: clears React Query caches, updates the X-Tenant-ID header,
 * and re-fetches user profile with the new tenant context.
 *
 * Platform administrators get one extra entry — "Platform" — which is the
 * context they sign in to: no active tenant, no X-Tenant-ID, platform pages
 * only. Available tenants are exclusively explicit, active memberships.
 * Platform tenant administration is never a tenant-switching option.
 */

import { useRef, useState, useEffect, useMemo } from 'react';
import { usePathname, useRouter } from 'next/navigation';
import { Building2, Check, ChevronsUpDown, Globe2 } from 'lucide-react';
import { useAuth } from '@/hooks/useAuth';
import { cn } from '@/lib/utils';

import { getRoleLabel } from '@/lib/roles';

/** Rendering cap for the platform tenant list — search narrows the rest. */
const MAX_VISIBLE = 25;

interface SwitcherOption {
  id: string;
  name: string;
  detail: string;
}

export function TenantSwitcher({ compact = false }: { compact?: boolean }) {
  const pathname = usePathname();
  const router = useRouter();
  const {
    tenants, activeTenantId, selectTenant, switchTenant, clearTenantSelection, user,
  } = useAuth();
  const isPlatformAdmin = Boolean(user?.isPlatformAdmin);
  const [open, setOpen] = useState(false);
  const [search, setSearch] = useState('');
  const containerRef = useRef<HTMLDivElement>(null);
  const triggerRef = useRef<HTMLButtonElement>(null);

  // Close on outside click
  useEffect(() => {
    function handleClickOutside(e: MouseEvent) {
      if (containerRef.current && !containerRef.current.contains(e.target as Node)) {
        setOpen(false);
      }
    }
    if (open) {
      document.addEventListener('mousedown', handleClickOutside);
      return () => document.removeEventListener('mousedown', handleClickOutside);
    }
  }, [open]);

  // Close on Escape
  useEffect(() => {
    function handleKey(e: KeyboardEvent) {
      if (e.key === 'Escape') { setOpen(false); triggerRef.current?.focus(); }
      if (e.key === 'ArrowDown' || e.key === 'ArrowUp') {
        const options = Array.from(containerRef.current?.querySelectorAll<HTMLButtonElement>('[role="option"]') ?? []);
        const index = options.indexOf(document.activeElement as HTMLButtonElement);
        if (options.length) {
          e.preventDefault();
          options[(index + (e.key === 'ArrowDown' ? 1 : -1) + options.length) % options.length]?.focus();
        }
      }
    }
    if (open) {
      document.addEventListener('keydown', handleKey);
      return () => document.removeEventListener('keydown', handleKey);
    }
  }, [open]);

  const membershipOptions = useMemo<SwitcherOption[]>(
    () => tenants.map((tenant) => {
      const roles = tenant.roles ?? (tenant.role ? [tenant.role] : []);
      return {
        id: String(tenant.id),
        name: tenant.name,
        detail: [
          roles.length > 0 ? roles.map(getRoleLabel).join(', ') : 'Platform management context',
          tenant.membershipStatus ?? '',
        ].filter(Boolean).join(' · '),
      };
    }),
    [tenants],
  );

  const options = membershipOptions;

  const term = search.trim().toLowerCase();
  const matches = term
    ? options.filter(
        (option) =>
          option.name.toLowerCase().includes(term) || option.detail.toLowerCase().includes(term),
      )
    : options;
  const visible = matches.slice(0, MAX_VISIBLE);

  // Nothing to switch between and no platform context to return to.
  if (tenants.length === 0) {
    return null;
  }

  const activeTenant = tenants.find((t) => String(t.id) === activeTenantId);
  const currentLabel = activeTenant?.name
    ?? (isPlatformAdmin && !activeTenantId ? 'Platform' : 'Select Tenant');

  const choose = (tenantId: string) => {
    if (tenantId === activeTenantId) return;
    // Project/Application/SBOM IDs in the dashboard URL belong to the old
    // tenant. Clear them before resolving the newly selected tenant context.
    if (pathname === '/') router.replace('/', { scroll: false });
    if (selectTenant) {
      void selectTenant(tenantId).then(() => {
        if (!activeTenantId) router.replace('/');
      });
    } else {
      switchTenant(tenantId);
    }
  };

  return (
    <div ref={containerRef} className="relative" onBlur={event => {
      if (!event.currentTarget.contains(event.relatedTarget as Node | null)) setOpen(false);
    }}>
      <button
        id="tenant-switcher-trigger"
        ref={triggerRef}
        type="button"
        onClick={() => setOpen(!open)}
        aria-expanded={open}
        aria-haspopup="listbox"
        aria-label="Switch tenant"
        aria-controls={open ? 'tenant-switcher-options' : undefined}
        title={compact ? `Switch tenant · ${currentLabel}` : undefined}
        className={cn(
          'flex w-full min-w-0 items-center gap-2.5 rounded-xl border border-white/20 bg-white/10 px-3 py-2.5 text-sm shadow-inner transition-colors',
          'hover:border-white/40 hover:bg-white/15 focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-white/80',
          compact && 'md:justify-center md:px-0',
          open && 'border-white/70 bg-white/10',
        )}
      >
        <span className="flex h-8 w-8 shrink-0 items-center justify-center rounded-lg border border-white/15 bg-black/10 text-white">
          {isPlatformAdmin && !activeTenantId ? <Globe2 className="h-4 w-4" aria-hidden /> : <Building2 className="h-4 w-4" aria-hidden />}
        </span>
        <span className={cn('min-w-0 flex-1 text-left', compact && 'md:hidden')}>
          <span className="block truncate text-xs font-semibold text-white" title={currentLabel}>{currentLabel}</span>
          <span className="mt-0.5 block text-[10px] text-white/75">{isPlatformAdmin && !activeTenantId ? 'Platform control plane' : activeTenant ? 'Active tenant' : 'Tenant workspace'}</span>
        </span>
        <ChevronsUpDown className={cn('h-3.5 w-3.5 shrink-0 text-white/80', compact && 'md:hidden')} aria-hidden />
      </button>

      {open && (
        <div
          role="listbox"
          id="tenant-switcher-options"
          aria-label="Available tenants"
          className={cn(
            'absolute left-0 top-full mt-2 z-50 w-full min-w-[220px] max-w-[calc(100vw-2rem)]',
            compact && 'md:left-full md:top-0 md:ml-3 md:mt-0 md:w-64',
            'rounded-xl border border-border bg-surface shadow-elev-3',
            'animate-in fade-in slide-in-from-top-2 duration-150',
            'max-h-80 overflow-y-auto',
          )}
        >
          <div className="p-1.5">
            {isPlatformAdmin && (
              <>
                <button
                  type="button"
                  role="option"
                  aria-selected={!activeTenantId}
                  onClick={() => {
                    if (activeTenantId) clearTenantSelection();
                    router.replace('/platform');
                    setOpen(false);
                  }}
                  className={cn(
                    'flex w-full items-center gap-3 rounded-lg px-3 py-2 text-sm transition-colors',
                    'hover:bg-surface-muted focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-hcl-blue',
                    !activeTenantId && 'bg-hcl-blue/5',
                  )}
                >
                  <Globe2
                    className={cn('h-4 w-4 shrink-0', !activeTenantId ? 'text-hcl-blue' : 'text-hcl-muted')}
                  />
                  <div className="min-w-0 flex-1 text-left">
                    <p className={cn('truncate font-medium', !activeTenantId ? 'text-hcl-blue' : 'text-foreground')}>
                      Platform
                    </p>
                    <p className="text-xs text-hcl-muted">Platform administration · no tenant</p>
                  </div>
                  {!activeTenantId && <Check className="h-4 w-4 shrink-0 text-hcl-blue" />}
                </button>
                <div className="px-1.5 py-1.5">
                  <input
                    type="search"
                    aria-label="Search tenants"
                    placeholder="Search tenants…"
                    value={search}
                    onChange={(event) => setSearch(event.target.value)}
                    className="w-full rounded-md border border-border bg-background px-2 py-1.5 text-sm text-foreground"
                  />
                </div>
              </>
            )}
            {visible.map((option) => {
              const isActive = option.id === activeTenantId;
              return (
                <button
                  key={option.id}
                  type="button"
                  role="option"
                  aria-selected={isActive}
                  onClick={() => {
                    choose(option.id);
                    setOpen(false);
                  }}
                  className={cn(
                    'flex w-full items-center gap-3 rounded-lg px-3 py-2 text-sm transition-colors',
                    'hover:bg-surface-muted focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-hcl-blue',
                    isActive && 'bg-hcl-blue/5',
                  )}
                >
                  <Building2
                    className={cn(
                      'h-4 w-4 shrink-0',
                      isActive ? 'text-hcl-blue' : 'text-hcl-muted',
                    )}
                  />
                  <div className="min-w-0 flex-1 text-left">
                    <p
                      className={cn(
                        'truncate font-medium',
                        isActive ? 'text-hcl-blue' : 'text-foreground',
                      )}
                    >
                      {option.name}
                    </p>
                    {option.detail && <p className="text-xs text-hcl-muted">{option.detail}</p>}
                  </div>
                  {isActive && (
                    <Check className="h-4 w-4 shrink-0 text-hcl-blue" />
                  )}
                </button>
              );
            })}
            {matches.length > visible.length && (
              <p className="px-3 py-2 text-xs text-hcl-muted">
                Showing {visible.length} of {matches.length} tenants — refine your search.
              </p>
            )}
            {isPlatformAdmin && term && matches.length === 0 && (
              <p className="px-3 py-2 text-xs text-hcl-muted">No tenant matches “{search.trim()}”.</p>
            )}
          </div>
        </div>
      )}
    </div>
  );
}

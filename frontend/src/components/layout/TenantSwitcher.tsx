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
 * only. Their tenant list is fetched on demand and searched rather than
 * carried in the auth context, because platform reach covers every tenant in
 * the deployment and rendering hundreds of them is not a sign-in step.
 */

import { useRef, useState, useEffect, useMemo } from 'react';
import { useQuery } from '@tanstack/react-query';
import { Building2, Check, ChevronsUpDown, Globe2 } from 'lucide-react';
import { useAuth } from '@/hooks/useAuth';
import { listPlatformTenants } from '@/lib/api';
import { cn } from '@/lib/utils';

import { getRoleLabel } from '@/lib/roles';

/** Rendering cap for the platform tenant list — search narrows the rest. */
const MAX_VISIBLE = 25;

interface SwitcherOption {
  id: string;
  name: string;
  detail: string;
}

export function TenantSwitcher() {
  const {
    tenants, activeTenantId, selectTenant, switchTenant, clearTenantSelection, user,
  } = useAuth();
  const isPlatformAdmin = Boolean(user?.isPlatformAdmin);
  const [open, setOpen] = useState(false);
  const [search, setSearch] = useState('');
  const containerRef = useRef<HTMLDivElement>(null);

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
      if (e.key === 'Escape') setOpen(false);
    }
    if (open) {
      document.addEventListener('keydown', handleKey);
      return () => document.removeEventListener('keydown', handleKey);
    }
  }, [open]);

  // Only while the dropdown is open, and only for platform administrators —
  // bootstrap never pays for this list.
  const platformTenants = useQuery({
    queryKey: ['platform-tenants'],
    queryFn: listPlatformTenants,
    enabled: open && isPlatformAdmin,
    staleTime: 60_000,
    retry: false,
  });

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

  const options = useMemo<SwitcherOption[]>(() => {
    if (isPlatformAdmin && platformTenants.data && platformTenants.data.length > 0) {
      return platformTenants.data.map((tenant) => ({
        id: String(tenant.id),
        name: tenant.name,
        detail: tenant.slug,
      }));
    }
    return membershipOptions;
  }, [isPlatformAdmin, membershipOptions, platformTenants.data]);

  const term = search.trim().toLowerCase();
  const matches = term
    ? options.filter(
        (option) =>
          option.name.toLowerCase().includes(term) || option.detail.toLowerCase().includes(term),
      )
    : options;
  const visible = matches.slice(0, MAX_VISIBLE);

  // Nothing to switch between and no platform context to return to.
  if (!isPlatformAdmin && tenants.length === 0) {
    return null;
  }

  const activeTenant = tenants.find((t) => String(t.id) === activeTenantId);
  const currentLabel = activeTenant?.name
    ?? (isPlatformAdmin && !activeTenantId ? 'Platform' : 'Select Tenant');

  const choose = (tenantId: string) => {
    if (tenantId === activeTenantId) return;
    if (selectTenant) {
      void selectTenant(tenantId);
    } else {
      switchTenant(tenantId);
    }
  };

  return (
    <div ref={containerRef} className="relative">
      <button
        id="tenant-switcher-trigger"
        type="button"
        onClick={() => setOpen(!open)}
        aria-expanded={open}
        aria-haspopup="listbox"
        aria-label="Switch tenant"
        className={cn(
          'flex w-full items-center gap-2 rounded-lg border border-border px-3 py-2 text-sm transition-colors',
          'hover:bg-white/10 focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-white/50',
          open && 'border-white/70 bg-white/10',
        )}
      >
        {isPlatformAdmin && !activeTenantId ? (
          <Globe2 className="h-4 w-4 shrink-0 text-hcl-muted" />
        ) : (
          <Building2 className="h-4 w-4 shrink-0 text-hcl-muted" />
        )}
        <span className="flex-1 truncate text-left font-medium text-white">
          {currentLabel}
        </span>
        <ChevronsUpDown className="h-3.5 w-3.5 shrink-0 text-hcl-muted" />
      </button>

      {open && (
        <div
          role="listbox"
          aria-label="Available tenants"
          className={cn(
            'absolute left-0 top-full mt-1 z-50 w-full min-w-[220px]',
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
                    setOpen(false);
                  }}
                  className={cn(
                    'flex w-full items-center gap-3 rounded-lg px-3 py-2 text-sm transition-colors',
                    'hover:bg-surface-muted',
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
                {platformTenants.isLoading && (
                  <p className="px-3 py-2 text-xs text-hcl-muted">Loading tenants…</p>
                )}
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
                    'hover:bg-surface-muted',
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

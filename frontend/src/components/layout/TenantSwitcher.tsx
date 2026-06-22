'use client';

/**
 * TenantSwitcher — dropdown for switching between tenants.
 *
 * Shows the current tenant name and a list of available tenants.
 * On switch: clears React Query caches, updates the X-Tenant-ID header,
 * and re-fetches user profile with the new tenant context.
 */

import { useRef, useState, useEffect } from 'react';
import { Building2, Check, ChevronsUpDown } from 'lucide-react';
import { useAuth } from '@/hooks/useAuth';
import { cn } from '@/lib/utils';

export function TenantSwitcher() {
  const { tenants, activeTenantId, switchTenant, user } = useAuth();
  const [open, setOpen] = useState(false);
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

  // Don't show if only one tenant
  if (tenants.length <= 1) {
    const single = tenants[0];
    if (!single) return null;
    return (
      <div className="flex items-center gap-2 rounded-lg px-3 py-2 text-sm text-hcl-muted">
        <Building2 className="h-4 w-4 shrink-0" />
        <span className="truncate font-medium">{single.name}</span>
      </div>
    );
  }

  const activeTenant = tenants.find((t) => String(t.id) === activeTenantId);

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
          'hover:bg-surface-muted focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-hcl-blue/50',
          open && 'bg-surface-muted border-hcl-blue/50',
        )}
      >
        <Building2 className="h-4 w-4 shrink-0 text-hcl-muted" />
        <span className="flex-1 truncate text-left font-medium text-foreground">
          {activeTenant?.name || 'Select Tenant'}
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
            'max-h-64 overflow-y-auto',
          )}
        >
          <div className="p-1.5">
            {tenants.map((tenant) => {
              const isActive = String(tenant.id) === activeTenantId;
              return (
                <button
                  key={tenant.id}
                  type="button"
                  role="option"
                  aria-selected={isActive}
                  onClick={() => {
                    if (!isActive) {
                      switchTenant(String(tenant.id));
                    }
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
                      {tenant.name}
                    </p>
                    {tenant.role && (
                      <p className="text-xs text-hcl-muted">
                        {tenant.role.replace(/_/g, ' ')}
                      </p>
                    )}
                  </div>
                  {isActive && (
                    <Check className="h-4 w-4 shrink-0 text-hcl-blue" />
                  )}
                </button>
              );
            })}
          </div>
        </div>
      )}
    </div>
  );
}

'use client';

/**
 * UserMenu — dropdown showing the authenticated user's identity, role,
 * and logout action. Renders in the TopBar or sidebar footer.
 */

import { useRef, useState, useEffect } from 'react';
import { LogOut, Shield, User } from 'lucide-react';
import { useAuth } from '@/hooks/useAuth';
import { cn } from '@/lib/utils';

export function UserMenu() {
  const { user, logout, config } = useAuth();
  const [open, setOpen] = useState(false);
  const menuRef = useRef<HTMLDivElement>(null);

  // Close menu on outside click
  useEffect(() => {
    function handleClickOutside(e: MouseEvent) {
      if (menuRef.current && !menuRef.current.contains(e.target as Node)) {
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

  if (!user) return null;

  const initials = (user.displayName || user.email || 'U')
    .split(/[\s@]+/)
    .slice(0, 2)
    .map((w) => w[0]?.toUpperCase() || '')
    .join('');

  const primaryRole = user.roles[0] || 'USER';

  return (
    <div ref={menuRef} className="relative">
      <button
        id="user-menu-trigger"
        type="button"
        onClick={() => setOpen(!open)}
        aria-expanded={open}
        aria-haspopup="true"
        className={cn(
          'flex items-center gap-2 rounded-lg px-2 py-1.5 text-sm transition-colors',
          'hover:bg-surface-muted focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-hcl-blue/50',
          open && 'bg-surface-muted',
        )}
      >
        <div className="flex h-8 w-8 shrink-0 items-center justify-center rounded-full bg-gradient-to-br from-hcl-blue to-hcl-cyan text-xs font-bold text-white">
          {initials}
        </div>
        <span className="hidden md:block max-w-[120px] truncate text-foreground font-medium">
          {user.displayName || user.email || user.externalUserId}
        </span>
      </button>

      {open && (
        <div
          role="menu"
          className={cn(
            'absolute right-0 top-full mt-2 z-50 w-72 origin-top-right',
            'rounded-xl border border-border bg-surface shadow-elev-3',
            'animate-in fade-in slide-in-from-top-2 duration-150',
          )}
        >
          {/* Profile section */}
          <div className="border-b border-border px-4 py-3">
            <div className="flex items-center gap-3">
              <div className="flex h-10 w-10 shrink-0 items-center justify-center rounded-full bg-gradient-to-br from-hcl-blue to-hcl-cyan text-sm font-bold text-white">
                {initials}
              </div>
              <div className="min-w-0 flex-1">
                <p className="truncate text-sm font-semibold text-foreground">
                  {user.displayName || 'User'}
                </p>
                {user.email && (
                  <p className="truncate text-xs text-hcl-muted">{user.email}</p>
                )}
              </div>
            </div>
          </div>

          {/* Role badge */}
          <div className="border-b border-border px-4 py-2">
            <div className="flex items-center gap-2">
              <Shield className="h-3.5 w-3.5 text-hcl-muted" />
              <span className="text-xs font-medium text-hcl-muted">
                {primaryRole.replace(/_/g, ' ')}
              </span>
              {user.isPlatformAdmin && (
                <span className="rounded-full bg-hcl-blue/10 px-2 py-0.5 text-[10px] font-bold text-hcl-blue">
                  PLATFORM
                </span>
              )}
            </div>
          </div>

          {/* Actions */}
          <div className="p-1.5">
            {config.enabled && (
              <button
                type="button"
                role="menuitem"
                onClick={() => {
                  setOpen(false);
                  logout();
                }}
                className={cn(
                  'flex w-full items-center gap-3 rounded-lg px-3 py-2 text-sm transition-colors',
                  'text-red-600 dark:text-red-400 hover:bg-red-50 dark:hover:bg-red-900/10',
                )}
              >
                <LogOut className="h-4 w-4" />
                Sign Out
              </button>
            )}
            {!config.enabled && (
              <div className="px-3 py-2 text-xs text-hcl-muted flex items-center gap-2">
                <User className="h-3.5 w-3.5" />
                Development mode — no sign out
              </div>
            )}
          </div>
        </div>
      )}
    </div>
  );
}

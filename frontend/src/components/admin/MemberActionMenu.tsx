'use client';

import { useEffect, useRef, useState, type KeyboardEvent } from 'react';
import { MoreVertical, Shield, UserX, UserCheck, UserMinus } from 'lucide-react';

interface MemberActionMenuProps {
  displayName: string;
  membershipStatus: string;
  canUpdate: boolean;
  onManageRoles: () => void;
  onDisableMembership: () => void;
  onEnableMembership: () => void;
  onRemoveFromTenant: () => void;
}

export function MemberActionMenu({
  displayName,
  membershipStatus,
  canUpdate,
  onManageRoles,
  onDisableMembership,
  onEnableMembership,
  onRemoveFromTenant,
}: MemberActionMenuProps) {
  const [open, setOpen] = useState(false);
  const containerRef = useRef<HTMLDivElement>(null);
  const buttonRef = useRef<HTMLButtonElement>(null);
  const menuRef = useRef<HTMLDivElement>(null);

  const isMembershipActive = membershipStatus === 'ACTIVE';

  useEffect(() => {
    if (!open) return;

    const handleOutsideClick = (e: MouseEvent) => {
      if (containerRef.current && !containerRef.current.contains(e.target as Node)) {
        setOpen(false);
      }
    };

    const handleKeyDown = (e: globalThis.KeyboardEvent) => {
      if (e.key === 'Escape') {
        e.preventDefault();
        setOpen(false);
        buttonRef.current?.focus();
      }
    };

    document.addEventListener('mousedown', handleOutsideClick);
    document.addEventListener('keydown', handleKeyDown);
    return () => {
      document.removeEventListener('mousedown', handleOutsideClick);
      document.removeEventListener('keydown', handleKeyDown);
    };
  }, [open]);

  useEffect(() => {
    if (open) {
      const firstItem = menuRef.current?.querySelector<HTMLButtonElement>('[role="menuitem"]');
      firstItem?.focus();
    }
  }, [open]);

  const handleMenuKeyDown = (e: KeyboardEvent<HTMLDivElement>) => {
    const items = Array.from(
      menuRef.current?.querySelectorAll<HTMLButtonElement>('[role="menuitem"]') ?? [],
    );
    const currentIndex = items.findIndex((item) => item === document.activeElement);

    if (e.key === 'ArrowDown') {
      e.preventDefault();
      const nextIndex = currentIndex + 1 < items.length ? currentIndex + 1 : 0;
      items[nextIndex]?.focus();
    } else if (e.key === 'ArrowUp') {
      e.preventDefault();
      const prevIndex = currentIndex - 1 >= 0 ? currentIndex - 1 : items.length - 1;
      items[prevIndex]?.focus();
    }
  };

  if (!canUpdate) {
    return null;
  }

  const ariaLabel = `Open actions for ${displayName || 'user'}`;

  return (
    <div ref={containerRef} className="relative inline-block text-left">
      <button
        ref={buttonRef}
        type="button"
        onClick={() => setOpen((prev) => !prev)}
        aria-label={ariaLabel}
        aria-haspopup="menu"
        aria-expanded={open}
        className="inline-flex h-11 w-11 items-center justify-center rounded-lg border border-transparent text-hcl-muted hover:border-border hover:bg-surface-elevated hover:text-foreground focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-hcl-blue focus-visible:ring-offset-2 transition-colors min-h-[44px] min-w-[44px]"
      >
        <MoreVertical className="h-5 w-5" aria-hidden="true" />
      </button>

      {open && (
        <div
          ref={menuRef}
          role="menu"
          aria-orientation="vertical"
          aria-label={`Actions for ${displayName}`}
          onKeyDown={handleMenuKeyDown}
          className="absolute right-0 z-50 mt-1 w-56 origin-top-right rounded-xl border border-border bg-surface p-1.5 shadow-elev-3 focus:outline-none"
        >
          <button
            type="button"
            role="menuitem"
            onClick={() => {
              setOpen(false);
              onManageRoles();
            }}
            className="flex w-full items-center gap-2.5 rounded-lg px-3 py-2.5 text-left text-sm font-medium text-foreground hover:bg-surface-elevated focus:bg-surface-elevated focus:outline-none transition-colors min-h-[44px]"
          >
            <Shield className="h-4 w-4 text-hcl-blue" aria-hidden="true" />
            Manage roles
          </button>

          {isMembershipActive ? (
            <button
              type="button"
              role="menuitem"
              onClick={() => {
                setOpen(false);
                onDisableMembership();
              }}
              className="flex w-full items-center gap-2.5 rounded-lg px-3 py-2.5 text-left text-sm font-medium text-amber-700 dark:text-amber-400 hover:bg-amber-50 dark:hover:bg-amber-950/20 focus:bg-amber-50 focus:outline-none transition-colors min-h-[44px]"
            >
              <UserX className="h-4 w-4 text-amber-600" aria-hidden="true" />
              Disable membership
            </button>
          ) : (
            <button
              type="button"
              role="menuitem"
              onClick={() => {
                setOpen(false);
                onEnableMembership();
              }}
              className="flex w-full items-center gap-2.5 rounded-lg px-3 py-2.5 text-left text-sm font-medium text-emerald-700 dark:text-emerald-400 hover:bg-emerald-50 dark:hover:bg-emerald-950/20 focus:bg-emerald-50 focus:outline-none transition-colors min-h-[44px]"
            >
              <UserCheck className="h-4 w-4 text-emerald-600" aria-hidden="true" />
              Enable membership
            </button>
          )}

          <div className="my-1 border-t border-border" />

          <button
            type="button"
            role="menuitem"
            onClick={() => {
              setOpen(false);
              onRemoveFromTenant();
            }}
            className="flex w-full items-center gap-2.5 rounded-lg px-3 py-2.5 text-left text-sm font-medium text-red-700 dark:text-red-400 hover:bg-red-50 dark:hover:bg-red-950/20 focus:bg-red-50 focus:outline-none transition-colors min-h-[44px]"
          >
            <UserMinus className="h-4 w-4 text-red-600" aria-hidden="true" />
            Remove from tenant
          </button>
        </div>
      )}
    </div>
  );
}

'use client';

import { useCallback, useEffect, useId, useLayoutEffect, useRef, useState, type KeyboardEvent } from 'react';
import { createPortal } from 'react-dom';
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

const COLLISION_PADDING = 8;
const ESTIMATED_MENU_WIDTH = 224; // w-56 = 14rem = 224px
const ESTIMATED_MENU_HEIGHT = 176;

export function MemberActionMenu({
  displayName,
  membershipStatus,
  canUpdate,
  onManageRoles,
  onDisableMembership,
  onEnableMembership,
  onRemoveFromTenant,
}: MemberActionMenuProps) {
  const menuId = useId();
  const [open, setOpen] = useState(false);
  const [positionStyle, setPositionStyle] = useState<{ top: number; left: number }>({ top: 0, left: 0 });
  const buttonRef = useRef<HTMLButtonElement>(null);
  const menuRef = useRef<HTMLDivElement>(null);

  const isMembershipActive = membershipStatus === 'ACTIVE';

  const updatePosition = useCallback(() => {
    if (!buttonRef.current) return;

    const triggerRect = buttonRef.current.getBoundingClientRect();
    const vh = window.innerHeight;
    const vw = window.innerWidth;

    const menuWidth = menuRef.current?.offsetWidth || ESTIMATED_MENU_WIDTH;
    const menuHeight = menuRef.current?.offsetHeight || ESTIMATED_MENU_HEIGHT;

    const spaceBelow = vh - triggerRect.bottom - COLLISION_PADDING;
    const spaceAbove = triggerRect.top - COLLISION_PADDING;

    let top: number;
    if (spaceBelow < menuHeight && spaceAbove >= menuHeight) {
      top = triggerRect.top - menuHeight - 4;
    } else {
      top = triggerRect.bottom + 4;
    }

    // Clamp top to viewport bounds
    top = Math.max(COLLISION_PADDING, Math.min(top, vh - menuHeight - COLLISION_PADDING));

    // Align right edge of menu with right edge of trigger
    const preferredLeft = triggerRect.right - menuWidth;
    const left = Math.max(COLLISION_PADDING, Math.min(preferredLeft, vw - menuWidth - COLLISION_PADDING));

    setPositionStyle({ top, left });
  }, []);

  // Listen for single-active-menu event across all MemberActionMenu instances
  useEffect(() => {
    const handleCloseOthers = (e: Event) => {
      const customEvent = e as CustomEvent<{ menuId: string }>;
      if (customEvent.detail?.menuId !== menuId) {
        setOpen(false);
      }
    };

    document.addEventListener('close-member-action-menus', handleCloseOthers);
    return () => document.removeEventListener('close-member-action-menus', handleCloseOthers);
  }, [menuId]);

  // Click outside and Escape key handlers
  useEffect(() => {
    if (!open) return;

    const handleOutsideClick = (e: MouseEvent) => {
      const target = e.target as Node;
      if (
        buttonRef.current &&
        !buttonRef.current.contains(target) &&
        menuRef.current &&
        !menuRef.current.contains(target)
      ) {
        setOpen(false);
      }
    };

    const handleKeyDown = (e: globalThis.KeyboardEvent) => {
      if (e.key === 'Escape') {
        e.preventDefault();
        setOpen(false);
        buttonRef.current?.focus();
      } else if (e.key === 'Tab') {
        setOpen(false);
      }
    };

    document.addEventListener('mousedown', handleOutsideClick);
    document.addEventListener('keydown', handleKeyDown);

    return () => {
      document.removeEventListener('mousedown', handleOutsideClick);
      document.removeEventListener('keydown', handleKeyDown);
    };
  }, [open]);

  // Update position on open, scroll, or resize
  useLayoutEffect(() => {
    if (!open) return;

    updatePosition();

    const handleScrollOrResize = () => updatePosition();
    window.addEventListener('scroll', handleScrollOrResize, true);
    window.addEventListener('resize', handleScrollOrResize);

    return () => {
      window.removeEventListener('scroll', handleScrollOrResize, true);
      window.removeEventListener('resize', handleScrollOrResize);
    };
  }, [open, updatePosition]);

  // Focus management on open
  useEffect(() => {
    if (open) {
      const firstItem = menuRef.current?.querySelector<HTMLButtonElement>('[role="menuitem"]');
      firstItem?.focus();
    }
  }, [open]);

  const toggleMenu = () => {
    if (!open) {
      document.dispatchEvent(new CustomEvent('close-member-action-menus', { detail: { menuId } }));
    }
    setOpen((prev) => !prev);
  };

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

  const menuContent = open && (
    <div
      ref={menuRef}
      role="menu"
      aria-orientation="vertical"
      aria-label={`Actions for ${displayName}`}
      onKeyDown={handleMenuKeyDown}
      style={{
        position: 'fixed',
        top: `${positionStyle.top}px`,
        left: `${positionStyle.left}px`,
        zIndex: 9999,
      }}
      className="w-56 rounded-xl border border-border bg-surface p-1.5 shadow-elev-3 focus:outline-none"
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

      <div className="my-1 border-t border-border" aria-hidden="true" />

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
  );

  return (
    <div className="inline-block text-left">
      <button
        ref={buttonRef}
        type="button"
        onClick={toggleMenu}
        aria-label={ariaLabel}
        aria-haspopup="menu"
        aria-expanded={open}
        className="inline-flex h-11 w-11 items-center justify-center rounded-lg border border-transparent text-hcl-muted hover:border-border hover:bg-surface-elevated hover:text-foreground focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-hcl-blue focus-visible:ring-offset-2 transition-colors min-h-[44px] min-w-[44px]"
      >
        <MoreVertical className="h-5 w-5" aria-hidden="true" />
      </button>

      {typeof document !== 'undefined' && menuContent ? createPortal(menuContent, document.body) : null}
    </div>
  );
}

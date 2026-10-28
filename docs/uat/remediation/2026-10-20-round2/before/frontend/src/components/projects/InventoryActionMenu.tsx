'use client';

import { useEffect, useId, useLayoutEffect, useRef, useState } from 'react';
import { createPortal } from 'react-dom';
import Link from 'next/link';
import { usePermissions } from '@/hooks/usePermission';
import { permissionReason } from '@/lib/permissionUi';
import { MoreHorizontal } from 'lucide-react';

export interface InventoryAction {
  label: string;
  accessibleName?: string;
  href?: string;
  onClick?: () => void;
  destructive?: boolean;
  disabled?: boolean;
  permission?: string | string[];
  disabledReason?: string;
}

/** Portal keeps inventory menus outside scrolling tables and clipped card frames. */
export function InventoryActionMenu({ label, actions }: { label: string; actions: InventoryAction[] }) {
  const id = useId();
  const [open, setOpen] = useState(false);
  const [position, setPosition] = useState({ top: 0, left: 0 });
  const trigger = useRef<HTMLButtonElement>(null);
  const menu = useRef<HTMLDivElement>(null);
  const focusItems = () => Array.from(menu.current?.querySelectorAll<HTMLElement>('[role="menuitem"]:not([disabled])') ?? []);
  function close(restore = false) { setOpen(false); if (restore) trigger.current?.focus(); }

  useLayoutEffect(() => {
    if (!open || !trigger.current) return;
    const rect = trigger.current.getBoundingClientRect();
    const height = menu.current?.offsetHeight ?? actions.length * 40;
    setPosition({ left: Math.max(8, Math.min(rect.right - 224, window.innerWidth - 232)), top: Math.max(8, Math.min(rect.bottom + 4, window.innerHeight - height - 8)) });
    menu.current?.querySelector<HTMLElement>('[role="menuitem"]:not([disabled])')?.focus();
  }, [open, actions.length]);

  useEffect(() => {
    if (!open) return;
    const outside = (event: PointerEvent) => { if (!menu.current?.contains(event.target as Node) && !trigger.current?.contains(event.target as Node)) setOpen(false); };
    const dismiss = () => setOpen(false);
    document.addEventListener('pointerdown', outside);
    window.addEventListener('resize', dismiss);
    // Scrolling a table/page can detach its trigger from a portalled menu.
    document.addEventListener('scroll', dismiss, true);
    return () => { document.removeEventListener('pointerdown', outside); window.removeEventListener('resize', dismiss); document.removeEventListener('scroll', dismiss, true); };
  }, [open]);

  return <>
    <button ref={trigger} type="button" aria-label={label} title={label} aria-haspopup="menu" aria-expanded={open} aria-controls={open ? id : undefined} onClick={() => setOpen(value => !value)} onKeyDown={event => { if (event.key === 'ArrowDown' || event.key === 'ArrowUp') { event.preventDefault(); setOpen(true); } }} className="inline-flex h-9 w-9 shrink-0 items-center justify-center rounded-lg border border-border text-hcl-muted hover:bg-surface-muted focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-hcl-blue/50"><MoreHorizontal className="h-4 w-4" /></button>
    {open && createPortal(<div ref={menu} id={id} role="menu" aria-label={label} style={position} className="fixed z-50 w-56 rounded-xl border border-border bg-surface p-1.5 shadow-lg" onKeyDown={event => {
      const items = focusItems(); const index = items.indexOf(document.activeElement as HTMLElement);
      if (event.key === 'Escape') { event.preventDefault(); event.stopPropagation(); close(true); }
      else if (event.key === 'Tab') { close(); }
      else if (['ArrowDown', 'ArrowUp', 'Home', 'End'].includes(event.key)) { event.preventDefault(); const next = event.key === 'Home' ? 0 : event.key === 'End' ? items.length - 1 : (index + (event.key === 'ArrowDown' ? 1 : -1) + items.length) % items.length; items[next]?.focus(); }
    }}>{actions.map((action, index) => <div key={action.label} className={action.destructive && index > 0 ? 'mt-1 border-t border-border pt-1' : ''}><ActionItem action={action} close={close} /></div>)}</div>, document.body)}
  </>;
}

function ActionItem({ action, close }: { action: InventoryAction; close: (restore?: boolean) => void }) {
  return action.permission ? <CheckedAction action={action} close={close} /> : <ActionContent action={action} close={close} />;
}
function CheckedAction({ action, close }: { action: InventoryAction; close: (restore?: boolean) => void }) {
  const { can, permissionsLoaded, pendingReason } = usePermissions();
  return <ActionContent action={action} close={close} denied={!(Array.isArray(action.permission) ? action.permission.every(can) : can(action.permission!))} reason={!permissionsLoaded ? pendingReason : action.disabledReason || permissionReason(Array.isArray(action.permission) ? action.permission.find(value => !can(value)) : action.permission)} />;
}
function ActionContent({ action, close, denied = false, reason }: { action: InventoryAction; close: (restore?: boolean) => void; denied?: boolean; reason?: string }) {
  const id = useId();
  const blocked = denied || action.disabled;
  const classes = `block w-full rounded-md px-3 py-2 text-left text-sm focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-hcl-blue/50 ${blocked ? 'cursor-not-allowed text-hcl-muted' : action.destructive ? 'text-red-700 hover:bg-red-50' : 'text-hcl-navy hover:bg-surface-muted'}`;
  return <div className="group/action relative">{action.href && !blocked ? <Link role="menuitem" aria-label={action.accessibleName} href={action.href} onClick={() => close()} className={classes}>{action.label}</Link> : <button type="button" role="menuitem" disabled={action.disabled && !denied} aria-label={action.accessibleName} aria-disabled={blocked || undefined} aria-describedby={denied ? id : undefined} onClick={event => { if (blocked) { event.preventDefault(); return; } close(true); action.onClick?.(); }} className={classes}>{action.label}</button>}
    {denied && <span id={id} role="tooltip" className="pointer-events-none absolute bottom-full left-0 mb-1 z-50 w-60 max-w-[70vw] rounded-lg border border-border bg-surface p-3 text-xs text-foreground shadow-lg opacity-0 group-hover/action:opacity-100 group-focus-within/action:opacity-100">{reason}</span>}
  </div>;
}

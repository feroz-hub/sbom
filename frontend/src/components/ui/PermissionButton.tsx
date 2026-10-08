'use client';

import { forwardRef, useId, useRef, useState, type ComponentProps, type ReactNode } from 'react';
import { createPortal } from 'react-dom';
import { Button } from './Button';
import { usePermissions } from '@/hooks/usePermission';
import { permissionReason } from '@/lib/permissionUi';

type Props = ComponentProps<typeof Button> & {
  permission?: string | string[];
  resourceAllowed?: boolean;
  disabledReason?: string;
};

/** Focusable explanation wraps a genuinely disabled button: clicks, Enter and Space cannot invoke it. */
export function PermissionExplanation({ reason, children }: { reason?: string; children: ReactNode }) {
  const id = useId();
  const anchor = useRef<HTMLSpanElement>(null);
  const [position, setPosition] = useState<{ top: number; left: number; above: boolean } | null>(null);
  const show = () => {
    if (!reason || !anchor.current) return;
    const rect = anchor.current.getBoundingClientRect();
    setPosition({ left: Math.max(8, Math.min(rect.left, window.innerWidth - 272)), top: rect.top > 120 ? rect.top - 8 : rect.bottom + 8, above: rect.top > 120 });
  };
  // Always retain the wrapper/child hierarchy so availability changes do not recreate the button.
  return <span ref={anchor} tabIndex={reason ? 0 : undefined} role={reason ? 'group' : undefined} aria-label={reason ? 'Action availability' : undefined} aria-describedby={reason ? id : undefined}
    onFocus={show} onBlur={() => setPosition(null)} onMouseEnter={show} onMouseLeave={() => setPosition(null)} onKeyDown={event => { if (event.key === 'Escape') setPosition(null); }}
    className={`relative inline-flex max-w-full rounded-lg focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-hcl-blue/50 ${reason ? 'cursor-not-allowed' : ''}`}>
    {children}
    {reason && <span id={id} className="sr-only">{reason}</span>}
    {reason && position && createPortal(<span role="tooltip" style={{ left: position.left, top: position.top, transform: position.above ? 'translateY(-100%)' : undefined }} className="pointer-events-none fixed z-[100] w-64 max-w-[85vw] rounded-lg border border-border bg-surface p-3 text-left text-xs font-normal text-foreground shadow-lg">{reason}</span>, document.body)}
  </span>;
}
const AuthorizedButton = forwardRef<HTMLButtonElement, Props>(function AuthorizedButton({ permission, resourceAllowed, disabledReason, ...props }, ref) {
  const { can, permissionsLoaded, pendingReason } = usePermissions();
  const permitted = permissionsLoaded && (!permission || (Array.isArray(permission) ? permission.every(can) : can(permission))) && resourceAllowed !== false;
  const reason = !permissionsLoaded ? pendingReason : !permitted ? (resourceAllowed === false ? disabledReason : undefined) || permissionReason(Array.isArray(permission) ? permission.find(value => !can(value)) : permission) : props.disabled ? disabledReason : undefined;
  const button = <Button {...props} ref={ref} disabled={props.disabled || !permitted} className={`${props.className || ''} ${!permitted ? 'disabled:!opacity-100 disabled:!bg-surface-muted disabled:!text-hcl-muted disabled:!border-border disabled:!shadow-none' : ''}`} />;
  return <PermissionExplanation reason={reason}>{button}</PermissionExplanation>;
});
export const PermissionButton = forwardRef<HTMLButtonElement, Props>(function PermissionButton(props, ref) {
  // Ordinary navigation/filter controls retain their behavior and do not require mutation authority.
  return props.permission || props.resourceAllowed !== undefined ? <AuthorizedButton {...props} ref={ref} /> : <Button {...props} ref={ref} />;
});

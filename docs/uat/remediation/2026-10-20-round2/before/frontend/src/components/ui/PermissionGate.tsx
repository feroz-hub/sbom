'use client';
import type { ReactNode, FormEvent } from 'react';
import Link from 'next/link';
import { usePathname } from 'next/navigation';
import { usePermissions } from '@/hooks/usePermission';
import { permissionReason, routePermissions } from '@/lib/permissionUi';
export function PermissionGate({ permission, children, fallback = null }: { permission: string; children: ReactNode; fallback?: ReactNode }) {
  return usePermissions().can(permission) ? children : fallback;
}
export function PermissionRouteGuard({ children }: { children: ReactNode }) {
  const pathname = usePathname();
  const { can, permissionsLoaded, pendingReason } = usePermissions();
  const required = routePermissions(pathname);
  if (!required) return children;
  if (!permissionsLoaded) return <p role="status" className="p-6 text-sm text-hcl-muted">{pendingReason}</p>;
  if (required.some(can)) return children;
  return <section className="m-6 rounded-xl border border-border bg-surface p-6"><h1 className="text-xl font-semibold">Access restricted</h1><p className="mt-2 text-sm text-hcl-muted">You don’t have permission to access this section.</p><Link href="/" className="mt-4 inline-block rounded text-sm font-medium text-hcl-blue focus-visible:ring-2">Back to Dashboard</Link></section>;
}
/** Disable fields before entry, and prevent implicit Enter submission, without hiding readable details. */
export function PermissionFields({ permission, resourceAllowed = true, reason, children }: { permission?: string | string[]; resourceAllowed?: boolean; reason?: string; children: ReactNode }) {
  const { can, permissionsLoaded, pendingReason } = usePermissions();
  const allowed = permissionsLoaded && (!permission || (Array.isArray(permission) ? permission.every(can) : can(permission))) && resourceAllowed;
  const block = (event: FormEvent) => { if (!allowed) { event.preventDefault(); event.stopPropagation(); } };
  return <div onSubmitCapture={block}>{!allowed && <p role="status" className="mb-3 text-sm text-hcl-muted">{!permissionsLoaded ? pendingReason : reason || permissionReason(Array.isArray(permission) ? permission.find(value => !can(value)) : permission)}</p>}<fieldset disabled={!allowed} className="min-w-0">{children}</fieldset></div>;
}

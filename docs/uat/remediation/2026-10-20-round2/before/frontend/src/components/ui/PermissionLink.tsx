'use client';
import Link from 'next/link';
import type { ComponentProps } from 'react';
import { usePermissions } from '@/hooks/usePermission';
import { permissionReason } from '@/lib/permissionUi';
import { PermissionExplanation } from './PermissionButton';
export function PermissionLink({ permission, ...props }: ComponentProps<typeof Link> & { permission: string }) {
  const { can, permissionsLoaded, pendingReason } = usePermissions();
  if (can(permission)) return <Link {...props} />;
  return <PermissionExplanation reason={permissionsLoaded ? permissionReason(permission) : pendingReason}><span aria-disabled="true" className="inline-flex items-center gap-2 rounded-lg border border-border bg-surface-muted px-4 py-2 text-sm font-medium text-hcl-muted">{props.children}</span></PermissionExplanation>;
}

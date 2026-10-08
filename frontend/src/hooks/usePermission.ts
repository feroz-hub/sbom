'use client';

import { useCallback } from 'react';
import { useAuth } from '@/hooks/useAuth';

/** Presentation only. The backend remains authoritative for every request. */
export function usePermissions() {
  const auth = useAuth();
  const permissionsLoaded = !auth.isLoading && !auth.isTenantContextLoading && !!auth.user && auth.bootstrapState !== 'error';
  const permissionError = auth.bootstrapState === 'error' ? auth.bootstrapError || 'Permission resolution failed' : null;
  const { hasPermission } = auth;
  const can = useCallback((permission: string) => permissionsLoaded && hasPermission(permission), [permissionsLoaded, hasPermission]);
  return { can, permissionsLoaded, permissionError, effectivePermissions: permissionsLoaded ? auth.user?.permissions ?? [] : [],
    pendingReason: permissionError ? 'Unable to verify access. Refresh your session and try again.' : 'Checking your permissions…' };
}
export function usePermission(permission: string): boolean { return usePermissions().can(permission); }
export function useAnyPermission(...permissions: string[]): boolean { const { can } = usePermissions(); return permissions.some(can); }

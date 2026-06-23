'use client';

import { useAuth } from '@/hooks/useAuth';

/** UX-only permission helper — backend enforces RBAC on every API call. */
export function usePermission(permission: string): boolean {
  const { hasPermission, isLoading } = useAuth();
  if (isLoading) return false;
  return hasPermission(permission);
}

export function useAnyPermission(...permissions: string[]): boolean {
  const { hasPermission, isLoading } = useAuth();
  if (isLoading) return false;
  return permissions.some((p) => hasPermission(p));
}

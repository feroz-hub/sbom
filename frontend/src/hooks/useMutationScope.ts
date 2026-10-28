'use client';
import { useCallback, useEffect, useRef } from 'react';
import { useAuth } from './useAuth';
import { getActiveTenantId } from '@/lib/auth';

/** Guard asynchronous writes against tenant changes, logout and unmount. */
export function useMutationScope() {
  const auth = useAuth();
  const key = `${auth.activeTenantId ?? auth.user?.tenantId ?? 'none'}:${auth.user?.userId ?? auth.user?.externalUserId ?? 'anonymous'}`;
  const ready = !!auth.user && !auth.isLoading && !auth.isTenantContextLoading && (auth.bootstrapState == null || auth.bootstrapState === 'ready');
  const generation = useRef({ key, ready, mounted: true });
  if (generation.current.key !== key || generation.current.ready !== ready) generation.current = { key, ready, mounted: true };
  useEffect(() => {
    const current = generation.current; current.mounted = true;
    return () => { current.mounted = false; };
  }, [key, ready]);
  const capture = useCallback(() => {
    const current = generation.current, tenant = getActiveTenantId();
    return () => current === generation.current && current.ready && current.mounted && getActiveTenantId() === tenant;
  }, []);
  return { key, ready, capture };
}

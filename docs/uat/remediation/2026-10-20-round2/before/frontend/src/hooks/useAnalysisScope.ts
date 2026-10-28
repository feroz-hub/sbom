'use client';
import { useCallback, useEffect, useRef, useMemo } from 'react';
import { useAuth } from './useAuth';
import { getActiveTenantId } from '@/lib/auth';

/** Captured generations prevent old callbacks from crossing auth changes, including logout/login to the same tenant. */
export function useAnalysisScope() {
  const auth = useAuth();
  const key = `${auth.activeTenantId ?? auth.user?.tenantId ?? 'none'}:${auth.user?.userId ?? auth.user?.externalUserId ?? 'anonymous'}`;
  const ready = !auth.isLoading && !auth.isTenantContextLoading && !!auth.user && auth.bootstrapState !== 'error';
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
  const canReadAnalysis = auth.hasPermission('analysis:read');
  return useMemo(() => ({ key, ready, capture, canReadAnalysis }), [key, ready, capture, canReadAnalysis]);
}

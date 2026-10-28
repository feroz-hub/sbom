'use client';
import { useEffect, useMemo } from 'react';
import { useQueryClient } from '@tanstack/react-query';
import { ANALYSIS_POLL_MS } from '@/lib/analysisSync';

// React Query owns the timer. Elect one observer per Query object, including staggered mounts.
const owners = new WeakMap<object, { active: boolean }>();
export function useSharedAnalysisPolling(queryKey: readonly unknown[], enabled: boolean) {
  const qc = useQueryClient(), identity = JSON.stringify(queryKey);
  const token = useMemo(() => ({ active: true, identity, enabled }), [identity, enabled]);
  useEffect(() => {
    token.active = true;
    return () => {
      token.active = false;
      const query = qc.getQueryCache().find({ queryKey: JSON.parse(identity), exact: true });
      if (query && owners.get(query) === token) {
        owners.delete(query);
        query.invalidate(); // Notify remaining observers to take ownership; does not issue a fetch.
      }
    };
  }, [qc, identity, token]);
  return (query: object) => {
    if (!enabled || !token.active) return false;
    const owner = owners.get(query);
    if (!owner?.active) owners.set(query, token);
    return owners.get(query) === token ? ANALYSIS_POLL_MS : false;
  };
}

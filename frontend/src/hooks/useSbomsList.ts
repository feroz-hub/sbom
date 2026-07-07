'use client';

import { useQuery } from '@tanstack/react-query';
import { getSboms } from '@/lib/api';

/** Single list fetch size so Analysis, SBOMs table, and upload dup-check share one React Query cache. */
export const SBOMS_LIST_PAGE_SIZE = 500;
const ACTIVE_ANALYSIS_RESULTS = new Set(['queued', 'running']);
const ACTIVE_ANALYSIS_STATUSES = new Set(['PENDING', 'QUEUED', 'RUNNING', 'ANALYSING', 'ANALYZING']);

export function useSbomsList(options?: { enabled?: boolean }) {
  return useQuery({
    queryKey: ['sboms'],
    queryFn: ({ signal }) => getSboms(1, SBOMS_LIST_PAGE_SIZE, signal),
    refetchInterval: (query) => {
      const rows = query.state.data ?? [];
      return rows.some((sbom) => {
        const latest = sbom.latest_analysis;
        if (!latest) return false;
        return (
          ACTIVE_ANALYSIS_RESULTS.has(String(latest.result ?? '').toLowerCase()) ||
          ACTIVE_ANALYSIS_STATUSES.has(String(latest.status ?? '').toUpperCase())
        );
      })
        ? 3000
        : false;
    },
    refetchOnWindowFocus: true,
    ...options,
  });
}

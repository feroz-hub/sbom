'use client';
import { useEffect, useRef } from 'react';
import { useQuery, useQueryClient } from '@tanstack/react-query';
import { getSboms, type DashboardFilterScope } from '@/lib/api';
import { isActiveAnalysis, reconcileAnalysisTerminal } from '@/lib/analysisSync';
import { useAnalysisScope } from './useAnalysisScope';
import { useSharedAnalysisPolling } from './useSharedAnalysisPolling';
import { usePendingAnalysisRecovery } from './usePendingAnalysisRecovery';
export const SBOMS_LIST_PAGE_SIZE = 500;
export function useSbomsList(options?: { enabled?: boolean; scope?: DashboardFilterScope; analysed?: boolean }) {
  const qc = useQueryClient(), auth = useAnalysisScope();
  const scope = options?.scope, enabled = options?.enabled ?? true;
  usePendingAnalysisRecovery(enabled);
  const queryKey = scope ? ['sboms', 'dashboard-scope', scope.projectId, scope.applicationId, scope.sbomId, !!options?.analysed] : ['sboms'];
  const poll = useSharedAnalysisPolling(queryKey, enabled);
  const query = useQuery({
    queryKey,
    queryFn: ({ signal }) => scope ? getSboms(1, SBOMS_LIST_PAGE_SIZE, signal, scope, options?.analysed) : getSboms(1, SBOMS_LIST_PAGE_SIZE, signal),
    enabled,
    refetchInterval: query => query.state.data?.some(row => isActiveAnalysis(row.latest_analysis?.status) || isActiveAnalysis(row._analysisStatus) || ['queued', 'running'].includes(row.latest_analysis?.result ?? '')) ? poll(query) : false,
    refetchOnWindowFocus: true,
  });
  const previous = useRef(new Map<string, { runId: string; status: string }>());
  useEffect(() => {
    for (const row of query.data ?? []) {
      const latest = row.latest_analysis; if (!latest?.run_id) continue;
      const key = `${auth.key}:${row.id}`, before = previous.current.get(key);
      previous.current.set(key, { runId: String(latest.run_id), status: latest.status });
      if (before && isActiveAnalysis(before.status) && auth.canReadAnalysis) {
        void reconcileAnalysisTerminal(qc, { scope: auth.key, runId: String(latest.run_id), sbomId: row.id,
          status: latest.status, previousStatus: before.status, isCurrent: auth.capture() });
      }
    }
  }, [query.data, qc, auth]);
  return query;
}

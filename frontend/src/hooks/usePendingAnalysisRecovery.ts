'use client';
import { useEffect } from 'react';
import { useQuery, useQueryClient } from '@tanstack/react-query';
import { getRuns } from '@/lib/api';
import { isActiveAnalysis, isTerminalAnalysis, reconcileAnalysisTerminal } from '@/lib/analysisSync';
import { addPendingAnalysis, clearStalePendingAnalyses, getStillPendingAnalyses, pendingAnalysisExpired, removePendingAnalysis } from '@/lib/pendingAnalysis';
import { invalidateSbomLists } from '@/lib/queryInvalidation';
import type { SBOMSource } from '@/types';
import { useSharedAnalysisPolling } from './useSharedAnalysisPolling';
import { useAnalysisScope } from './useAnalysisScope';

export function usePendingAnalysisRecovery(enabled = true) {
  const qc = useQueryClient(), scope = useAnalysisScope();
  const pending = getStillPendingAnalyses(scope.key);
  const identity = pending.map(entry => `${entry.sbomId}:${entry.startedAt}`).sort().join(',');
  const queryKey = ['pending-analysis-recovery', scope.key, identity];
  const recover = enabled && scope.ready && scope.canReadAnalysis && pending.length > 0;
  const poll = useSharedAnalysisPolling(queryKey, recover);
  const recovery = useQuery({
    queryKey,
    enabled: recover,
    staleTime: 0, retry: false,
    queryFn: async ({ signal }) => {
      const isCurrent = scope.capture();
      return Promise.all(getStillPendingAnalyses(scope.key).map(async entry => {
        try {
          const runs = await getRuns({ sbom_id: entry.sbomId, page: 1, page_size: 1 }, signal);
          const run = runs[0];
          // Never confuse a previous completed run with this pending submission.
          const started = Date.parse(run?.started_on ?? '');
          const matches = run && (entry.runId ? run.id === entry.runId : Number.isFinite(started) && started >= entry.startedAt - 1000);
          return { entry, run: matches ? run : undefined, isCurrent };
        } catch { return { entry, run: undefined, isCurrent }; }
      }));
    },
    refetchInterval: query => getStillPendingAnalyses(scope.key).length > 0 && query.state.data?.some(item => !item.run || isActiveAnalysis(item.run.run_status)) ? poll(query) : false,
  });
  useEffect(() => {
    clearStalePendingAnalyses();
    for (const item of recovery.data ?? []) {
      const { entry, run, isCurrent } = item;
      if (!isCurrent()) continue;
      if (run && isActiveAnalysis(run.run_status)) {
        addPendingAnalysis(entry.sbomId, entry.sbomName, scope.key, run.id);
        const outdated = qc.getQueriesData<SBOMSource[]>({ queryKey: ['sboms'] }).some(([, rows]) => rows?.some(row => row.id === entry.sbomId && (row.latest_analysis?.run_id !== run.id || !isActiveAnalysis(row.latest_analysis?.status))));
        if (outdated) void invalidateSbomLists(qc);
      }
      else if (run && isTerminalAnalysis(run.run_status)) {
        void reconcileAnalysisTerminal(qc, { scope: scope.key, runId: run.id, sbomId: entry.sbomId, status: run.run_status, isCurrent });
        removePendingAnalysis(entry.sbomId, scope.key);
      } else if (pendingAnalysisExpired(entry)) removePendingAnalysis(entry.sbomId, scope.key);
    }
  }, [recovery.data, qc, scope.key]);
}

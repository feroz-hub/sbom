'use client';

import { useCallback, useRef } from 'react';
import { useRouter } from 'next/navigation';
import { useQueryClient } from '@tanstack/react-query';
import { analyzeSbom } from '@/lib/api';
import { useToast } from '@/hooks/useToast';
import { addPendingAnalysis, removePendingAnalysis } from '@/lib/pendingAnalysis';
import { invalidateAnalysisSubmission } from '@/lib/queryInvalidation';
import { reconcileAnalysisTerminal, isTerminalAnalysis, isActiveAnalysis } from '@/lib/analysisSync';
import { useAnalysisScope } from './useAnalysisScope';
import type { SBOMSource } from '@/types';

// ADR-0001 — canonical names + legacy aliases (deprecation window).
export type AnalysisStatus =
  | 'ANALYSING'
  | 'PENDING'
  | 'QUEUED'
  | 'RUNNING'
  | 'OK'
  | 'FINDINGS'
  | 'PARTIAL'
  | 'ERROR'
  | 'CANCELLED'
  | 'INTERRUPTED'
  | 'NOT_ANALYSED'
  | 'PASS' // legacy alias for OK
  | 'FAIL'; // legacy alias for FINDINGS

/**
 * Provides `triggerBackgroundAnalysis(sbomId, sbomName)`.
 *
 * - Fires analysis without blocking the caller (no await needed)
 * - Updates the React Query SBOM cache optimistically
 * - Shows a loading → success/error toast with action button
 * - Persists pending state to sessionStorage for refresh recovery
 */
export function useBackgroundAnalysis() {
  const { showToast, updateToast } = useToast();
  const router = useRouter();
  const queryClient = useQueryClient();
  const scope = useAnalysisScope();

  const triggerRef = useRef<((sbomId: number, sbomName: string) => void) | null>(null);

  const triggerBackgroundAnalysis = useCallback(
    (sbomId: number, sbomName: string) => {
      if (!scope.ready) return;
      const isCurrent = scope.capture();
      removePendingAnalysis(sbomId, scope.key);
      addPendingAnalysis(sbomId, sbomName, scope.key);
      queryClient.setQueriesData<SBOMSource[]>({ queryKey: ['sboms'] }, (old) =>
        old?.map((s) =>
          s.id === sbomId
            ? {
                ...s,
                _analysisStatus: 'ANALYSING',
                _findingsCount: undefined,
                latest_analysis: {
                  run_id: s.latest_analysis?.run_id ?? 0,
                  status: 'RUNNING',
                  result: 'running',
                  finding_count: s.latest_analysis?.finding_count ?? 0,
                  critical_count: s.latest_analysis?.critical_count ?? 0,
                  high_count: s.latest_analysis?.high_count ?? 0,
                  medium_count: s.latest_analysis?.medium_count ?? 0,
                  low_count: s.latest_analysis?.low_count ?? 0,
                  risk_score: s.latest_analysis?.risk_score ?? null,
                  risk_level: s.latest_analysis?.risk_level ?? null,
                  started_at: new Date().toISOString(),
                  completed_at: null,
                  error_message: null,
                },
              }
            : s,
        ) ?? [],
      );


      const toastId = showToast(`Analysing "${sbomName}"…`, 'loading', {
        id: `analysis-${sbomId}`,
        duration: 0,
      });

      analyzeSbom(sbomId)
        .then((result) => {
          if (!isCurrent()) return;
          const status = result.run_status;
          const raw = result as unknown as Record<string, unknown>;
          const runId = Number(raw.runId ?? raw.run_id ?? raw.id);
          const total = result.total_findings ?? Number((raw.summary as { findings?: { total?: number } })?.findings?.total ?? 0);
          if (isActiveAnalysis(status)) {
            addPendingAnalysis(sbomId, sbomName, scope.key, runId || undefined);
            void invalidateAnalysisSubmission(queryClient);
            return;
          }
          if (!isTerminalAnalysis(status) || !runId) return;
          removePendingAnalysis(sbomId, scope.key);
          void reconcileAnalysisTerminal(queryClient, { scope: scope.key, sbomId, runId, status, isCurrent });

          updateToast(
            toastId,
            ['ERROR', 'INTERRUPTED', 'CANCELLED'].includes(status) ? `Analysis stopped · ${status}` : `Analysis complete · ${total} finding${total !== 1 ? 's' : ''}`,
            ['ERROR', 'INTERRUPTED', 'CANCELLED'].includes(status) ? 'error' : 'success',
            {
              duration: 8000,
              action: {
                label: 'View Results',
                onClick: () => router.push(`/sboms/${sbomId}`),
              },
            },
          );
        })
        .catch(() => {
          if (!isCurrent()) return;
          // A transport failure does not prove the server job failed. Recovery retains its marker.
          void invalidateAnalysisSubmission(queryClient);

          updateToast(toastId, `Analysis failed for "${sbomName}"`, 'error', {
            duration: 0,
            action: {
              label: 'Retry',
              onClick: () => triggerRef.current?.(sbomId, sbomName),
            },
          });
        });
    },
    [showToast, updateToast, router, queryClient, scope],
  );

  triggerRef.current = triggerBackgroundAnalysis;

  return { triggerBackgroundAnalysis };
}

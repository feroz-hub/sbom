'use client';

import { useEffect } from 'react';
import { useQueryClient } from '@tanstack/react-query';
import { getRuns } from '@/lib/api';
import { getStillPendingAnalyses, removePendingAnalysis } from '@/lib/pendingAnalysis';
import type { AnalysisStatus } from '@/hooks/useBackgroundAnalysis';
import type { SBOMSource } from '@/types';

function runStatusToBadgeStatus(runStatus: string | undefined): AnalysisStatus {
  const u = (runStatus ?? 'ERROR').toUpperCase();
  if (u === 'RUNNING' || u === 'PENDING') return 'ANALYSING';
  const allowed: AnalysisStatus[] = ['PASS', 'FAIL', 'PARTIAL', 'ERROR'];
  return allowed.includes(u as AnalysisStatus) ? (u as AnalysisStatus) : 'ERROR';
}

/**
 * On mount, checks sessionStorage for any analysis jobs that were in-flight
 * before a page refresh. For each:
 *   - If the server already has a completed run → update React Query SBOM cache
 *   - If no run found yet → re-trigger background analysis (resumes waiting)
 */
export function usePendingAnalysisRecovery(
  triggerBackgroundAnalysis: (sbomId: number, sbomName: string) => void,
) {
  const queryClient = useQueryClient();

  useEffect(() => {
    const pending = getStillPendingAnalyses();
    if (pending.length === 0) return;

    for (const { sbomId, sbomName } of pending) {
      getRuns({ sbom_id: sbomId, page: 1, page_size: 1 })
        .then((runs) => {
          if (runs.length > 0) {
            const run = runs[0];
            removePendingAnalysis(sbomId);
            queryClient.setQueryData<SBOMSource[]>(['sboms'], (old) =>
              old?.map((s) =>
                s.id === sbomId
                  ? {
                      ...s,
                      _analysisStatus: runStatusToBadgeStatus(run.run_status),
                      _findingsCount: run.total_findings ?? 0,
                    }
                  : s,
              ) ?? [],
            );
          } else {
            triggerBackgroundAnalysis(sbomId, sbomName);
          }
        })
        .catch(() => {
          removePendingAnalysis(sbomId);
          queryClient.setQueryData<SBOMSource[]>(['sboms'], (old) =>
            old?.map((s) =>
              s.id === sbomId ? { ...s, _analysisStatus: 'ERROR', _findingsCount: undefined } : s,
            ) ?? [],
          );
        });
    }
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, []);
}

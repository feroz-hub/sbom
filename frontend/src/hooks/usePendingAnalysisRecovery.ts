'use client';

import { useEffect } from 'react';
import { getRuns } from '@/lib/api';
import { getStillPendingAnalyses, removePendingAnalysis } from '@/lib/pendingAnalysis';
import { dispatchSbomStatus } from '@/hooks/useBackgroundAnalysis';
import type { AnalysisStatus } from '@/hooks/useBackgroundAnalysis';

/**
 * On mount, checks sessionStorage for any analysis jobs that were in-flight
 * before a page refresh. For each:
 *   - If the server already has a completed run → dispatch the final status
 *   - If no run found yet → re-trigger background analysis (resumes waiting)
 */
export function usePendingAnalysisRecovery(
  triggerBackgroundAnalysis: (sbomId: number, sbomName: string) => void,
) {
  useEffect(() => {
    const pending = getStillPendingAnalyses();
    if (pending.length === 0) return;

    for (const { sbomId, sbomName } of pending) {
      getRuns({ sbom_id: sbomId, page: 1, page_size: 1 })
        .then((runs) => {
          if (runs.length > 0) {
            // Analysis finished while page was reloading
            const run = runs[0];
            removePendingAnalysis(sbomId);
            dispatchSbomStatus(
              sbomId,
              (run.run_status ?? 'UNKNOWN').toUpperCase() as AnalysisStatus,
              run.total_findings ?? 0,
            );
          } else {
            // Analysis still pending — re-trigger so user gets toasts + status
            triggerBackgroundAnalysis(sbomId, sbomName);
          }
        })
        .catch(() => {
          removePendingAnalysis(sbomId);
          dispatchSbomStatus(sbomId, 'ERROR');
        });
    }
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, []); // run once on mount only
}

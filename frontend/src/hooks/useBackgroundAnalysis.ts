'use client';

import { useCallback, useRef } from 'react';
import { useRouter } from 'next/navigation';
import { useQueryClient } from '@tanstack/react-query';
import { analyzeConsolidated } from '@/lib/api';
import { useToast } from '@/hooks/useToast';
import { addPendingAnalysis, removePendingAnalysis } from '@/lib/pendingAnalysis';
import type { SBOMSource } from '@/types';

export type AnalysisStatus = 'ANALYSING' | 'PASS' | 'FAIL' | 'PARTIAL' | 'ERROR' | 'NOT_ANALYSED';

/** Broadcast an analysis status change to all SbomStatusBadge instances. */
export function dispatchSbomStatus(sbomId: number, status: AnalysisStatus, findingsCount?: number) {
  if (typeof window === 'undefined') return;
  window.dispatchEvent(
    new CustomEvent('sbom-analysis-update', {
      detail: { sbomId, status, findingsCount },
    }),
  );
}

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

  // Use a ref so the retry closure can call the latest version without stale captures
  const triggerRef = useRef<(sbomId: number, sbomName: string) => void>();

  const triggerBackgroundAnalysis = useCallback(
    (sbomId: number, sbomName: string) => {
      // 1. Mark ANALYSING in React Query cache
      queryClient.setQueryData<SBOMSource[]>(['sboms'], (old) =>
        old?.map((s) =>
          s.id === sbomId ? { ...s, _analysisStatus: 'ANALYSING', _findingsCount: undefined } : s,
        ) ?? [],
      );

      // 2. Broadcast via CustomEvent (SbomStatusBadge components subscribe)
      dispatchSbomStatus(sbomId, 'ANALYSING');

      // 3. Persist to sessionStorage (survives page refresh)
      addPendingAnalysis(sbomId, sbomName);

      // 4. Loading toast — persists until analysis resolves
      const toastId = showToast(`Analysing "${sbomName}"…`, 'loading', {
        id: `analysis-${sbomId}`,
        duration: 0,
      });

      // 5. Fire analysis — intentionally not awaited
      analyzeConsolidated({ sbom_id: sbomId, sbom_name: sbomName })
        .then((result) => {
          removePendingAnalysis(sbomId);

          // Backend returns summary.findings.total or top-level total_findings
          const raw = result as Record<string, unknown>;
          const total: number =
            (raw.summary as Record<string, unknown> | undefined)?.findings != null
              ? ((raw.summary as Record<string, Record<string, unknown>>).findings.total as number) ?? 0
              : (result.total_findings ?? 0);

          const status = ((result.status as string) ?? 'UNKNOWN').toUpperCase() as AnalysisStatus;

          // Update cache with final status + count
          queryClient.setQueryData<SBOMSource[]>(['sboms'], (old) =>
            old?.map((s) =>
              s.id === sbomId
                ? { ...s, _analysisStatus: status, _findingsCount: total }
                : s,
            ) ?? [],
          );

          dispatchSbomStatus(sbomId, status, total);

          // Invalidate runs list so analysis page shows the new run
          queryClient.invalidateQueries({ queryKey: ['runs'] });

          updateToast(
            toastId,
            `Analysis complete · ${total} finding${total !== 1 ? 's' : ''}`,
            'success',
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
          removePendingAnalysis(sbomId);

          queryClient.setQueryData<SBOMSource[]>(['sboms'], (old) =>
            old?.map((s) =>
              s.id === sbomId ? { ...s, _analysisStatus: 'ERROR', _findingsCount: undefined } : s,
            ) ?? [],
          );

          dispatchSbomStatus(sbomId, 'ERROR');

          updateToast(toastId, `Analysis failed for "${sbomName}"`, 'error', {
            duration: 0,
            action: {
              label: 'Retry',
              onClick: () => triggerRef.current?.(sbomId, sbomName),
            },
          });
        });
    },
    [showToast, updateToast, router, queryClient],
  );

  // Keep ref in sync so retry closure always calls the latest version
  triggerRef.current = triggerBackgroundAnalysis;

  return { triggerBackgroundAnalysis };
}

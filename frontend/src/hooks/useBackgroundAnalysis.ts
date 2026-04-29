'use client';

import { useCallback, useRef } from 'react';
import { useRouter } from 'next/navigation';
import { useQueryClient } from '@tanstack/react-query';
import { analyzeConsolidated } from '@/lib/api';
import { useToast } from '@/hooks/useToast';
import { addPendingAnalysis, removePendingAnalysis } from '@/lib/pendingAnalysis';
import type { SBOMSource } from '@/types';

export type AnalysisStatus =
  | 'ANALYSING'
  | 'PASS'
  | 'FAIL'
  | 'PARTIAL'
  | 'ERROR'
  | 'NOT_ANALYSED';

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

  const triggerRef = useRef<(sbomId: number, sbomName: string) => void>();

  const triggerBackgroundAnalysis = useCallback(
    (sbomId: number, sbomName: string) => {
      queryClient.setQueryData<SBOMSource[]>(['sboms'], (old) =>
        old?.map((s) =>
          s.id === sbomId ? { ...s, _analysisStatus: 'ANALYSING', _findingsCount: undefined } : s,
        ) ?? [],
      );

      addPendingAnalysis(sbomId, sbomName);

      const toastId = showToast(`Analysing "${sbomName}"…`, 'loading', {
        id: `analysis-${sbomId}`,
        duration: 0,
      });

      analyzeConsolidated({ sbom_id: sbomId, sbom_name: sbomName })
        .then((result) => {
          removePendingAnalysis(sbomId);

          const raw = result as Record<string, unknown>;
          const total: number =
            (raw.summary as Record<string, unknown> | undefined)?.findings != null
              ? ((raw.summary as Record<string, Record<string, unknown>>).findings.total as number) ?? 0
              : (result.total_findings ?? 0);

          const status = ((result.status as string) ?? 'UNKNOWN').toUpperCase() as AnalysisStatus;

          queryClient.setQueryData<SBOMSource[]>(['sboms'], (old) =>
            old?.map((s) =>
              s.id === sbomId ? { ...s, _analysisStatus: status, _findingsCount: total } : s,
            ) ?? [],
          );

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

  triggerRef.current = triggerBackgroundAnalysis;

  return { triggerBackgroundAnalysis };
}

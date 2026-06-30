'use client';

import { useCallback, useRef } from 'react';
import { useRouter } from 'next/navigation';
import { useQueryClient } from '@tanstack/react-query';
import { analyzeConsolidated } from '@/lib/api';
import { useToast } from '@/hooks/useToast';
import { addPendingAnalysis, removePendingAnalysis } from '@/lib/pendingAnalysis';
import { invalidateAnalysisCompletion } from '@/lib/queryInvalidation';
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

  const triggerRef = useRef<(sbomId: number, sbomName: string) => void>();

  const triggerBackgroundAnalysis = useCallback(
    (sbomId: number, sbomName: string) => {
      queryClient.setQueryData<SBOMSource[]>(['sboms'], (old) =>
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
                  finding_count: 0,
                  critical_count: 0,
                  high_count: 0,
                  medium_count: 0,
                  low_count: 0,
                  risk_score: null,
                  risk_level: null,
                  started_at: new Date().toISOString(),
                  completed_at: null,
                  error_message: null,
                },
              }
            : s,
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
              s.id === sbomId
                ? {
                    ...s,
                    _analysisStatus: status,
                    _findingsCount: total,
                    latest_analysis: {
                      run_id: Number(raw.run_id ?? s.latest_analysis?.run_id ?? 0),
                      status,
                      result: status === 'ERROR' ? 'failed' : 'completed',
                      finding_count: total,
                      critical_count: Number(raw.critical_count ?? raw.critical ?? s.latest_analysis?.critical_count ?? 0),
                      high_count: Number(raw.high_count ?? raw.high ?? s.latest_analysis?.high_count ?? 0),
                      medium_count: Number(raw.medium_count ?? raw.medium ?? s.latest_analysis?.medium_count ?? 0),
                      low_count: Number(raw.low_count ?? raw.low ?? s.latest_analysis?.low_count ?? 0),
                      risk_score: s.latest_analysis?.risk_score ?? null,
                      risk_level: s.latest_analysis?.risk_level ?? null,
                      started_at: String(raw.started_on ?? raw.started_at ?? s.latest_analysis?.started_at ?? ''),
                      completed_at: String(raw.completed_on ?? raw.completed_at ?? new Date().toISOString()),
                      error_message: null,
                    },
                  }
                : s,
            ) ?? [],
          );

          // Run lists, dashboard tiles, recents, per-SBOM detail — every
          // surface whose numbers just changed.
          invalidateAnalysisCompletion(queryClient, { sbomId });

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
              s.id === sbomId
                ? {
                    ...s,
                    _analysisStatus: 'ERROR',
                    _findingsCount: undefined,
                    latest_analysis: {
                      run_id: s.latest_analysis?.run_id ?? 0,
                      status: 'ERROR',
                      result: 'failed',
                      finding_count: s.latest_analysis?.finding_count ?? 0,
                      critical_count: s.latest_analysis?.critical_count ?? 0,
                      high_count: s.latest_analysis?.high_count ?? 0,
                      medium_count: s.latest_analysis?.medium_count ?? 0,
                      low_count: s.latest_analysis?.low_count ?? 0,
                      risk_score: s.latest_analysis?.risk_score ?? null,
                      risk_level: s.latest_analysis?.risk_level ?? null,
                      started_at: s.latest_analysis?.started_at ?? null,
                      completed_at: new Date().toISOString(),
                      error_message: 'Analysis failed.',
                    },
                  }
                : s,
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

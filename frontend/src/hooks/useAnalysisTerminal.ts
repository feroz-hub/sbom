'use client';
import { useEffect, useRef } from 'react';
import { useQueryClient } from '@tanstack/react-query';
import { reconcileAnalysisTerminal } from '@/lib/analysisSync';
import { useAnalysisScope } from './useAnalysisScope';
export function useAnalysisTerminal(run?: { id: number; sbom_id: number | null; run_status: string }) {
  const qc = useQueryClient(), scope = useAnalysisScope();
  const previous = useRef(new Map<string, string>());
  const id = run?.id, sbomId = run?.sbom_id, status = run?.run_status;
  useEffect(() => {
    if (!id || !status || !scope.ready || !scope.canReadAnalysis) return;
    const key = `${scope.key}:${id}`, previousStatus = previous.current.get(key);
    previous.current.set(key, status);
    void reconcileAnalysisTerminal(qc, { scope: scope.key, runId: id, sbomId: sbomId ?? undefined,
      status, previousStatus, isCurrent: scope.capture() });
  }, [qc, id, sbomId, status, scope]);
}

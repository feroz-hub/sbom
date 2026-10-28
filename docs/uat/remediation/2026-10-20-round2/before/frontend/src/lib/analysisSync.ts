import type { QueryClient } from '@tanstack/react-query';
import { canonicalRunStatus } from './analysisRunStatusLabels';
import { invalidateAnalysisCompletion } from './queryInvalidation';
export const ANALYSIS_POLL_MS = 3000;
export const isActiveAnalysis = (status?: string | null) => ['PENDING', 'QUEUED', 'RUNNING', 'ANALYSING', 'ANALYZING'].includes(canonicalRunStatus(status));
export const isTerminalAnalysis = (status?: string | null) => ['OK', 'FINDINGS', 'PARTIAL', 'ERROR', 'INTERRUPTED', 'NO_DATA', 'CANCELLED'].includes(canonicalRunStatus(status));

/** Bookkeeping lives in QueryClient so logout/tenant cache clearing also resets deduplication. */
export async function reconcileAnalysisTerminal(qc: QueryClient, args: {
  scope: string; runId: number; sbomId?: (string | number); status: string; previousStatus?: string;
  isCurrent: () => boolean;
}): Promise<boolean> {
  if (!args.isCurrent() || !Number.isSafeInteger(args.runId) || args.runId <= 0 || !isTerminalAnalysis(args.status)) return false;
  if (args.previousStatus && !isActiveAnalysis(args.previousStatus) && !isTerminalAnalysis(args.previousStatus)) return false;
  const status = canonicalRunStatus(args.status);
  const key = ['analysis-terminal-sync', args.scope, args.runId];
  if (qc.getQueryData(key) === status) return false;
  qc.setQueryData(key, status);
  await invalidateAnalysisCompletion(qc, { runId: args.runId, sbomId: args.sbomId });
  return true;
}

import type { QueryClient } from '@tanstack/react-query';
import type { AiBatchProgress } from '@/types/ai';
import { invalidateAiBatchSurfaces } from './queryInvalidation';

/** Budget halt is final only when the worker has persisted its completion time. */
export function isAiBatchTerminal(progress: AiBatchProgress): boolean {
  return ['complete', 'failed', 'cancelled'].includes(progress.status)
    || (progress.status === 'paused_budget' && progress.finished_at != null);
}

export async function reconcileAiBatchTerminal(qc: QueryClient, args: {
  progress: AiBatchProgress; scope: string; batchId?: string | null; isCurrent: () => boolean;
}): Promise<boolean> {
  const { progress: p } = args;
  if (!args.isCurrent() || !Number.isInteger(p.run_id) || p.run_id <= 0 || !isAiBatchTerminal(p)) return false;
  if (args.batchId != null && p.batch_id != null && args.batchId !== p.batch_id) return false;
  const batch = p.batch_id ?? args.batchId ?? `legacy:${p.started_at ?? 'unknown'}`;
  const key = ['ai-batch-terminal-sync', args.scope, p.run_id, batch];
  // Later persisted partial results/status changes are distinct observations.
  const fingerprint = JSON.stringify([p.status, p.generated, p.from_cache, p.failed, p.cost_so_far_usd, p.finished_at, p.last_error]);
  if (qc.getQueryData(key) === fingerprint) return false;
  qc.setQueryData(key, fingerprint);
  await invalidateAiBatchSurfaces(qc, p.run_id, { results: true });
  return true;
}

/** A successful cancel POST is an acknowledgment, not a terminal progress envelope. */
export async function invalidateAiBatchCancellation(qc: QueryClient, args: {
  scope: string; runId: number; batchId: string | null; isCurrent: () => boolean;
}): Promise<void> {
  if (!args.isCurrent()) return;
  const batch = args.batchId ?? qc.getQueryData<AiBatchProgress>(['ai-batch-progress', args.runId])?.started_at ?? 'legacy';
  const key = ['ai-batch-cancel-sync', args.scope, args.runId, batch];
  if (qc.getQueryData(key)) return;
  qc.setQueryData(key, true);
  await invalidateAiBatchSurfaces(qc, args.runId, { results: true });
}

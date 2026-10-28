import { QueryClient, QueryObserver } from '@tanstack/react-query';
import { describe, expect, it, vi } from 'vitest';
import { reconcileAiBatchTerminal, invalidateAiBatchCancellation } from './aiBatchSync';
import { invalidateAiBatchSurfaces } from './queryInvalidation';
import { makeBatchProgress } from '@/components/ai-fixes/__tests__/test-utils';
const client = () => new QueryClient({ defaultOptions: { queries: { staleTime: 300000, refetchOnWindowFocus: false, retry: false } } });
const progress = makeBatchProgress({ run_id: 42, batch_id: 'batch-a', status: 'complete', finished_at: '2026-10-09', generated: 2 });
const keys = [['ai-fix-list', 42], ['ai-fix', 10, null], ['ai-fix', 10, 'other-provider'], ['ai-batch-progress', 42], ['ai-batch-progress', 42, 'batch-a'], ['ai-batch-list', 42], ['ai-settings', 'usage'], ['ai-usage-trend', 30], ['ai-top-cached', 20]];
function observe(qc: QueryClient) {
  const fetchers = keys.map(() => vi.fn().mockResolvedValue('authoritative partial output'));
  const stops = keys.map((queryKey, i) => { qc.setQueryData(queryKey, 'before'); return new QueryObserver(qc, { queryKey, queryFn: fetchers[i] }).subscribe(() => {}); });
  return { fetchers, stop: () => { stops.forEach(stop => stop()); qc.clear(); } };
}
describe('AI terminal reconciliation', () => {
  it.each(['complete', 'failed', 'cancelled', 'paused_budget'] as const)('%s refreshes server output/history/usage, including partial fixes', async status => {
    const qc = client(); const { fetchers, stop } = observe(qc);
    qc.setQueryData(['ai-fix-list', 99], 'other run'); qc.setQueryData(['ai-batch-progress', 99], 'other run'); qc.setQueryData(['vex-run-snapshot', 42], 'immutable'); qc.setQueryData(['ai-settings', 'providers'], 'config');
    await reconcileAiBatchTerminal(qc, { progress: { ...progress, status }, scope: 'tenant:user', isCurrent: () => true });
    keys.forEach((key, i) => { expect(qc.getQueryData(key)).toBe('authoritative partial output'); expect(fetchers[i]).toHaveBeenCalledTimes(1); });
    for (const key of [['ai-fix-list', 99], ['ai-batch-progress', 99], ['vex-run-snapshot', 42], ['ai-settings', 'providers']]) expect(qc.getQueryState(key)?.isInvalidated).toBe(false);
    stop();
  });
  it.each(['pending', 'queued', 'in_progress', 'paused_budget'] as const)('never infers completion from counters for active %s', async status => {
    const qc = client(); qc.setQueryData(['ai-fix-list', 42], []);
    expect(await reconcileAiBatchTerminal(qc, { progress: { ...progress, status, remaining: 0, finished_at: null }, scope: 't:u', isCurrent: () => true })).toBe(false);
    expect(qc.getQueryState(['ai-fix-list', 42])?.isInvalidated).toBe(false); qc.clear();
  });
  it('deduplicates repeated transports, but allows two batches and later persisted result changes', async () => {
    const qc = client(); const { fetchers, stop } = observe(qc);
    const reconcile = (p = progress) => reconcileAiBatchTerminal(qc, { progress: p, scope: 't:u', isCurrent: () => true });
    await Promise.all([reconcile(), reconcile(), reconcile()]);
    expect(fetchers[0]).toHaveBeenCalledTimes(1);
    await reconcile(); expect(fetchers[0]).toHaveBeenCalledTimes(1);
    await reconcile({ ...progress, batch_id: 'batch-b' }); expect(fetchers[0]).toHaveBeenCalledTimes(2);
    await reconcile({ ...progress, generated: 3 }); expect(fetchers[0]).toHaveBeenCalledTimes(3); stop();
  });
  it('cleared context bookkeeping permits later work and rejects old callbacks/mismatched batch identities', async () => {
    const qc = client(); const run = (isCurrent: boolean, batchId = 'batch-a') => reconcileAiBatchTerminal(qc, { progress, scope: 't:u', batchId, isCurrent: () => isCurrent });
    expect(await run(false)).toBe(false); expect(await run(true, 'another-batch')).toBe(false); expect(qc.getQueryCache().getAll()).toHaveLength(0);
    expect(await run(true)).toBe(true); qc.clear(); expect(await run(true)).toBe(true); qc.clear();
  });
  it('enqueue only refreshes queued progress/history; successful cancel acknowledgment refreshes partial results once', async () => {
    const qc = client(); const { fetchers, stop } = observe(qc);
    await invalidateAiBatchSurfaces(qc, 42);
    expect(fetchers[0]).not.toHaveBeenCalled(); expect(fetchers[5]).toHaveBeenCalledTimes(1);
    const args = { runId: 42, batchId: 'batch-a', scope: 't:u', isCurrent: () => true };
    await Promise.all([invalidateAiBatchCancellation(qc, args), invalidateAiBatchCancellation(qc, args)]);
    expect(fetchers[0]).toHaveBeenCalledTimes(1); expect(fetchers[5]).toHaveBeenCalledTimes(2); stop();
  });
  it('disabled observers stay idle while inactive caches become stale', async () => {
    const qc = client(); const fetcher = vi.fn();
    qc.setQueryData(['ai-fix-list', 42], []); qc.setQueryData(['ai-batch-list', 42], []);
    const stop = new QueryObserver(qc, { queryKey: ['ai-fix-list', 42], queryFn: fetcher, enabled: false }).subscribe(() => {});
    await reconcileAiBatchTerminal(qc, { progress, scope: 't:u', isCurrent: () => true });
    expect(fetcher).not.toHaveBeenCalled(); expect(qc.getQueryState(['ai-fix-list', 42])?.isInvalidated).toBe(true); expect(qc.getQueryState(['ai-batch-list', 42])?.isInvalidated).toBe(true); stop(); qc.clear();
  });
});

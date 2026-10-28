import { QueryClient, QueryObserver } from '@tanstack/react-query';
import { expect, it, vi } from 'vitest';
import { invalidateScheduleLists, invalidateAnalysisSubmission } from './queryInvalidation';
it('schedule changes refresh every scope/list/preview once, leaving findings and snapshots untouched', async () => {
  const qc = new QueryClient({ defaultOptions: { queries: { staleTime: 300_000, retry: false } } });
  const keys = [['schedules', { enabled: true }], ['schedule', 'TENANT', 1], ['schedule', 'PROJECT', 2], ['schedule', 'PRODUCT', 3], ['schedule', 'SBOM', 4], ['schedule-targets', 7]];
  const fetchers = keys.map(() => vi.fn().mockResolvedValue('backend schedule'));
  const off = keys.map((queryKey, i) => { qc.setQueryData(queryKey, 'before'); return new QueryObserver(qc, { queryKey, queryFn: fetchers[i] }).subscribe(() => {}); });
  qc.setQueryData(['findings-enriched', 8], 'previous findings'); qc.setQueryData(['vex-run-snapshot', 4, 8], 'immutable');
  await Promise.all([invalidateScheduleLists(qc), invalidateScheduleLists(qc)]);
  keys.forEach((key, i) => { expect(qc.getQueryData(key)).toBe('backend schedule'); expect(fetchers[i]).toHaveBeenCalledTimes(1); });
  await invalidateAnalysisSubmission(qc);
  expect(qc.getQueryState(['findings-enriched', 8])?.isInvalidated).toBe(false); expect(qc.getQueryState(['vex-run-snapshot', 4, 8])?.isInvalidated).toBe(false);
  off.forEach(stop => stop()); qc.clear();
});

import { QueryClient, QueryObserver } from '@tanstack/react-query';
import { describe, expect, it, vi } from 'vitest';
import { invalidateAnalysisCompletion, invalidateDashboardTiles, invalidateProductSurfaces, invalidateSbomLifecycle, invalidateUploadSurfaces, invalidateVexSurfaces } from './queryInvalidation';

const families = ['dashboard-priority-findings', 'dashboard-operational-runs', 'portfolio-trend', 'vulnerability-age'];
const events = {
  analysis: (qc: QueryClient) => invalidateAnalysisCompletion(qc, { sbomId: 5 }),
  remediation: invalidateDashboardTiles,
  product: (qc: QueryClient) => invalidateProductSurfaces(qc, 3),
  lifecycle: (qc: QueryClient) => invalidateSbomLifecycle(qc, { id: 5, projectid: 2, product_id: 3 }),
  upload: (qc: QueryClient) => invalidateUploadSurfaces(qc, 2),
};
const client = () => new QueryClient({ defaultOptions: { queries: { staleTime: 300_000, refetchOnWindowFocus: false, retry: false } } });

describe('dashboard and VEX cache dependencies', () => {
  it.each(Object.entries(events))('%s refreshes every active family once and marks alternate filters stale', async (_name, event) => {
    const qc = client();
    const fetchers = families.map(() => vi.fn().mockResolvedValue('authoritative result'));
    const keys = families.map(family => family === 'vulnerability-age' ? [family, 2, 3, 5, 'all', '', ''] : family === 'portfolio-trend' ? [family, 'tenant-1', 2, 3, 5, 7] : [family, 'tenant-1', 2, 3, 5]);
    const off = keys.map((queryKey, i) => {
      qc.setQueryData(queryKey, 'before');
      return new QueryObserver(qc, { queryKey, queryFn: fetchers[i] }).subscribe(() => {});
    });
    const alternate = families.map(family => family === 'vulnerability-age' ? [family, 2, 3, 5, 'custom', '2026-01-01', '2026-10-09'] : family === 'portfolio-trend' ? [family, 'tenant-1', 2, 3, 5, 90] : [family, 'tenant-1', 9, 10, 11]);
    alternate.forEach(key => qc.setQueryData(key, 'alternate before'));
    qc.setQueryData(['vex-run-snapshot', 'tenant-1', 5, 8, 0], 'immutable snapshot');
    await event(qc);
    await Promise.resolve();
    await Promise.resolve();
    // Legacy composed helpers return void; await their active query tasks explicitly.
    await Promise.all(keys.map(queryKey => qc.getQueryCache().find({ queryKey })?.promise));
    keys.forEach((key, i) => { expect(qc.getQueryData(key)).toBe('authoritative result'); expect(fetchers[i]).toHaveBeenCalledTimes(1); });
    alternate.forEach(key => expect(qc.getQueryState(key)?.isInvalidated).toBe(true));
    expect(qc.getQueryState(['vex-run-snapshot', 'tenant-1', 5, 8, 0])?.isInvalidated).toBe(false);
    off.forEach(unsubscribe => unsubscribe()); qc.clear();
  });

  it('scopes triple/detail updates, leaves other SBOMs fresh and does not change metrics on assignment', async () => {
    const qc = client();
    const keys = [['vex-investigation-by-triple', 5, '11', 'CVE-A'], ['vex-investigation-by-triple', 6, '11', 'CVE-A'], ['vex-investigation', 1], ['vex-investigation', 2], ['dashboard-summary', 'tenant-1'], ['dashboard-vex', 'tenant-1']];
    keys.forEach(key => qc.setQueryData(key, 'before'));
    await invalidateVexSurfaces(qc, 5, { change: 'assignment', investigationId: 1 });
    expect(keys.map(key => qc.getQueryState(key)?.isInvalidated)).toEqual([true, false, true, false, false, false]);
    await invalidateVexSurfaces(qc, 5, { investigationId: 1 });
    expect(keys.map(key => qc.getQueryState(key)?.isInvalidated)).toEqual([true, false, true, false, true, true]);
    qc.clear();
  });

  it('disabled aggregate observers are not force-fetched', async () => {
    const qc = client(); const fetch = vi.fn();
    qc.setQueryData(['dashboard-summary', 'tenant-1'], 'before');
    const off = new QueryObserver(qc, { queryKey: ['dashboard-summary', 'tenant-1'], queryFn: fetch, enabled: false }).subscribe(() => {});
    await invalidateVexSurfaces(qc, 5);
    expect(fetch).not.toHaveBeenCalled(); expect(qc.getQueryState(['dashboard-summary', 'tenant-1'])?.isInvalidated).toBe(true);
    off(); qc.clear();
  });
});

it('a later mutation cancels a pre-mutation read rather than accepting its stale response', async () => {
  const qc = client(); const key = ['dashboard-summary', 'tenant-1', 2, 3, 5];
  qc.setQueryData(key, 'before');
  let firstSignal: AbortSignal | undefined;
  const fetch = vi.fn().mockImplementationOnce(({ signal }: { signal: AbortSignal }) => {
    firstSignal = signal;
    return new Promise<string>(() => {});
  }).mockResolvedValue('after mutation');
  const observer = new QueryObserver(qc, { queryKey: key, queryFn: fetch });
  const off = observer.subscribe(() => {});
  void observer.refetch();
  await invalidateVexSurfaces(qc, 5);
  expect(firstSignal?.aborted).toBe(true); expect(fetch).toHaveBeenCalledTimes(2);
  expect(qc.getQueryData(key)).toBe('after mutation'); off(); qc.clear();
});

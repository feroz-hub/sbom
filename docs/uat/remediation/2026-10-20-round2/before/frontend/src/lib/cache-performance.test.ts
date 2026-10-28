import { appendFileSync } from 'node:fs';
import { QueryClient, QueryObserver } from '@tanstack/react-query';
import { describe, expect, it, vi } from 'vitest';
import * as sync from './queryInvalidation';

type Operation = (qc: QueryClient) => void | Promise<void>;
const operations: Record<string, Operation> = {
  analysis: qc => sync.invalidateAnalysisCompletion(qc, { sbomId: 5, runId: 8 }),
  upload: qc => sync.invalidateUploadSurfaces(qc, 1, 10),
  delete: qc => { sync.invalidateSbomSurfaces(qc, 5); sync.invalidateProjectSurfaces(qc, 1); sync.invalidateRunLists(qc); sync.invalidateScheduleLists(qc); sync.invalidateDashboardTiles(qc); },
  lifecycle: qc => sync.invalidateSbomLifecycle(qc, { id: 5, projectid: 1, product_id: 10 }),
  projectDelete: qc => { sync.invalidateProjectLists(qc); sync.invalidateSbomLists(qc); sync.invalidateRunLists(qc); sync.invalidateScheduleLists(qc); sync.invalidateDashboardTiles(qc); },
  product: qc => sync.invalidateProductSurfaces(qc, 10),
  vex: qc => sync.invalidateVexSurfaces(qc, 5, { investigationId: 3 }),
  ai: qc => sync.invalidateAiBatchSurfaces(qc, 8, { results: true }),
  membership: qc => sync.invalidateTenantMembershipSurfaces(qc, 1),
  advisor: qc => sync.invalidateComponentAdvisorSurfaces(qc, 7),
  policy: qc => sync.invalidateAdvisorPolicySurfaces(qc, 1),
};
const activeKeys: readonly (readonly unknown[])[] = [
  ['dashboard-summary', '1', 1, 10, 5], ['dashboard-priority-findings', '1'], ['dashboard-operational-runs', '1'], ['portfolio-trend', '1', 30], ['vulnerability-age', '1'],
  ['sboms'], ['sbom', 5], ['sbom-info', 5], ['sbom-components-canonical', 5], ['product', 10], ['product-sboms', 10], ['project', 1], ['projects'],
  ['reports', 'targets', 'SBOM', 'search'], ['runs'], ['run', 8], ['findings-enriched', 8, 'HIGH'], ['schedules'],
  ['component-advisor-summary', '1', {}], ['component-advisor-components', '1', {}], ['component-advisor-summary', '2', {}],
  ['component-advisor-recommendation', 7, '1'], ['component-advisor-candidate-evidence', 7, 4, '1'],
  ['vex-investigations', '1'], ['vex-investigation', 3], ['vex-investigation-by-triple', 5, 6, 'CVE-1'],
  ['ai-fix-list', 8], ['ai-fix', 4], ['ai-batch-progress', 8, 9], ['ai-batch-list', 8], ['ai-settings', 'usage'], ['ai-usage-trend', 30],
  ['platform-summary'], ['platform-tenant', 1], ['tenant-users', 1], ['vex-assignees', '1', 'search'],
];
const inactiveKeys = [['sboms', 'dashboard-scope', 1], ['portfolio-trend', '1', 90], ['reports', 'targets', 'PRODUCT', 'other'], ['ai-batch-progress', 8]];
const disabledKeys = [['dashboard-summary', 'denied'], ['vex-investigation-by-triple', 5, 9, 'denied']];
const immutableKeys = [['vex-run-snapshot', '1', 5, 8], ['reports', 'deliveries', 1], ['lifecycle-providers', 'tenant:1']];
const settle = async (qc: QueryClient) => { await new Promise(resolve => setTimeout(resolve, 20)); await vi.waitFor(() => expect(qc.isFetching()).toBe(0)); };

describe('Batch 6 actual queryFn performance measurements', () => {
  it.each(Object.keys(operations))('%s refresh counts', async operation => {
    const qc = new QueryClient({ defaultOptions: { queries: { staleTime: 300_000, refetchOnWindowFocus: false, retry: false } } });
    const counts = new Map<string, number>(); const canceled = new Map<string, number>(); const off: Array<() => void> = [];
    for (const key of [...activeKeys, ...inactiveKeys, ...disabledKeys, ...immutableKeys]) qc.setQueryData(key, 'before');
    for (const key of [...activeKeys, ...disabledKeys, ...immutableKeys]) {
      const id = JSON.stringify(key);
      off.push(new QueryObserver(qc, { queryKey: key, enabled: !disabledKeys.includes(key as string[]), queryFn: async ({ signal }) => {
        counts.set(id, (counts.get(id) ?? 0) + 1); signal.addEventListener('abort', () => canceled.set(id, (canceled.get(id) ?? 0) + 1));
        await new Promise(resolve => setTimeout(resolve, 5)); return 'authoritative';
      } }).subscribe(() => {}));
    }
    await operations[operation](qc); await settle(qc);
    const active = activeKeys.filter(key => counts.has(JSON.stringify(key))).length;
    const executions = [...counts.values()].reduce((a, b) => a + b, 0);
    const inactive = inactiveKeys.filter(key => qc.getQueryState(key)?.isInvalidated).length;
    const disabled = disabledKeys.filter(key => qc.getQueryState(key)?.isInvalidated).length;
    const duplicate = executions - active;
    console.log('CACHE_MEASURE', JSON.stringify({ operation, cached: qc.getQueryCache().getAll().length, affected: active + inactive + disabled, active, executions, inactive, disabledStale: disabled, duplicate, canceled: [...canceled.values()].reduce((a, b) => a + b, 0) }));
    disabledKeys.forEach(key => expect(counts.get(JSON.stringify(key)) ?? 0).toBe(0));
    immutableKeys.forEach(key => { expect(counts.get(JSON.stringify(key)) ?? 0).toBe(0); expect(qc.getQueryState(key)?.isInvalidated).toBe(false); });
    for (const key of activeKeys.filter(key => counts.has(JSON.stringify(key)))) expect(qc.getQueryData(key)).toBe('authoritative');
    if (process.env.UI_SYNC_MEASURE_PATH) appendFileSync(process.env.UI_SYNC_MEASURE_PATH, JSON.stringify({ operation, active, executions, inactive, disabled, duplicate, duplicates: [...counts].filter(([, count]) => count > 1) }) + '\n');
    const expected: Record<string, number[]> = { analysis: [20, 3, 2], upload: [15, 3, 1], delete: [20, 3, 1], lifecycle: [22, 3, 1], projectDelete: [15, 3, 1], product: [13, 2, 1], vex: [5, 0, 2], ai: [6, 1, 0], membership: [5, 0, 0], advisor: [5, 0, 0], policy: [4, 0, 0] };
    expect([active, inactive, disabled]).toEqual(expected[operation]);
    expect(duplicate).toBe(0);
    off.forEach(stop => stop()); qc.clear();
  });
});

describe('cache coalescing correctness across mutation events', () => {
  function setup(fetch: (context: { signal: AbortSignal }) => Promise<unknown>) {
    const qc = new QueryClient({ defaultOptions: { queries: { staleTime: 300_000, refetchOnWindowFocus: false, retry: false } } });
    const key = ['dashboard-summary', '1']; qc.setQueryData(key, 'initial');
    const off = new QueryObserver(qc, { queryKey: key, queryFn: fetch }).subscribe(() => {});
    return { qc, key, cleanup: () => { off(); qc.clear(); } };
  }
  it('same-turn composition refreshes once; a second completed mutation refreshes again', async () => {
    let version = 1; const fetch = vi.fn(async () => version); const h = setup(fetch);
    await Promise.all([sync.invalidateDashboardTiles(h.qc), sync.invalidateDashboardSummary(h.qc)]);
    expect(fetch).toHaveBeenCalledTimes(1); expect(h.qc.getQueryData(h.key)).toBe(1);
    version = 2; await sync.invalidateDashboardSummary(h.qc);
    expect(fetch).toHaveBeenCalledTimes(2); expect(h.qc.getQueryData(h.key)).toBe(2); h.cleanup();
  });
  it('a mutation during an in-flight refresh cancels the older read and fetches newer server data', async () => {
    const requests: Array<{ signal: AbortSignal; finish: (value: unknown) => void }> = [];
    const h = setup(({ signal }) => new Promise(resolve => requests.push({ signal, finish: resolve })));
    const first = sync.invalidateDashboardSummary(h.qc);
    await vi.waitFor(() => expect(requests).toHaveLength(1));
    const second = sync.invalidateDashboardSummary(h.qc);
    await vi.waitFor(() => expect(requests).toHaveLength(2));
    expect(requests[0].signal.aborted).toBe(true); requests[1].finish('newer'); await second;
    requests[0].finish('older'); await first;
    expect(h.qc.getQueryData(h.key)).toBe('newer'); h.cleanup();
  });
  it('failed refetch does not block a later mutation and helper promises await completion', async () => {
    const fetch = vi.fn().mockRejectedValueOnce(new Error('Unavailable')).mockResolvedValue('recovered'); const h = setup(fetch);
    await sync.invalidateDashboardSummary(h.qc); expect(h.qc.getQueryData(h.key)).toBe('initial');
    await sync.invalidateDashboardSummary(h.qc); expect(h.qc.getQueryData(h.key)).toBe('recovered'); expect(fetch).toHaveBeenCalledTimes(2); h.cleanup();
  });
  it('queues are QueryClient-specific', async () => {
    const aFetch = vi.fn().mockResolvedValue('a'), bFetch = vi.fn().mockResolvedValue('b'); const a = setup(aFetch), b = setup(bFetch);
    await Promise.all([sync.invalidateDashboardSummary(a.qc), sync.invalidateDashboardSummary(b.qc)]);
    expect(a.qc.getQueryData(a.key)).toBe('a'); expect(b.qc.getQueryData(b.key)).toBe('b'); a.cleanup(); b.cleanup();
  });
  it.each([1, null])('policy scope %s uses actual list/detail/recommendation/evidence identities', async tenantId => {
    const qc = new QueryClient({ defaultOptions: { queries: { staleTime: 300_000, retry: false } } });
    const keys = [
      ['component-advisor-summary', '1', {}], ['component-advisor-summary', '2', {}],
      ['component-advisor-component', '1', 'npm/x', {}], ['component-advisor-component', '2', 'npm/x', {}],
      ['component-advisor-recommendation', 7, '1'], ['component-advisor-recommendation', 7, '2'],
      ['component-advisor-candidate-evidence', 7, 9, 'checks', '1'], ['component-advisor-candidate-evidence', 7, 9, 'checks', '2'],
    ];
    const fetches = keys.map(key => { qc.setQueryData(key, 'before'); const fetch = vi.fn().mockResolvedValue('new classification'); const off = new QueryObserver(qc, { queryKey: key, queryFn: fetch }).subscribe(() => {}); return { fetch, off }; });
    await sync.invalidateAdvisorPolicySurfaces(qc, tenantId);
    fetches.forEach(({ fetch }, i) => expect(fetch).toHaveBeenCalledTimes(tenantId === null || i % 2 === 0 ? 1 : 0));
    fetches.forEach(({ off }) => off()); qc.clear();
  });
});

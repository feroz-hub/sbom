import { QueryClient, QueryObserver } from '@tanstack/react-query';
import { describe, expect, it, vi } from 'vitest';
import { invalidatePlatformAdministratorSurfaces, invalidatePlatformTenantSurfaces } from './queryInvalidation';

function client() {
  return new QueryClient({ defaultOptions: { queries: { staleTime: 5 * 60_000, refetchOnWindowFocus: false, retry: false } } });
}

describe('platform invalidation helpers', () => {
  it('awaits active summary, tenant list and affected detail refreshes while leaving unrelated data fresh', async () => {
    const qc = client();
    const keys = [['platform-summary'], ['platform-tenants', 'overview'], ['platform-tenant', 7]];
    const resolvers: Array<(data: string) => void> = [];
    const unsubscribes = keys.map(queryKey => {
      qc.setQueryData(queryKey, 'before');
      const observer = new QueryObserver(qc, { queryKey, queryFn: () => new Promise<string>(resolve => resolvers.push(resolve)) });
      return observer.subscribe(() => {});
    });
    qc.setQueryData(['platform-tenant', 99], 'other tenant');
    qc.setQueryData(['sboms'], 'business data');
    let finished = false;
    const promise = invalidatePlatformTenantSurfaces(qc, 7).then(() => { finished = true; });
    expect(resolvers).toHaveLength(3);
    resolvers[0]('server summary');
    await Promise.resolve();
    expect(finished).toBe(false);
    resolvers[1]('server tenants'); resolvers[2]('server detail');
    await promise;
    expect(keys.map(key => qc.getQueryData(key))).toEqual(['server summary', 'server tenants', 'server detail']);
    expect(qc.getQueryState(['platform-tenant', 99])?.isInvalidated).toBe(false);
    expect(qc.getQueryState(['sboms'])?.isInvalidated).toBe(false);
    unsubscribes.forEach(unsubscribe => unsubscribe()); qc.clear();
  });

  it('marks inactive and disabled query variants stale without executing unauthorized observers', async () => {
    const qc = client();
    const fetchSummary = vi.fn();
    qc.setQueryData(['platform-summary'], 'cached summary');
    qc.setQueryData(['platform-tenants', 'filtered', 2], 'cached list');
    qc.setQueryData(['platform-tenant', 7], 'cached detail');
    const observer = new QueryObserver(qc, { queryKey: ['platform-summary'], queryFn: fetchSummary, enabled: false });
    const unsubscribe = observer.subscribe(() => {});
    await invalidatePlatformTenantSurfaces(qc, 7);
    expect(fetchSummary).not.toHaveBeenCalled();
    expect(qc.getQueryState(['platform-summary'])?.isInvalidated).toBe(true);
    expect(qc.getQueryState(['platform-tenants', 'filtered', 2])?.isInvalidated).toBe(true);
    expect(qc.getQueryState(['platform-tenant', 7])?.isInvalidated).toBe(true);
    expect(qc.getQueryData(['platform-summary'])).toBe('cached summary');
    unsubscribe(); qc.clear();
  });

  it('refreshes active administrator and summary data without refetching tenant inventory', async () => {
    const qc = client();
    const keys = [['platform-administrators'], ['platform-summary'], ['platform-tenants', 'overview'], ['sboms']];
    const fetchers = keys.map((_key, i) => vi.fn().mockResolvedValue(`server ${i}`));
    const unsubscribes = keys.map((queryKey, i) => {
      qc.setQueryData(queryKey, `cached ${i}`);
      return new QueryObserver(qc, { queryKey, queryFn: fetchers[i] }).subscribe(() => {});
    });
    await invalidatePlatformAdministratorSurfaces(qc);
    expect(qc.getQueryData(keys[0])).toBe('server 0'); expect(qc.getQueryData(keys[1])).toBe('server 1');
    expect(fetchers[0]).toHaveBeenCalledTimes(1); expect(fetchers[1]).toHaveBeenCalledTimes(1);
    expect(fetchers[2]).not.toHaveBeenCalled(); expect(fetchers[3]).not.toHaveBeenCalled();
    unsubscribes.forEach(unsubscribe => unsubscribe()); qc.clear();
  });
});

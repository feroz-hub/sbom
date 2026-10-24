import { InfiniteQueryObserver, QueryClient, QueryObserver } from '@tanstack/react-query';
import { describe, expect, it, vi } from 'vitest';
import { invalidateTenantMembershipSurfaces, invalidateUserSurfaces } from './queryInvalidation';
const client = () => new QueryClient({ defaultOptions: { queries: { staleTime: 300000, refetchOnWindowFocus: false, retry: false } } });
describe('user/membership cache integration', () => {
  it.each(['invitation', 'addition', 'removal', 'activation', 'deactivation', 'roles'])('%s refreshes authoritative counts and scoped projections once', async () => {
    const qc = client();
    const keys = [['platform-summary'], ['platform-tenants', 'overview'], ['tenant-users', 7], ['tenant-roles', 7], ['tenant-audit-history', 7, { page: 2 }], ['platform-tenant', 7], ['vex-investigations', '7', {}]];
    const fetchers = keys.map(() => vi.fn().mockResolvedValue({ server: true, memberCount: 2, adminCount: 1 }));
    const stops = keys.map((queryKey, i) => { qc.setQueryData(queryKey, { memberCount: 1 }); return new QueryObserver(qc, { queryKey, queryFn: fetchers[i] }).subscribe(() => {}); });
    qc.setQueryData(['platform-tenant', 9], 'unrelated'); qc.setQueryData(['tenant-users', 9], []);
    qc.setQueryData(['reports', 'delivery', 1], 'artifact');
    await Promise.all([invalidateTenantMembershipSurfaces(qc, 7), invalidateTenantMembershipSurfaces(qc, 7)]);
    keys.forEach((key, i) => { expect(qc.getQueryData(key)).toMatchObject({ server: true }); expect(fetchers[i]).toHaveBeenCalledTimes(1); });
    for (const key of [['platform-tenant', 9], ['tenant-users', 9], ['reports', 'delivery', 1]]) expect(qc.getQueryState(key)?.isInvalidated).toBe(false);
    stops.forEach(stop => stop()); qc.clear();
  });
  it('refreshes every infinite assignee search/page variant without touching another tenant', async () => {
    const qc = client(); const fetcher = vi.fn(async ({ pageParam }: { pageParam: number }) => ({ items: ['eligible server user'], offset: pageParam }));
    const key = ['vex-assignees', '7', 'developer'];
    qc.setQueryData(key, { pages: [{ items: ['old'], offset: 0 }, { items: ['old page2'], offset: 1 }], pageParams: [0, 1] });
    const observer = new InfiniteQueryObserver(qc, { queryKey: key, queryFn: fetcher, initialPageParam: 0, getNextPageParam: data => data.offset + 1 });
    const stop = observer.subscribe(() => {});
    qc.setQueryData(['vex-assignees', '7', 'other search'], { pages: [], pageParams: [] });
    qc.setQueryData(['vex-assignees', '8', 'developer'], { pages: [], pageParams: [] });
    await invalidateTenantMembershipSurfaces(qc, 7);
    expect(fetcher).toHaveBeenCalledTimes(2); expect(qc.getQueryData(key)).toMatchObject({ pages: [{ items: ['eligible server user'] }, { items: ['eligible server user'] }] });
    expect(qc.getQueryState(['vex-assignees', '7', 'other search'])?.isInvalidated).toBe(true);
    expect(qc.getQueryState(['vex-assignees', '8', 'developer'])?.isInvalidated).toBe(false);
    stop(); qc.clear();
  });
  it('profile edits refresh cached shared identities and administrator names, without summary/count recalculation', async () => {
    const qc = client();
    qc.setQueryData(['tenant-users', 8], [{ user_id: 42 }]); qc.setQueryData(['tenant-users', 9], [{ user_id: 43 }]);
    qc.setQueryData(['platform-summary'], { total_memberships: 10 }); qc.setQueryData(['platform-administrators'], []);
    await invalidateUserSurfaces(qc, { userId: 42, tenantIds: [7], accountChanged: true });
    expect(qc.getQueryState(['tenant-users', 8])?.isInvalidated).toBe(true);
    expect(qc.getQueryState(['tenant-users', 9])?.isInvalidated).toBe(false);
    expect(qc.getQueryState(['platform-administrators'])?.isInvalidated).toBe(true);
    expect(qc.getQueryState(['platform-summary'])?.isInvalidated).toBe(false); qc.clear();
  });
  it('account disabling invalidates admin metrics; disabled observers never fetch and inactive dashboard fetches on return', async () => {
    const qc = client(); const fetcher = vi.fn().mockResolvedValue({ platform_admins: 0 });
    qc.setQueryData(['platform-summary'], { platform_admins: 1 });
    const disabled = new QueryObserver(qc, { queryKey: ['platform-summary'], queryFn: fetcher, enabled: false }); const stop = disabled.subscribe(() => {});
    await invalidateUserSurfaces(qc, { tenantIds: [7], accountChanged: true, affectsMetrics: true });
    expect(fetcher).not.toHaveBeenCalled(); expect(qc.getQueryState(['platform-summary'])?.isInvalidated).toBe(true); stop();
    await qc.fetchQuery({ queryKey: ['platform-summary'], queryFn: fetcher });
    expect(qc.getQueryData(['platform-summary'])).toEqual({ platform_admins: 0 }); expect(fetcher).toHaveBeenCalledTimes(1); qc.clear();
  });
});

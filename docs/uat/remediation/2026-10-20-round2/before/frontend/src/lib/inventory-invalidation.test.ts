import { QueryClient, QueryObserver } from '@tanstack/react-query';
import { describe, expect, it, vi } from 'vitest';
import { invalidateProjectMetadata, invalidateProjectLists, invalidateProductSurfaces, invalidateSbomLists } from './queryInvalidation';
const client = () => new QueryClient({ defaultOptions: { queries: { staleTime: 300_000, refetchOnWindowFocus: false, retry: false } } });
function observe(qc: QueryClient, key: readonly unknown[], data: unknown = 'before') {
  qc.setQueryData(key, data); const fetch = vi.fn().mockResolvedValue('backend result');
  const off = new QueryObserver(qc, { queryKey: key, queryFn: fetch }).subscribe(() => {});
  return { fetch, off };
}
describe('3A project and report target synchronization', () => {
  it.each(['create', 'rename', 'status'] as const)('%s refreshes project details, labels and report choices', async action => {
    const qc = client();
    const keys = [['project', 7], ['project-detail', 7], ['projects'], ['sboms', 'filtered', 7], ['reports', 'targets', 'PROJECT', 'search'], ['dashboard-summary', 'tenant', 7]];
    const watches = keys.map(key => observe(qc, key));
    qc.setQueryData(['reports', 'targets', 'SBOM', 'another search'], 'before');
    qc.setQueryData(['reports', 'deliveries', false, '', 52], 'immutable delivery');
    qc.setQueryData(['project', 99], 'unrelated'); qc.setQueryData(['runs'], 'unchanged analysis');
    qc.setQueryData(['dashboard-posture', 'tenant', 7], 'security counts');
    await invalidateProjectMetadata(qc, { id: 7, project_status: action === 'status' ? 0 : 1 }, action === 'create' ? null : { project_status: 1 });
    keys.forEach((key, i) => { expect(qc.getQueryData(key)).toBe('backend result'); expect(watches[i].fetch).toHaveBeenCalledTimes(1); });
    expect(qc.getQueryState(['reports', 'targets', 'SBOM', 'another search'])?.isInvalidated).toBe(true);
    expect(qc.getQueryState(['reports', 'deliveries', false, '', 52])?.isInvalidated).toBe(false);
    expect(qc.getQueryState(['project', 99])?.isInvalidated).toBe(false);
    expect(qc.getQueryState(['runs'])?.isInvalidated).toBe(false);
    expect(qc.getQueryState(['dashboard-posture', 'tenant', 7])?.isInvalidated).toBe(action !== 'rename');
    watches.forEach(w => w.off()); qc.clear();
  });
  it.each([invalidateProjectLists, invalidateProductSurfaces, invalidateSbomLists])('inventory helper refreshes actual report target prefixes only', async event => {
    const qc = client(); qc.setQueryData(['reports', 'targets', 'PRODUCT', 'x'], 'before'); qc.setQueryData(['reports', 'deliveries'], 'delivery');
    await event(qc); await Promise.resolve();
    expect(qc.getQueryState(['reports', 'targets', 'PRODUCT', 'x'])?.isInvalidated).toBe(true);
    expect(qc.getQueryState(['reports', 'deliveries'])?.isInvalidated).toBe(false); qc.clear();
  });
});

import { invalidateProjectAssignmentSurfaces } from './queryInvalidation';
describe('3B SBOM ownership and metadata', () => {
  it('refreshes old and new ownership lists exactly once without affecting other resource details', async () => {
    const qc = client();
    const keys = [['sboms', 'dashboard-scope', 1, 10], ['sboms', 'dashboard-scope', 2, 20], ['product-sboms', 10], ['product-sboms', 20], ['product', 10], ['product', 20], ['project', 1], ['project', 2], ['products', 1], ['products', 2], ['dashboard-sboms', 'tenant', 2, 20], ['reports', 'targets', 'SBOM', 'search'], ['logical-sbom-versions', 'tenant', 4], ['sbom', 5]];
    const watches = keys.map(key => observe(qc, key));
    qc.setQueryData(['product', 99], 'other product'); qc.setQueryData(['project', 99], 'other project'); qc.setQueryData(['sbom', 99], 'other SBOM');
    await invalidateProjectAssignmentSurfaces(qc, { sbomId: 5, previousProjectId: 1, nextProjectId: 2, previousProductId: 10, nextProductId: 20 });
    keys.forEach((key, i) => { expect(qc.getQueryData(key)).toBe('backend result'); expect(watches[i].fetch).toHaveBeenCalledTimes(1); });
    for (const family of ['project', 'product', 'sbom']) expect(qc.getQueryState([family, 99])?.isInvalidated).toBe(false);
    watches.forEach(w => w.off()); qc.clear();
  });
  it('same-owner metadata refreshes projections without replacing historical snapshots or unrelated analysis', async () => {
    const qc = client(); const watch = observe(qc, ['product-sboms', 10]);
    qc.setQueryData(['vex-run-snapshot', 'tenant', 5, 8, 0], 'snapshot'); qc.setQueryData(['runs'], 'analysis');
    qc.setQueryData(['dashboard-posture'], 'security values');
    await invalidateProjectAssignmentSurfaces(qc, { sbomId: 5, previousProjectId: 1, nextProjectId: 1, previousProductId: 10, nextProductId: 10 });
    expect(watch.fetch).toHaveBeenCalledTimes(1);
    expect(qc.getQueryState(['vex-run-snapshot', 'tenant', 5, 8, 0])?.isInvalidated).toBe(false);
    expect(qc.getQueryState(['runs'])?.isInvalidated).toBe(false); expect(qc.getQueryState(['dashboard-posture'])?.isInvalidated).toBe(false);
    watch.off(); qc.clear();
  });
});

import { invalidateSbomRevisionCreated } from './queryInvalidation';
import type { SBOMSource } from '@/types';
const sbom: SBOMSource = { id: 5, sbom_name: 'Parent', sbom_type: null, sbom_version: '1.0', projectid: 1, product_id: 10, created_by: null, created_on: null, modified_by: null, modified_on: null, productver: null };
describe('3C newly restored revision', () => {
  it('refreshes history, new revision, inventory and both response owners without touching immutable snapshots', async () => {
    const qc = client(); const revision = { ...sbom, id: 6, parent_id: 5, projectid: 2, product_id: 20 };
    const keys = [['sbom-versions', 5], ['sbom', 6], ['sbom-versions', 6], ['sboms'], ['logical-sbom-versions', 4], ['logical-sbom-versions', 'tenant', 4], ['logical-sboms', 20, 'choices'], ['product-sboms', 10], ['product-sboms', 20], ['reports', 'targets', 'SBOM', ''], ['dashboard-sboms', 'tenant', 2, 20]];
    const watches = keys.map(key => observe(qc, key));
    qc.setQueryData(['vex-run-snapshot', 'tenant', 5, 8], 'immutable'); qc.setQueryData(['reports', 'deliveries'], 'immutable');
    await invalidateSbomRevisionCreated(qc, sbom, revision);
    keys.forEach((key, i) => { expect(qc.getQueryData(key)).toBe('backend result'); expect(watches[i].fetch).toHaveBeenCalledTimes(1); });
    expect(qc.getQueryState(['vex-run-snapshot', 'tenant', 5, 8])?.isInvalidated).toBe(false);
    expect(qc.getQueryState(['reports', 'deliveries'])?.isInvalidated).toBe(false);
    watches.forEach(w => w.off()); qc.clear();
  });
  it('uses parent context only for omitted ownership and respects explicit null owners', async () => {
    const qc = client(); qc.setQueryData(['product-sboms', 10], 'before'); qc.setQueryData(['product-sboms', 99], 'other');
    await invalidateSbomRevisionCreated(qc, sbom, { ...sbom, id: 6, product_id: undefined });
    expect(qc.getQueryState(['product-sboms', 10])?.isInvalidated).toBe(true);
    expect(qc.getQueryState(['product-sboms', 99])?.isInvalidated).toBe(false); qc.clear();
    qc.setQueryData(['project', 2], 'unrelated');
    await invalidateSbomRevisionCreated(qc, sbom, { ...sbom, id: 6, projectid: null, product_id: null });
    expect(qc.getQueryState(['project', 2])?.isInvalidated).toBe(false); qc.clear();
  });
});

import { invalidateLifecycleOverrideSurfaces } from './queryInvalidation';
describe('3D component lifecycle evidence', () => {
  it('refreshes canonical and paginated evidence once, retains filters and isolates other SBOMs', async () => {
    const qc = client(); const keys = [['sbom-components', 5, false, 2, 25, 'openssl', 'name', 'asc'], ['sbom-components-canonical', 5]];
    const watches = keys.map(key => observe(qc, key));
    qc.setQueryData(['sbom-components', 5, true, 1, 50, 'other', 'name', 'desc'], 'inactive variant');
    qc.setQueryData(['sbom-components-canonical', 99], 'other SBOM'); qc.setQueryData(['runs'], 'analysis');
    await Promise.all([invalidateLifecycleOverrideSurfaces(qc, 5), invalidateLifecycleOverrideSurfaces(qc, 5)]);
    keys.forEach((key, i) => { expect(qc.getQueryData(key)).toBe('backend result'); expect(watches[i].fetch).toHaveBeenCalledTimes(1); });
    expect(qc.getQueryState(['sbom-components', 5, true, 1, 50, 'other', 'name', 'desc'])?.isInvalidated).toBe(true);
    expect(qc.getQueryState(['sbom-components-canonical', 99])?.isInvalidated).toBe(false); expect(qc.getQueryState(['runs'])?.isInvalidated).toBe(false);
    watches.forEach(w => w.off()); qc.clear();
  });
  it('does not force disabled or unauthorized target observers to execute', async () => {
    const qc = client(), fetch = vi.fn(); const key = ['reports', 'targets', 'SBOM', 'search']; qc.setQueryData(key, 'before');
    const off = new QueryObserver(qc, { queryKey: key, queryFn: fetch, enabled: false }).subscribe(() => {});
    await invalidateSbomLists(qc); expect(fetch).not.toHaveBeenCalled(); expect(qc.getQueryState(key)?.isInvalidated).toBe(true); off(); qc.clear();
  });
});

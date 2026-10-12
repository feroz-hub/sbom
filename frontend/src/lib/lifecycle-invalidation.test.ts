import { QueryClient, QueryObserver } from '@tanstack/react-query';
import { describe, expect, it, vi } from 'vitest';
import { invalidateLifecycleProviderSurfaces, invalidateLifecycleVendorRecords } from './queryInvalidation';
const client = () => new QueryClient({ defaultOptions: { queries: { staleTime: 300_000, refetchOnWindowFocus: false, retry: false } } });
describe('lifecycle configuration and catalog cache dependencies', () => {
  it.each(['configuration', 'secret saved', 'secret deleted', 'override reset'])('%s refreshes readiness, marks inactive scope variants stale and respects disabled observers', async () => {
    const qc = client(); const status = ['lifecycle-provider-status']; const config = ['lifecycle-providers', 'tenant:1'];
    for (const key of [status, config, ['lifecycle-providers', 'platform'], ['lifecycle-providers', 'tenant:2']]) qc.setQueryData(key, 'before');
    const fetch = vi.fn().mockResolvedValue('server readiness');
    const off = new QueryObserver(qc, { queryKey: status, queryFn: fetch }).subscribe(() => {});
    const forbidden = vi.fn(); const disabled = new QueryObserver(qc, { queryKey: config, queryFn: forbidden, enabled: false }); const offDisabled = disabled.subscribe(() => {});
    await invalidateLifecycleProviderSurfaces(qc, 'tenant:1');
    expect(fetch).toHaveBeenCalledTimes(1); expect(qc.getQueryData(status)).toBe('server readiness'); expect(forbidden).not.toHaveBeenCalled();
    expect(qc.getQueryState(config)?.isInvalidated).toBe(true);
    expect(qc.getQueryState(['lifecycle-providers', 'platform'])?.isInvalidated).toBe(false);
    expect(qc.getQueryState(['lifecycle-providers', 'tenant:2'])?.isInvalidated).toBe(false);
    off(); offDisabled(); qc.clear();
  });
  it('platform defaults invalidate cached inherited tenant configurations', async () => {
    const qc = client(); for (const key of ['platform', 'tenant:1', 'tenant:2']) qc.setQueryData(['lifecycle-providers', key], 'before');
    await invalidateLifecycleProviderSurfaces(qc, 'platform');
    for (const key of ['platform', 'tenant:1', 'tenant:2']) expect(qc.getQueryState(['lifecycle-providers', key])?.isInvalidated).toBe(true); qc.clear();
  });
  it.each(['create', 'update', 'delete', 'import'])('%s invalidates catalog search variants without pretending to enrich existing components', async () => {
    const qc = client(); const key = ['lifecycle-vendor-records', 'openssl']; qc.setQueryData(key, 'before');
    qc.setQueryData(['lifecycle-vendor-records', 'other'], 'before'); qc.setQueryData(['sbom-components-canonical', 5], 'evidence'); qc.setQueryData(['lifecycle-provider-status'], 'health');
    const fetch = vi.fn().mockResolvedValue('server records'); const off = new QueryObserver(qc, { queryKey: key, queryFn: fetch }).subscribe(() => {});
    await invalidateLifecycleVendorRecords(qc); expect(fetch).toHaveBeenCalledTimes(1); expect(qc.getQueryData(key)).toBe('server records');
    expect(qc.getQueryState(['lifecycle-vendor-records', 'other'])?.isInvalidated).toBe(true);
    expect(qc.getQueryState(['sbom-components-canonical', 5])?.isInvalidated).toBe(false); expect(qc.getQueryState(['lifecycle-provider-status'])?.isInvalidated).toBe(false); off(); qc.clear();
  });
});

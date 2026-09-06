// @vitest-environment jsdom

import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import { request } from '@/lib/api';

/**
 * Guards the single place every non-streaming API call gets its tenant scope
 * from: ``getAuthHeaders()`` reading the persisted active tenant on each call.
 * A tenant switch must therefore be visible to the very next request without
 * any per-call plumbing.
 */
describe('shared request helper tenant scoping', () => {
  const fetchMock = vi.fn();
  const requestHeaders = (callIndex: number) =>
    new Headers((fetchMock.mock.calls[callIndex]?.[1] as RequestInit | undefined)?.headers);

  beforeEach(() => {
    sessionStorage.clear();
    fetchMock.mockReset();
    fetchMock.mockImplementation(() =>
      Promise.resolve(
        new Response(JSON.stringify({ ok: true }), {
          status: 200,
          headers: { 'Content-Type': 'application/json' },
        }),
      ),
    );
    vi.stubGlobal('fetch', fetchMock);
  });

  afterEach(() => {
    vi.unstubAllGlobals();
    sessionStorage.clear();
  });

  it('injects X-Tenant-ID from the persisted active tenant', async () => {
    sessionStorage.setItem('sbom_active_tenant_id', '7');

    await request('/api/sboms');

    expect(requestHeaders(0).get('X-Tenant-ID')).toBe('7');
  });

  it('omits the tenant header when no tenant is selected', async () => {
    await request('/api/sboms');

    expect(requestHeaders(0).get('X-Tenant-ID')).toBeNull();
  });

  it('uses the newly selected tenant on the next request after a switch', async () => {
    sessionStorage.setItem('sbom_active_tenant_id', '7');
    await request('/api/sboms');

    sessionStorage.setItem('sbom_active_tenant_id', '1');
    await request('/api/sboms');

    expect(requestHeaders(0).get('X-Tenant-ID')).toBe('7');
    expect(requestHeaders(1).get('X-Tenant-ID')).toBe('1');
  });

  it('does not duplicate content-type when caller casing differs', async () => {
    await request('/api/v1/ai/credentials/test', {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify({ provider_name: 'gemini' }),
    });

    expect(requestHeaders(0).get('Content-Type')).toBe('application/json');
  });
});

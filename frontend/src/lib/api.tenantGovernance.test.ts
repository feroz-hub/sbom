// @vitest-environment jsdom
import { afterEach, beforeEach, expect, it, vi } from 'vitest';
import {
  ApiError, getPlatformTenantAdministrators, revokePlatformTenantAdministrator,
  deactivatePlatformTenantAdministrator, removePlatformTenantAdministrator,
} from './api';

const tenant = '00000000-0000-4000-8000-000000000007';
const membership = '00000000-0000-4000-8000-000000000008';
const fetchMock = vi.fn();
const callOptions = () => fetchMock.mock.calls[0][1] as RequestInit;
beforeEach(() => {
  sessionStorage.setItem('sbom_active_tenant_id', '00000000-0000-4000-8000-000000000099');
  fetchMock.mockReset().mockResolvedValue(new Response('{}', { status: 200 }));
  vi.stubGlobal('fetch', fetchMock);
});
afterEach(() => { vi.unstubAllGlobals(); sessionStorage.clear(); });

it('loads governance metadata without a tenant header or changing tenant selection', async () => {
  await getPlatformTenantAdministrators(tenant);
  expect(fetchMock.mock.calls[0][0]).toContain(`/api/platform/tenants/${tenant}/administrators`);
  expect(new Headers(callOptions().headers).has('X-Tenant-ID')).toBe(false);
  expect(sessionStorage.getItem('sbom_active_tenant_id')).toBe('00000000-0000-4000-8000-000000000099');
});
it('serializes revoke version, explicit role and reason against the membership UUID', async () => {
  const payload = { expected_version: 3, replacement_primary_role_code: 'CUSTOM_REVIEWER', reason: 'Reassignment' };
  await revokePlatformTenantAdministrator(tenant, membership, payload);
  expect(fetchMock.mock.calls[0][0]).toContain(`/tenants/${tenant}/administrators/${membership}/revoke`);
  expect(callOptions()).toMatchObject({ method: 'POST', body: JSON.stringify(payload) });
  expect(new Headers(callOptions().headers).has('X-Tenant-ID')).toBe(false);
});
it('does not invent a replacement on secondary administrator revocation', async () => {
  await revokePlatformTenantAdministrator(tenant, membership, { expected_version: 3 });
  expect(JSON.parse(callOptions().body as string)).toEqual({ expected_version: 3 });
});
it.each([undefined, 'Temporary suspension'])('serializes deactivate reason %s', async reason => {
  await deactivatePlatformTenantAdministrator(tenant, membership, reason);
  expect(fetchMock.mock.calls[0][0]).toContain(`/administrators/${membership}/deactivate`);
  expect(callOptions()).toMatchObject({ method: 'POST', body: JSON.stringify(reason ? { reason } : {}) });
});
it.each([undefined, 'Approved removal & review? #1'])('accepts DELETE 204 without parsing JSON and encodes reason %s', async reason => {
  fetchMock.mockResolvedValue(new Response(null, { status: 204 }));
  await expect(removePlatformTenantAdministrator(tenant, membership, reason)).resolves.toBeUndefined();
  const url = new URL(fetchMock.mock.calls[0][0], 'http://test.local');
  expect(url.pathname).toContain(`/tenants/${tenant}/administrators/${membership}`);
  expect(url.searchParams.get('reason')).toBe(reason ?? null);
  expect(callOptions()).toMatchObject({ method: 'DELETE' });
  expect(callOptions().body).toBeUndefined();
});
it.each([401, 403, 404, 409, 422])('preserves structured HTTP %i errors without redirecting', async status => {
  fetchMock.mockResolvedValue(new Response(JSON.stringify({ detail: { code: 'TENANT_ROLE_VERSION_CONFLICT', message: 'Review current version', current_version: 4 } }), { status }));
  await expect(revokePlatformTenantAdministrator(tenant, membership, { expected_version: 3 })).rejects.toMatchObject({
    status, code: 'TENANT_ROLE_VERSION_CONFLICT', message: 'Review current version', detail: { current_version: 4 },
  } satisfies Partial<ApiError>);
});
it('preserves FastAPI 422 field validation details', async () => {
  fetchMock.mockResolvedValue(new Response(JSON.stringify({ detail: [{ loc: ['body', 'reason'], msg: 'Reason is too long' }] }), { status: 422 }));
  await expect(deactivatePlatformTenantAdministrator(tenant, membership, 'reason')).rejects.toMatchObject({ fieldErrors: { reason: ['Reason is too long'] } });
});
it('forwards cancellation from the metadata query', async () => {
  const controller = new AbortController();
  fetchMock.mockImplementation((_url, options) => new Promise((_resolve, reject) => {
    options.signal.addEventListener('abort', () => reject(options.signal.reason));
  }));
  const response = getPlatformTenantAdministrators(tenant, controller.signal);
  controller.abort();
  await expect(response).rejects.toHaveProperty('name', 'AbortError');
});

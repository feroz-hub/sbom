import { NextRequest } from 'next/server';
import { afterEach, beforeEach, expect, it, vi } from 'vitest';
import { GET, POST } from './route';
import { createSession, destroySession } from '@/lib/auth/session-store';
import { entraConfig } from '@/lib/auth/entra-config';

vi.mock('@/lib/auth/entra-config', () => ({ entraConfig: vi.fn() }));
vi.mock('@/lib/auth/session-store', () => ({ SESSION_COOKIE: '__Host-sbom-session', createSession: vi.fn(), destroySession: vi.fn() }));
const config = { tenantId: 'directory', clientId: 'client', scope: 'api://api/access_as_user', authority: 'https://login.microsoftonline.com/directory', redirectUri: 'https://sbom.test/auth/entra-callback' };
beforeEach(() => {
  vi.mocked(entraConfig).mockReturnValue(config);
  vi.mocked(createSession).mockResolvedValue('opaque-session');
  vi.stubEnv('APP_ORIGIN', 'https://sbom.test');
  vi.stubGlobal('fetch', vi.fn().mockResolvedValue(Response.json({ provider: 'MICROSOFT_ENTRA', status: 'USER_ACCESS_PENDING', expires_at: Math.floor(Date.now() / 1000) + 900 })));
});
afterEach(() => { vi.clearAllMocks(); vi.unstubAllGlobals(); vi.unstubAllEnvs(); });
const request = (origin = 'https://sbom.test') => new NextRequest('https://sbom.test/api/auth/entra', { method: 'POST', headers: { origin, cookie: '__Host-sbom-session=previous' }, body: JSON.stringify({ accessToken: 'private-api-token' }) });

it('creates an opaque pending session only after backend access-token validation', async () => {
  const response = await POST(request());
  expect(response.status).toBe(200);
  expect(fetch).toHaveBeenCalledWith(expect.stringContaining('/api/auth/entra/session'), expect.objectContaining({ headers: { Authorization: 'Bearer private-api-token' } }));
  expect(createSession).toHaveBeenCalledWith(expect.objectContaining({ provider: 'MICROSOFT_ENTRA', accessToken: 'private-api-token' }));
  expect(destroySession).toHaveBeenCalledWith('previous');
  expect(await response.text()).not.toContain('private-api-token');
  const cookie = response.headers.get('set-cookie')!;
  for (const flag of ['HttpOnly', 'Secure', 'SameSite=lax', 'opaque-session']) expect(cookie).toContain(flag);
});
it('rejects cross-site exchange before using the token', async () => {
  expect((await POST(request('https://attacker.test'))).status).toBe(403);
  expect(fetch).not.toHaveBeenCalled(); expect(createSession).not.toHaveBeenCalled();
});
it.each([401, 500])('does not establish sessions for upstream failure %s', async status => {
  vi.mocked(fetch).mockResolvedValue(Response.json({ detail: 'secret upstream diagnostics' }, { status }));
  const response = await POST(request());
  expect(response.status).toBe(status === 401 ? 401 : 503);
  expect(await response.text()).not.toContain('secret'); expect(createSession).not.toHaveBeenCalled();
});
it('fails closed for a Native token response', async () => {
  vi.mocked(fetch).mockResolvedValue(Response.json({ provider: 'NATIVE', status: 'READY', expires_at: Date.now() }));
  expect((await POST(request())).status).toBe(503); expect(createSession).not.toHaveBeenCalled();
});
it('does not advertise or accept disabled Microsoft sign-in', async () => {
  vi.mocked(entraConfig).mockReturnValue(null);
  expect(await (await GET()).json()).toEqual({ enabled: false });
  expect((await POST(request())).status).toBe(404);
});

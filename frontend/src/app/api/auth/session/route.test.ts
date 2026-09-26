import { NextRequest } from 'next/server';
import { afterEach, expect, it, vi } from 'vitest';
import { GET } from './route';
import { destroySession, getSession } from '@/lib/auth/session-store';
vi.mock('@/lib/auth/server-config', () => ({ serverAuthConfig: () => ({ enabled: true, apiUrl: 'http://backend.test' }) }));
vi.mock('@/lib/auth/session-store', () => ({ SESSION_COOKIE: 'session', getSession: vi.fn(), destroySession: vi.fn() }));
afterEach(() => { vi.clearAllMocks(); vi.unstubAllGlobals(); });
it.each(['password change','password reset','force change','global disable','security lock','logout all'])('rejects a cookie whose JWT was revoked by %s', async () => {
  vi.mocked(getSession).mockResolvedValue({ provider: 'NATIVE', accessToken: 'revoked-token', expiresAt: Date.now()+60_000, createdAt: Date.now() });
  vi.stubGlobal('fetch', vi.fn().mockResolvedValue(Response.json({ detail: 'Authentication required' }, { status: 401 })));
  const response = await GET(new NextRequest('https://sbom.test/api/auth/session', { headers: { cookie: 'session=opaque' } }));
  expect(await response.json()).toEqual({ authenticated: false }); expect(destroySession).toHaveBeenCalledWith('opaque');
});
it('checks current native authority and never sends token to browser', async () => {
  vi.mocked(getSession).mockResolvedValue({ provider: 'NATIVE', accessToken: 'private-token', expiresAt: Date.now()+60_000, createdAt: Date.now() });
  vi.stubGlobal('fetch', vi.fn().mockResolvedValue(Response.json({ authenticated: true })));
  const response = await GET(new NextRequest('https://sbom.test/api/auth/session', { headers: { cookie: 'session=opaque' } }));
  const body = await response.text(); expect(body).not.toContain('private-token'); expect(body).toContain('NATIVE');
});
it('leaves HCL sessions on their existing path', async () => {
  vi.mocked(getSession).mockResolvedValue({ provider: 'HCL_CS', accessToken: 'hcl-token', expiresAt: Date.now()+60_000, createdAt: Date.now() });
  vi.stubGlobal('fetch', vi.fn());
  const response = await GET(new NextRequest('https://sbom.test/api/auth/session', { headers: { cookie: 'session=opaque' } }));
  expect((await response.json()).authenticated).toBe(true); expect(fetch).not.toHaveBeenCalled();
});

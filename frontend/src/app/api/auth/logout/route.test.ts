import { NextRequest } from 'next/server';
import { afterEach, expect, it, vi } from 'vitest';
import { POST } from './route';
import { getDiscovery, revokeToken } from '@/lib/auth/oidc';
import { destroySession, getSession } from '@/lib/auth/session-store';
vi.mock('@/lib/auth/server-config', () => ({ serverAuthConfig: () => ({ postLogoutRedirectUri: 'https://sbom.test/logged-out' }) }));
vi.mock('@/lib/auth/oidc', () => ({ getDiscovery: vi.fn(), revokeToken: vi.fn() }));
vi.mock('@/lib/auth/session-store', () => ({ SESSION_COOKIE: 'session', getSession: vi.fn(() => ({ provider: 'NATIVE' })), destroySession: vi.fn() }));
afterEach(() => { vi.clearAllMocks(); vi.unstubAllEnvs(); });
it('native logout destroys the local session without contacting HCL', async () => {
  vi.stubEnv('APP_ORIGIN', 'https://sbom.test');
  const response = await POST(new NextRequest('https://sbom.test/api/auth/logout', { method: 'POST', headers: { origin: 'https://sbom.test', cookie: 'session=opaque' } }));
  expect(response.status).toBe(200);
  expect(destroySession).toHaveBeenCalledWith('opaque');
  expect(getDiscovery).not.toHaveBeenCalled();
  expect(response.headers.get('set-cookie')).toContain('Max-Age=0');
});
it('rejects cross-site logout', async () => {
  const response = await POST(new NextRequest('https://sbom.test/api/auth/logout', { method: 'POST', headers: { origin: 'https://evil.test' } }));
  expect(response.status).toBe(403);
  expect(destroySession).not.toHaveBeenCalled();
});

it('preserves HCL provider revocation and end-session redirect', async () => {
  vi.stubEnv('APP_ORIGIN', 'https://sbom.test');
  vi.mocked(getSession).mockResolvedValueOnce({ provider: 'HCL_CS', accessToken: 'hcl-access', refreshToken: 'hcl-refresh', expiresAt: Date.now()+10000, createdAt: Date.now() });
  vi.mocked(getDiscovery).mockResolvedValueOnce({ issuer: 'https://hcl.test', authorization_endpoint: 'https://hcl.test/authorize', token_endpoint: 'https://hcl.test/token', jwks_uri: 'https://hcl.test/jwks', revocation_endpoint: 'https://hcl.test/revoke', end_session_endpoint: 'https://hcl.test/logout' });
  vi.mocked(revokeToken).mockResolvedValue(undefined);
  const response = await POST(new NextRequest('https://sbom.test/api/auth/logout', { method: 'POST', headers: { origin: 'https://sbom.test', cookie: 'session=hcl-id' } }));
  expect(revokeToken).toHaveBeenCalledTimes(2); expect((await response.json()).redirectUrl).toContain('https://hcl.test/logout');
  expect(destroySession).toHaveBeenCalledWith('hcl-id');
});

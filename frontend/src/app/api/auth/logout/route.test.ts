import { NextRequest } from 'next/server';
import { afterEach, expect, it, vi } from 'vitest';
import { POST } from './route';
import { getDiscovery } from '@/lib/auth/oidc';
import { destroySession } from '@/lib/auth/session-store';
vi.mock('@/lib/auth/server-config', () => ({ serverAuthConfig: () => ({ postLogoutRedirectUri: 'https://sbom.test/logged-out' }) }));
vi.mock('@/lib/auth/oidc', () => ({ getDiscovery: vi.fn(), revokeToken: vi.fn() }));
vi.mock('@/lib/auth/session-store', () => ({ SESSION_COOKIE: 'session', getSession: () => ({ provider: 'NATIVE' }), destroySession: vi.fn() }));
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

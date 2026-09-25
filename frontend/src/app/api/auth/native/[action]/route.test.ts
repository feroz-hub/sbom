import { NextRequest } from 'next/server';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import { POST } from './route';
import { createSession, destroySession } from '@/lib/auth/session-store';
vi.mock('@/lib/auth/session-store', () => ({ SESSION_COOKIE: '__Host-sbom-session', createSession: vi.fn(() => 'opaque-id'), destroySession: vi.fn() }));
beforeEach(() => { vi.stubEnv('NATIVE_AUTH_ENABLED', 'true'); vi.stubEnv('APP_ORIGIN', 'https://sbom.test'); });
afterEach(() => { vi.unstubAllGlobals(); vi.unstubAllEnvs(); vi.clearAllMocks(); });
const context = (action = 'login') => ({ params: Promise.resolve({ action }) });
const request = (origin = 'https://sbom.test') => new NextRequest('https://sbom.test/api/auth/native/login', {
  method: 'POST', headers: { origin, cookie: '__Host-sbom-session=old-id' }, body: JSON.stringify({ email: 'a@b.test', password: 'private' }),
});
describe('native BFF', () => {
  it('keeps JWT server-side and rotates the opaque secure cookie', async () => {
    vi.stubGlobal('fetch', vi.fn().mockResolvedValue(Response.json({ access_token: 'secret-jwt', expires_in: 900 })));
    const response = await POST(request(), context());
    expect(await response.text()).not.toContain('secret-jwt');
    expect(createSession).toHaveBeenCalledWith(expect.objectContaining({ provider: 'NATIVE', accessToken: 'secret-jwt' }));
    expect(destroySession).toHaveBeenCalledWith('old-id');
    const cookie = response.headers.get('set-cookie');
    expect(cookie).toContain('HttpOnly'); expect(cookie).toContain('Secure'); expect(cookie).toContain('opaque-id');
  });
  it('rejects hostile origins before contacting the backend', async () => {
    vi.stubGlobal('fetch', vi.fn());
    expect((await POST(request('https://evil.test'), context())).status).toBe(403);
    expect(fetch).not.toHaveBeenCalled();
  });
  it('does not reflect backend validation secrets', async () => {
    vi.stubGlobal('fetch', vi.fn().mockResolvedValue(Response.json({ detail: 'private password' }, { status: 422 })));
    expect(await (await POST(request(), context())).text()).not.toContain('private password');
  });
  it('activation does not create a session', async () => {
    vi.stubGlobal('fetch', vi.fn().mockResolvedValue(Response.json({ status: 'ACTIVE' })));
    const response = await POST(request(), context('activate'));
    expect(response.status).toBe(200); expect(createSession).not.toHaveBeenCalled();
  });
});

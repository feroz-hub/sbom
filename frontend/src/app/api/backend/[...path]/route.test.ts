import { NextRequest } from 'next/server';
import { afterEach, describe, expect, it, vi } from 'vitest';
import { DELETE, GET } from './route';

vi.mock('@/lib/auth/server-config', () => ({
  serverAuthConfig: () => ({ enabled: false, apiUrl: 'http://backend.test' }),
}));
vi.mock('@/lib/auth/oidc', () => ({ getDiscovery: vi.fn(), refreshTokens: vi.fn() }));
vi.mock('@/lib/auth/session-store', () => ({
  SESSION_COOKIE: 'session',
  destroySession: vi.fn(),
  getSession: vi.fn(),
  setSession: vi.fn(),
  singleFlightRefresh: vi.fn(),
}));

afterEach(() => {
  vi.unstubAllGlobals();
  vi.restoreAllMocks();
});

const path = ['api', 'tenants', '3', 'users', '6'];
const context = () => ({ params: Promise.resolve({ path }) });

describe('backend response proxy', () => {
  it.each([204, 205, 304])('forwards status %s without a body even with JSON content type', async (status) => {
    const upstream = new Response(null, {
      status,
      headers: { 'Content-Type': 'application/json', 'X-Request-ID': 'test-request' },
    });
    vi.stubGlobal('fetch', vi.fn().mockResolvedValue(upstream));
    vi.spyOn(console, 'warn').mockImplementation(() => {});

    const response = await DELETE(new NextRequest('http://frontend.test/api/backend/' + path.join('/'), {
      method: 'DELETE', headers: { origin: 'https://localhost:3000' },
    }), context());

    expect(response.status).toBe(status);
    expect(response.body).toBeNull();
    expect(await response.text()).toBe('');
    expect(response.headers.get('x-request-id')).toBe('test-request');
    expect(fetch).toHaveBeenCalledWith(new URL('http://backend.test/' + path.join('/')), expect.objectContaining({ method: 'DELETE' }));
  });

  it.each([200, 409])('preserves JSON payloads for status %s', async (status) => {
    const payload = status === 200 ? { items: [] } : { detail: 'The last administrator cannot be removed.' };
    vi.stubGlobal('fetch', vi.fn().mockResolvedValue(Response.json(payload, { status })));
    vi.spyOn(console, 'warn').mockImplementation(() => {});

    const response = await GET(new NextRequest('http://frontend.test/api/backend/' + path.join('/')), context());

    expect(response.status).toBe(status);
    expect(await response.json()).toEqual(payload);
  });
});

it.each([
  ['api', 'auth', 'native', 'login'],
  ['api', '%61uth', 'native', 'login'],
  ['api', 'auth', 'other', '..', 'native', 'login'],
])('blocks native token responses through generic proxy %s', async (...parts) => {
  vi.stubGlobal('fetch', vi.fn());
  const response = await GET(new NextRequest('http://frontend.test/api/backend/test'), { params: Promise.resolve({ path: parts }) });
  expect(response.status).toBe(404);
  expect(fetch).not.toHaveBeenCalled();
});

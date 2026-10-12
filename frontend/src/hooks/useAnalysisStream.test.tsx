// @vitest-environment jsdom

import { QueryClient, QueryClientProvider } from '@tanstack/react-query';
import { act, renderHook, waitFor } from '@testing-library/react';
import type { ReactNode } from 'react';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';

vi.mock('@/lib/api', async () => {
  const actual = await vi.importActual<typeof import('@/lib/api')>('@/lib/api');
  return { ...actual, BASE_URL: 'http://test.local' };
});

import { AuthProvider, useAuth } from './useAuth';
import { useAnalysisStream } from './useAnalysisStream';

vi.mock('@/lib/auth', async () => ({
  ...(await vi.importActual<typeof import('@/lib/auth')>('@/lib/auth')),
  resolveAuthConfig: () => ({ enabled: true, issuer: 'https://identity.test', clientId: 'sbom', redirectUri: 'http://localhost/auth/callback', postLogoutRedirectUri: 'http://localhost', scopes: 'openid profile email' }),
}));
vi.mock('@/lib/auth/logout-navigation', () => ({ followLogoutRedirect: vi.fn() }));
let client: QueryClient;
let analysisFetch = vi.fn<(url: string, init: RequestInit) => Promise<Response>>();
function wrapper({ children }: { children: ReactNode }) {
  return <QueryClientProvider client={client}><AuthProvider>{children}</AuthProvider></QueryClientProvider>;
}
const tenants = [7, 1].map(id => ({ id, name: `Synthetic tenant ${id}`, slug: `synthetic-${id}`, status: 'ACTIVE', membership_status: 'ACTIVE', roles: ['SECURITY_ANALYST'] }));
function json(body: unknown) { return new Response(JSON.stringify(body), { status: 200, headers: { 'Content-Type': 'application/json' } }); }
function emptyStream() { return new Response(new ReadableStream({ start(controller) { controller.close(); } })); }
async function mount() {
  const hook = renderHook(() => ({ ...useAnalysisStream(42), auth: useAuth() }), { wrapper });
  await waitFor(() => expect(hook.result.current.auth.bootstrapState).toBe('ready'));
  expect(hook.result.current.auth.activeTenantId).toBe('7');
  expect(hook.result.current.auth.hasPermission('analysis:run')).toBe(true);
  return hook;
}

describe('useAnalysisStream', () => {
  beforeEach(() => {
    sessionStorage.clear();
    sessionStorage.setItem('sbom_active_tenant_id', '7');
    client = new QueryClient({ defaultOptions: { queries: { retry: false, staleTime: 300_000, refetchOnWindowFocus: false } } });
    analysisFetch = vi.fn<(url: string, init: RequestInit) => Promise<Response>>().mockResolvedValue(emptyStream());
    vi.stubGlobal('fetch', vi.fn((url: string, init?: RequestInit) => {
      if (url === '/api/auth/session') return Promise.resolve(json({ authenticated: true }));
      if (url.endsWith('/api/auth/me')) {
        const id = Number((init?.headers as Record<string, string> | undefined)?.['X-Tenant-ID'] ?? 7);
        return Promise.resolve(json({ authenticated: true, user_id: 3, tenant_id: id, roles: ['SECURITY_ANALYST'], permissions: ['analysis:run', 'sbom:read'], is_platform_admin: false,
          auth_context: { status: 'READY', user: { id: 3 }, tenant_context: { active_tenant: tenants.find(tenant => tenant.id === id), available_tenants: tenants } } }));
      }
      if (url === '/api/auth/logout') return Promise.resolve(json({ redirectUrl: '/logged-out' }));
      if (url.endsWith('/api/sboms/42/analyze/stream')) return analysisFetch(url, init!);
      throw new Error(`Unexpected test request: ${url}`);
    }));
  });

  afterEach(() => {
    client.clear();
    vi.unstubAllGlobals();
    sessionStorage.clear();
  });

  it('guards duplicate manual starts for the same SBOM', async () => {
    const { result } = await mount();

    act(() => {
      void result.current.startAnalysis();
      void result.current.startAnalysis();
    });

    await waitFor(() => expect(analysisFetch).toHaveBeenCalledTimes(1));
    expect(analysisFetch).toHaveBeenCalledWith(
      'http://test.local/api/sboms/42/analyze/stream',
      expect.objectContaining({
        method: 'POST',
        headers: expect.objectContaining({
          'Content-Type': 'application/json',
          'Idempotency-Key': expect.stringMatching(/^analysis-sbom-42-/),
        }),
      }),
    );
  });

  it('sends the active tenant on the stream request', async () => {
    const { result } = await mount();

    await act(async () => {
      await result.current.startAnalysis();
    });

    expect(analysisFetch).toHaveBeenCalledWith(
      'http://test.local/api/sboms/42/analyze/stream',
      expect.objectContaining({
        headers: expect.objectContaining({ 'X-Tenant-ID': '7' }),
      }),
    );
  });

  it('sends no request and reports an inline error when no tenant is selected', async () => {
    const { result } = await mount();
    sessionStorage.removeItem('sbom_active_tenant_id');

    await act(async () => {
      await result.current.startAnalysis();
    });

    expect(analysisFetch).not.toHaveBeenCalled();
    expect(result.current.state.phase).toBe('error');
    expect(result.current.state.error).toBe('Select a tenant before running analysis.');
  });

  it('uses the newly selected tenant on the next request after a tenant switch', async () => {
    const { result } = await mount();

    await act(async () => {
      await result.current.startAnalysis();
    });

    await act(async () => { await result.current.auth.selectTenant('1'); });
    await waitFor(() => expect(result.current.auth.activeTenantId).toBe('1'));

    await act(async () => {
      await result.current.startAnalysis();
    });

    const calls = analysisFetch.mock.calls;
    expect(calls).toHaveLength(2);
    expect(new Headers(calls[0][1].headers).get('X-Tenant-ID')).toBe('7');
    expect(new Headers(calls[1][1].headers).get('X-Tenant-ID')).toBe('1');
  });

  it('cancels an active request and returns to idle without inventing completion', async () => {
    let signal!: AbortSignal;
    analysisFetch.mockImplementation((_url: string, init: RequestInit) => new Promise((_resolve, reject) => {
      signal = init.signal!;
      signal.addEventListener('abort', () => reject(new DOMException('Canceled', 'AbortError')));
    }));
    const { result } = await mount(); let task!: Promise<void>;
    act(() => { task = result.current.startAnalysis(); });
    await waitFor(() => expect(result.current.state.phase).toBe('connecting'));
    await act(async () => { result.current.cancel(); await task; });
    expect(signal.aborted).toBe(true); expect(result.current.state.phase).toBe('idle'); expect(result.current.state.summary).toBeNull();
  });
  it('allows a new analysis after tenant switching aborts the prior fetch', async () => {
    analysisFetch.mockImplementationOnce((_url: string, init: RequestInit) => new Promise((_resolve, reject) => {
      init.signal!.addEventListener('abort', () => reject(new DOMException('Context changed', 'AbortError')));
    })).mockResolvedValueOnce(emptyStream());
    const { result } = await mount(); let task!: Promise<void>;
    act(() => { task = result.current.startAnalysis(); });
    await waitFor(() => expect(result.current.state.phase).toBe('connecting'));
    await act(async () => { await result.current.auth.selectTenant('1'); });
    await act(async () => { await task; });
    await waitFor(() => expect(result.current.auth.activeTenantId).toBe('1'));
    await act(async () => { await result.current.startAnalysis(); });
    expect(analysisFetch).toHaveBeenCalledTimes(2);
    expect(new Headers(analysisFetch.mock.calls[1][1].headers).get('X-Tenant-ID')).toBe('1');
  });
  it.each(['tenant switch', 'logout'] as const)('%s aborts active requests and ignores old terminal results/cache writes', async action => {
    let finish!: (value: Response) => void; let signal!: AbortSignal;
    analysisFetch.mockImplementation((_url: string, init: RequestInit) => new Promise(resolve => { signal = init.signal!; finish = resolve; }));
    const { result } = await mount(); client.setQueryData(['privileged', 'old tenant'], 'old data'); let task!: Promise<void>;
    act(() => { task = result.current.startAnalysis(); });
    await waitFor(() => expect(finish).toBeDefined());
    await act(async () => { if (action === 'logout') result.current.auth.logout(); else await result.current.auth.selectTenant('1'); });
    expect(signal.aborted).toBe(true);
    expect(client.getQueryData(['privileged', 'old tenant'])).toBeUndefined();
    await act(async () => { finish(new Response('event: complete\ndata: {"runId":8,"status":"FINDINGS","total":81}\n\n')); await task; });
    expect(result.current.state.summary).toBeNull(); expect(result.current.state.phase).not.toBe('done');
    expect(client.getQueryCache().getAll()).toHaveLength(0);
    if (action === 'logout') expect(result.current.auth.isAuthenticated).toBe(false);
    else expect(result.current.auth.activeTenantId).toBe('1');
  });
});

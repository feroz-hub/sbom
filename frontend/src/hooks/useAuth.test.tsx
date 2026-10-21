// @vitest-environment jsdom

import { QueryClient, QueryClientProvider } from '@tanstack/react-query';
import { act, render, screen, waitFor } from '@testing-library/react';
import { useEffect, type ReactNode } from 'react';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';

import { AuthProvider, useAuth } from '@/hooks/useAuth';

const followLogoutRedirect = vi.hoisted(() => vi.fn());
vi.mock('@/lib/auth/logout-navigation', () => ({ followLogoutRedirect }));

vi.mock('@/lib/auth', async () => {
  const actual = await vi.importActual<typeof import('@/lib/auth')>('@/lib/auth');
  return {
    ...actual,
    resolveAuthConfig: () => ({
      enabled: true,
      issuer: 'https://identity.test',
      clientId: 'sbom',
      redirectUri: 'http://localhost/auth/callback',
      postLogoutRedirectUri: 'http://localhost',
      scopes: 'openid profile email',
    }),
  };
});

function jsonResponse(body: unknown, status = 200): Response {
  return new Response(JSON.stringify(body), {
    status,
    headers: { 'Content-Type': 'application/json' },
  });
}

let latestAuth: ReturnType<typeof useAuth> | null = null;

function Probe() {
  const auth = useAuth();
  // Published after commit (not during render) so tests can drive
  // selectTenant/logout directly.
  useEffect(() => {
    latestAuth = auth;
  }, [auth]);
  return (
    <div>
      <span data-testid="status">{auth.authStatus}</span>
      <span data-testid="bootstrap-state">{auth.bootstrapState}</span>
      <span data-testid="session-authenticated">{String(auth.sessionAuthenticated)}</span>
      <span data-testid="authenticated">{String(auth.isAuthenticated)}</span>
      <span data-testid="active-tenant">{auth.activeTenantId ?? ''}</span>
      <span data-testid="platform-context">{String(auth.isPlatformContext)}</span>
      <span data-testid="tenant-names">{auth.tenants.map((tenant) => tenant.name).join('|')}</span>
      <span data-testid="email">{auth.user?.email ?? ''}</span>
    </div>
  );
}

function makeQueryClient() {
  return new QueryClient({ defaultOptions: { queries: { retry: false } } });
}

function wrap(children: ReactNode, queryClient: QueryClient = makeQueryClient()) {
  return (
    <QueryClientProvider client={queryClient}>
      <AuthProvider>{children}</AuthProvider>
    </QueryClientProvider>
  );
}

const identity = {
  id: '00000000-0000-4000-8000-000000000003',
  email: 'ferozebasha.s@hcltech.com',
  display_name: 'Feroze Basha',
};

function meBody(
  status: string,
  availableTenants: Array<Record<string, unknown>>,
  tenantId: string | null = null,
) {
  return {
    authenticated: true,
    user_id: '00000000-0000-4000-8000-000000000003',
    email: identity.email,
    display_name: identity.display_name,
    tenant_id: tenantId,
    roles: tenantId ? ['TENANT_ADMIN'] : [],
    permissions: tenantId ? ['tenant:user:read'] : [],
    is_platform_admin: false,
    auth_context: {
      status,
      user: identity,
      tenant_context: {
        active_tenant: tenantId
          ? availableTenants.find((tenant) => tenant.id === tenantId) ?? null
          : null,
        available_tenants: availableTenants,
      },
    },
  };
}

/**
 * ``/api/auth/me`` for a platform administrator: READY with no active tenant
 * unless one was explicitly requested, and ``available_tenants`` holding only
 * real memberships.
 */
function platformAdminMeBody({
  available = [] as Array<Record<string, unknown>>,
  active = null as Record<string, unknown> | null,
} = {}) {
  return {
    authenticated: true,
    user_id: '00000000-0000-4000-8000-000000000003',
    email: identity.email,
    display_name: identity.display_name,
    tenant_id: active ? active.id : null,
    roles: active ? ['VIEWER'] : ['PLATFORM_ADMIN'],
    permissions: active
      ? ['sbom:read', 'dashboard:read']
      : ['platform:admin', 'platform:tenant:create'],
    is_platform_admin: true,
    auth_context: {
      status: 'READY',
      user: identity,
      platform: { is_platform_admin: true, permissions: ['platform:tenant:read', 'platform:tenant:create'] },
      tenant_context: { active_tenant: active, available_tenants: active ? [...available, active] : available },
    },
  };
}

/** A tenant a platform admin reaches by authority, not by membership. */
function platformReachableTenant(id: string) {
  return {
    id,
    name: `Tenant ${id}`,
    slug: `tenant-${id}`,
    status: 'ACTIVE',
    membership_status: null,
    current_role: 'PLATFORM_ADMIN',
    roles: ['PLATFORM_ADMIN'],
    platform_context_available: true,
  };
}

const wellysis = {
  id: '00000000-0000-4000-8000-000000000007',
  name: 'Wellysis',
  slug: 'wellysis',
  status: 'ACTIVE',
  membership_status: 'ACTIVE',
  current_role: 'TENANT_ADMIN',
  roles: ['TENANT_ADMIN'],
};
const defaultTenant = {
  id: '00000000-0000-4000-8000-000000000001',
  name: 'Default Tenant',
  slug: 'default',
  status: 'ACTIVE',
  membership_status: 'ACTIVE',
  current_role: 'VIEWER',
  roles: ['VIEWER'],
};

/** Headers passed to the last ``/api/auth/me`` call, or null when none were. */
function lastMeTenantHeader(fetchMock: { mock: { calls: unknown[][] } }): string | null {
  const meCalls = fetchMock.mock.calls.filter(([url]) => String(url).includes('/api/auth/me'));
  const last = meCalls.at(-1);
  if (!last) return null;
  const init = last[1] as { headers?: Record<string, string> } | undefined;
  return init?.headers?.['X-Tenant-ID'] ?? null;
}

describe('AuthProvider membership-based tenant context', () => {
  beforeEach(() => {
    sessionStorage.clear();
    latestAuth = null;
    vi.restoreAllMocks();
  });

  it('keeps a valid session without a tenant claim authenticated and selects its one SBOM membership', async () => {
    const tenant = {
      id: '00000000-0000-4000-8000-000000000007',
      name: 'Wellysis',
      slug: 'wellysis',
      membership_status: 'ACTIVE',
      current_role: 'TENANT_ADMIN',
      roles: ['TENANT_ADMIN'],
    };
    const fetchMock = vi.spyOn(globalThis, 'fetch');
    fetchMock
      .mockResolvedValueOnce(jsonResponse({ authenticated: true }))
      .mockResolvedValueOnce(jsonResponse(meBody('READY', [tenant], '00000000-0000-4000-8000-000000000007')));

    render(wrap(<Probe />));

    await waitFor(() => expect(screen.getByTestId('status')).toHaveTextContent('authenticated'));
    expect(screen.getByTestId('authenticated')).toHaveTextContent('true');
    expect(screen.getByTestId('active-tenant')).toHaveTextContent('00000000-0000-4000-8000-000000000007');
    expect(screen.getByTestId('tenant-names')).toHaveTextContent('Wellysis');
    expect(screen.getByTestId('email')).toHaveTextContent(identity.email);
    expect(fetchMock).toHaveBeenCalledTimes(2);
  });

  it('uses access pending without restarting OIDC when the valid session has no membership', async () => {
    const fetchMock = vi.spyOn(globalThis, 'fetch');
    fetchMock
      .mockResolvedValueOnce(jsonResponse({ authenticated: true }))
      .mockResolvedValueOnce(jsonResponse(meBody('NO_TENANT', [])));

    render(wrap(<Probe />));

    await waitFor(() => expect(screen.getByTestId('status')).toHaveTextContent('access-pending'));
    expect(screen.getByTestId('session-authenticated')).toHaveTextContent('true');
    expect(screen.getByTestId('authenticated')).toHaveTextContent('false');
    expect(screen.getByTestId('email')).toHaveTextContent(identity.email);
    expect(fetchMock).toHaveBeenCalledTimes(2);
    expect(fetchMock.mock.calls.every(([url]) => !String(url).includes('/api/auth/login'))).toBe(true);
  });

  it('requires tenant selection for multiple active memberships with nothing persisted', async () => {
    const tenants = [wellysis, defaultTenant];
    const fetchMock = vi.spyOn(globalThis, 'fetch');
    fetchMock
      .mockResolvedValueOnce(jsonResponse({ authenticated: true }))
      .mockResolvedValueOnce(jsonResponse(meBody('TENANT_SELECTION_REQUIRED', tenants)));

    render(wrap(<Probe />));

    await waitFor(() =>
      expect(screen.getByTestId('status')).toHaveTextContent('tenant-selection-required'),
    );
    // Populated switcher, but nothing selected and the app is not yet "ready" —
    // this is what keeps tenant-scoped pages from mounting unscoped.
    expect(screen.getByTestId('tenant-names')).toHaveTextContent('Wellysis|Default Tenant');
    expect(screen.getByTestId('active-tenant')).toHaveTextContent('');
    expect(screen.getByTestId('authenticated')).toHaveTextContent('false');
    expect(sessionStorage.getItem('sbom_active_tenant_id')).toBeNull();
    // No tenant-scoped roles or permissions are exposed before selection.
    // Probe publishes latestAuth in a passive effect after the DOM commit.
    await waitFor(() => {
      expect(latestAuth?.user?.roles).toEqual([]);
      expect(latestAuth?.user?.permissions).toEqual([]);
      expect(latestAuth?.hasPermission('tenant:user:read')).toBe(false);
    });
    expect(fetchMock).toHaveBeenCalledTimes(2);
  });

  it('discards a legacy integer preference before sending an authentication-context header', async () => {
    sessionStorage.setItem('sbom_active_tenant_id', '999');
    const fetchMock = vi.spyOn(globalThis, 'fetch')
      .mockResolvedValueOnce(jsonResponse({ authenticated: true }))
      .mockResolvedValueOnce(jsonResponse(meBody('READY', [wellysis, defaultTenant], null)));
    render(wrap(<Probe />));
    await waitFor(() => expect(screen.getByTestId('status')).toHaveTextContent('tenant-selection-required'));
    expect(fetchMock).toHaveBeenCalledTimes(2);
    expect(fetchMock.mock.calls[1][1]?.headers).toEqual({});
    expect(sessionStorage.getItem('sbom_active_tenant_id')).toBeNull();
  });

  it('clears an unauthorized UUID tenant and requires selection when several memberships exist', async () => {
    sessionStorage.setItem('sbom_active_tenant_id', '00000000-0000-4000-8000-000000000999');
    const fetchMock = vi.spyOn(globalThis, 'fetch');
    fetchMock
      .mockResolvedValueOnce(jsonResponse({ authenticated: true }))
      .mockResolvedValueOnce(jsonResponse({ detail: { code: 'IAM_UNAUTHORIZED_TENANT' } }, 403))
      .mockResolvedValueOnce(jsonResponse(meBody('READY', [wellysis, defaultTenant], null)));

    render(wrap(<Probe />));

    await waitFor(() =>
      expect(screen.getByTestId('status')).toHaveTextContent('tenant-selection-required'),
    );
    expect(sessionStorage.getItem('sbom_active_tenant_id')).toBeNull();
    expect(screen.getByTestId('active-tenant')).toHaveTextContent('');
  });

  it('persists the choice, clears cached data, and becomes ready once selectTenant resolves', async () => {
    const queryClient = makeQueryClient();
    queryClient.setQueryData(['sboms'], [{ id: '00000000-0000-4000-8000-000000000001' }]);
    queryClient.setQueryData(['platform-summary'], { total_tenants: 4 });
    queryClient.setQueryData(['platform-administrators'], [{ user_id: '00000000-0000-4000-8000-000000000003' }]);

    const fetchMock = vi.spyOn(globalThis, 'fetch');
    fetchMock
      .mockResolvedValueOnce(jsonResponse({ authenticated: true }))
      .mockResolvedValueOnce(jsonResponse(meBody('TENANT_SELECTION_REQUIRED', [wellysis, defaultTenant])))
      // selectTenant re-runs the whole auth context with the chosen tenant.
      .mockResolvedValueOnce(jsonResponse({ authenticated: true }))
      .mockResolvedValueOnce(jsonResponse(meBody('READY', [wellysis, defaultTenant], '00000000-0000-4000-8000-000000000007')));

    render(wrap(<Probe />, queryClient));
    await waitFor(() =>
      expect(screen.getByTestId('status')).toHaveTextContent('tenant-selection-required'),
    );

    await act(async () => {
      await latestAuth!.selectTenant('00000000-0000-4000-8000-000000000007');
    });

    await waitFor(() => expect(screen.getByTestId('status')).toHaveTextContent('authenticated'));
    expect(sessionStorage.getItem('sbom_active_tenant_id')).toBe('00000000-0000-4000-8000-000000000007');
    expect(screen.getByTestId('active-tenant')).toHaveTextContent('00000000-0000-4000-8000-000000000007');
    expect(queryClient.getQueryData(['sboms'])).toBeUndefined();
    expect(queryClient.getQueryData(['platform-summary'])).toBeUndefined();
    expect(queryClient.getQueryData(['platform-administrators'])).toBeUndefined();
    // The re-resolved context was fetched with the selected tenant's header.
    expect(lastMeTenantHeader(fetchMock)).toBe('00000000-0000-4000-8000-000000000007');
  });

  it('sends the newly selected tenant on subsequent auth-context requests when switching', async () => {
    sessionStorage.setItem('sbom_active_tenant_id', '00000000-0000-4000-8000-000000000007');
    const fetchMock = vi.spyOn(globalThis, 'fetch');
    fetchMock
      .mockResolvedValueOnce(jsonResponse({ authenticated: true }))
      .mockResolvedValueOnce(jsonResponse(meBody('READY', [wellysis, defaultTenant], '00000000-0000-4000-8000-000000000007')))
      .mockResolvedValueOnce(jsonResponse({ authenticated: true }))
      .mockResolvedValueOnce(jsonResponse(meBody('READY', [wellysis, defaultTenant], '00000000-0000-4000-8000-000000000001')));

    render(wrap(<Probe />));
    await waitFor(() => expect(screen.getByTestId('status')).toHaveTextContent('authenticated'));
    expect(lastMeTenantHeader(fetchMock)).toBe('00000000-0000-4000-8000-000000000007');

    await act(async () => {
      await latestAuth!.selectTenant('00000000-0000-4000-8000-000000000001');
    });

    await waitFor(() => expect(screen.getByTestId('active-tenant')).toHaveTextContent('00000000-0000-4000-8000-000000000001'));
    expect(lastMeTenantHeader(fetchMock)).toBe('00000000-0000-4000-8000-000000000001');
    expect(sessionStorage.getItem('sbom_active_tenant_id')).toBe('00000000-0000-4000-8000-000000000001');
  });

  it('clears the active tenant on logout', async () => {
    const queryClient = makeQueryClient();
    queryClient.setQueryData(['platform-summary'], { total_tenants: 4 });
    queryClient.setQueryData(['platform-administrators'], [{ user_id: '00000000-0000-4000-8000-000000000003' }]);
    const fetchMock = vi.spyOn(globalThis, 'fetch');
    fetchMock
      .mockResolvedValueOnce(jsonResponse({ authenticated: true }))
      .mockResolvedValueOnce(jsonResponse(meBody('READY', [wellysis], '00000000-0000-4000-8000-000000000007')));

    render(wrap(<Probe />, queryClient));
    await waitFor(() => expect(screen.getByTestId('status')).toHaveTextContent('authenticated'));
    expect(sessionStorage.getItem('sbom_active_tenant_id')).toBe('00000000-0000-4000-8000-000000000007');

    // Never-settling logout call: keeps the jsdom navigation that follows it
    // out of the test while the synchronous teardown still runs.
    fetchMock.mockImplementation(() => new Promise<Response>(() => {}));

    act(() => {
      latestAuth!.logout();
    });

    expect(sessionStorage.getItem('sbom_active_tenant_id')).toBeNull();
    expect(queryClient.getQueryData(['platform-summary'])).toBeUndefined();
    expect(queryClient.getQueryData(['platform-administrators'])).toBeUndefined();
    await waitFor(() => expect(screen.getByTestId('bootstrap-state')).toHaveTextContent('logging-out'));
    expect(screen.getByTestId('status')).toHaveTextContent('loading');
    expect(screen.getByTestId('active-tenant')).toHaveTextContent('');
    expect(fetchMock).toHaveBeenCalledWith('/api/auth/logout', {
      method: 'POST', credentials: 'include', cache: 'no-store',
    });
  });

  it('follows the OIDC end-session redirect without restarting login', async () => {
    const fetchMock = vi.spyOn(globalThis, 'fetch');
    fetchMock
      .mockResolvedValueOnce(jsonResponse({ authenticated: true }))
      .mockResolvedValueOnce(jsonResponse(meBody('READY', [wellysis], '00000000-0000-4000-8000-000000000007')))
      .mockResolvedValueOnce(jsonResponse({ redirectUrl: 'https://identity.test/security/endsession?post_logout_redirect_uri=...' }));

    render(wrap(<Probe />));
    await waitFor(() => expect(screen.getByTestId('status')).toHaveTextContent('authenticated'));
    act(() => latestAuth!.logout());

    await waitFor(() => expect(screen.getByTestId('bootstrap-state')).toHaveTextContent('logging-out'));
    await waitFor(() => expect(followLogoutRedirect).toHaveBeenCalledWith('https://identity.test/security/endsession?post_logout_redirect_uri=...'));
    expect(fetchMock).toHaveBeenCalledWith('/api/auth/logout', {
      method: 'POST', credentials: 'include', cache: 'no-store',
    });
    expect(fetchMock.mock.calls.some(([url]) => String(url).includes('/api/auth/login'))).toBe(false);
  });

  it.each(['missing-redirect', 'network-failure'])('keeps Native logout local on %s', async failure => {
    const fetchMock = vi.spyOn(globalThis, 'fetch');
    fetchMock
      .mockResolvedValueOnce(jsonResponse({ authenticated: true, provider: 'NATIVE' }))
      .mockResolvedValueOnce(jsonResponse(meBody('READY', [wellysis], '00000000-0000-4000-8000-000000000007')));
    if (failure === 'network-failure') fetchMock.mockRejectedValueOnce(new Error('Unavailable'));
    else fetchMock.mockResolvedValueOnce(jsonResponse({}));
    render(wrap(<Probe />));
    await waitFor(() => expect(screen.getByTestId('status')).toHaveTextContent('authenticated'));
    act(() => latestAuth!.logout());
    await waitFor(() => expect(followLogoutRedirect).toHaveBeenCalledWith('/logged-out?provider=native'));
  });

  it('restores a valid persisted tenant on initial load', async () => {
    sessionStorage.setItem('sbom_active_tenant_id', '00000000-0000-4000-8000-000000000007');
    const tenant = {
      id: '00000000-0000-4000-8000-000000000007',
      name: 'Wellysis',
      slug: 'wellysis',
      status: 'ACTIVE',
      membership_status: 'ACTIVE',
      current_role: 'TENANT_ADMIN',
      roles: ['TENANT_ADMIN'],
    };
    const fetchMock = vi.spyOn(globalThis, 'fetch');
    fetchMock
      .mockResolvedValueOnce(jsonResponse({ authenticated: true }))
      .mockResolvedValueOnce(jsonResponse(meBody('READY', [tenant], '00000000-0000-4000-8000-000000000007')));

    render(wrap(<Probe />));

    await waitFor(() => expect(screen.getByTestId('status')).toHaveTextContent('authenticated'));
    expect(screen.getByTestId('active-tenant')).toHaveTextContent('00000000-0000-4000-8000-000000000007');
  });

  it('clears an unauthorized UUID tenant and auto-selects valid single membership', async () => {
    sessionStorage.setItem('sbom_active_tenant_id', '00000000-0000-4000-8000-000000000999');
    const tenant = {
      id: '00000000-0000-4000-8000-000000000007',
      name: 'Wellysis',
      slug: 'wellysis',
      status: 'ACTIVE',
      membership_status: 'ACTIVE',
      current_role: 'TENANT_ADMIN',
      roles: ['TENANT_ADMIN'],
    };
    const fetchMock = vi.spyOn(globalThis, 'fetch');
    fetchMock
      .mockResolvedValueOnce(jsonResponse({ authenticated: true }))
      .mockResolvedValueOnce(jsonResponse({ detail: { code: 'IAM_UNAUTHORIZED_TENANT' } }, 403))
      .mockResolvedValueOnce(jsonResponse(meBody('READY', [tenant], null)))
      .mockResolvedValueOnce(jsonResponse(meBody('READY', [tenant], '00000000-0000-4000-8000-000000000007')));

    render(wrap(<Probe />));

    await waitFor(() => expect(screen.getByTestId('status')).toHaveTextContent('authenticated'));
    expect(screen.getByTestId('active-tenant')).toHaveTextContent('00000000-0000-4000-8000-000000000007');
    expect(sessionStorage.getItem('sbom_active_tenant_id')).toBe('00000000-0000-4000-8000-000000000007');
  });
});

describe('AuthProvider platform administrator context', () => {
  beforeEach(() => {
    sessionStorage.clear();
    latestAuth = null;
    vi.restoreAllMocks();
  });

  it('signs a platform admin with no memberships into platform context', async () => {
    const fetchMock = vi.spyOn(globalThis, 'fetch');
    fetchMock
      .mockResolvedValueOnce(jsonResponse({ authenticated: true }))
      .mockResolvedValueOnce(jsonResponse(platformAdminMeBody()))
      // Would be the legacy tenant-list fallback — a platform admin must not
      // pull every tenant in the deployment at sign-in.
      .mockResolvedValueOnce(jsonResponse([platformReachableTenant('00000000-0000-4000-8000-000000000001')]));

    render(wrap(<Probe />));

    await waitFor(() => expect(screen.getByTestId('status')).toHaveTextContent('authenticated'));
    expect(screen.getByTestId('authenticated')).toHaveTextContent('true');
    expect(screen.getByTestId('active-tenant')).toHaveTextContent('');
    expect(screen.getByTestId('platform-context')).toHaveTextContent('true');
    expect(sessionStorage.getItem('sbom_active_tenant_id')).toBeNull();
    // Platform identity and permissions survive into platform context.
    expect(latestAuth?.user?.isPlatformAdmin).toBe(true);
    expect(latestAuth?.user?.roles).toContain('PLATFORM_ADMIN');
    expect(latestAuth?.hasPermission('platform:tenant:create')).toBe(true);
    expect(latestAuth?.hasPermission('platform:tenant:read')).toBe(true);
    expect(latestAuth?.hasPermission('tenant:user:read')).toBe(false);
    expect(fetchMock.mock.calls.every(([url]) => !String(url).endsWith('/api/tenants'))).toBe(true);
    expect(fetchMock).toHaveBeenCalledTimes(2);
  });

  it('stays in platform context for a platform admin holding a single membership', async () => {
    const fetchMock = vi.spyOn(globalThis, 'fetch');
    fetchMock
      .mockResolvedValueOnce(jsonResponse({ authenticated: true }))
      .mockResolvedValueOnce(jsonResponse(platformAdminMeBody({ available: [wellysis] })));

    render(wrap(<Probe />));

    await waitFor(() => expect(screen.getByTestId('status')).toHaveTextContent('authenticated'));
    expect(screen.getByTestId('active-tenant')).toHaveTextContent('');
    expect(screen.getByTestId('platform-context')).toHaveTextContent('true');
    expect(sessionStorage.getItem('sbom_active_tenant_id')).toBeNull();
    // The membership is still offered by the switcher, just not auto-entered.
    expect(screen.getByTestId('tenant-names')).toHaveTextContent('Wellysis');
    expect(fetchMock).toHaveBeenCalledTimes(2);
  });

  it('never requires tenant selection for a platform admin with a hundred reachable tenants', async () => {
    const reachable = Array.from({ length: 100 }, (_, index) => platformReachableTenant(`00000000-0000-4000-8000-${(index + 1).toString(16).padStart(12, '0')}`));
    const fetchMock = vi.spyOn(globalThis, 'fetch');
    fetchMock
      .mockResolvedValueOnce(jsonResponse({ authenticated: true }))
      .mockResolvedValueOnce(jsonResponse(platformAdminMeBody({ available: reachable })));

    render(wrap(<Probe />));

    await waitFor(() => expect(screen.getByTestId('status')).toHaveTextContent('authenticated'));
    expect(screen.getByTestId('status')).not.toHaveTextContent('tenant-selection-required');
    expect(screen.getByTestId('active-tenant')).toHaveTextContent('');
    expect(screen.getByTestId('platform-context')).toHaveTextContent('true');
    expect(latestAuth?.bootstrapState).toBe('ready');
  });

  it('enters tenant context when a platform admin explicitly selects a tenant', async () => {
    const nova = {
      id: '00000000-0000-4000-8000-00000000002a',
      name: 'Nova',
      slug: 'nova',
      status: 'ACTIVE',
      membership_status: 'ACTIVE',
      current_role: 'VIEWER',
      roles: ['VIEWER'],
    };
    const fetchMock = vi.spyOn(globalThis, 'fetch');
    fetchMock
      .mockResolvedValueOnce(jsonResponse({ authenticated: true }))
      .mockResolvedValueOnce(jsonResponse(platformAdminMeBody()))
      .mockResolvedValueOnce(jsonResponse({ authenticated: true }))
      .mockResolvedValueOnce(jsonResponse(platformAdminMeBody({ active: nova })));

    render(wrap(<Probe />));
    await waitFor(() => expect(screen.getByTestId('platform-context')).toHaveTextContent('true'));

    await act(async () => {
      await latestAuth!.selectTenant('00000000-0000-4000-8000-00000000002a');
    });

    await waitFor(() => expect(screen.getByTestId('active-tenant')).toHaveTextContent('00000000-0000-4000-8000-00000000002a'));
    expect(screen.getByTestId('status')).toHaveTextContent('authenticated');
    expect(screen.getByTestId('platform-context')).toHaveTextContent('false');
    expect(sessionStorage.getItem('sbom_active_tenant_id')).toBe('00000000-0000-4000-8000-00000000002a');
    expect(lastMeTenantHeader(fetchMock)).toBe('00000000-0000-4000-8000-00000000002a');
    // A tenant reached by platform authority is named in the switcher without
    // becoming a membership.
    expect(screen.getByTestId('tenant-names')).toHaveTextContent('Nova');
    expect(latestAuth?.activeTenant?.membershipStatus).toBe('ACTIVE');
    expect(latestAuth?.hasPermission('platform:tenant:create')).toBe(false);
  });

  it('clears the active tenant when a platform admin switches back to Platform', async () => {
    sessionStorage.setItem('sbom_active_tenant_id', '00000000-0000-4000-8000-00000000002a');
    const nova = {
      id: '00000000-0000-4000-8000-00000000002a',
      name: 'Nova',
      slug: 'nova',
      status: 'ACTIVE',
      membership_status: 'ACTIVE',
      current_role: 'VIEWER',
      roles: ['VIEWER'],
    };
    const fetchMock = vi.spyOn(globalThis, 'fetch');
    fetchMock
      .mockResolvedValueOnce(jsonResponse({ authenticated: true }))
      .mockResolvedValueOnce(jsonResponse(platformAdminMeBody({ active: nova })))
      .mockResolvedValueOnce(jsonResponse({ authenticated: true }))
      .mockResolvedValueOnce(jsonResponse(platformAdminMeBody()));

    render(wrap(<Probe />));
    await waitFor(() => expect(screen.getByTestId('active-tenant')).toHaveTextContent('00000000-0000-4000-8000-00000000002a'));

    act(() => {
      latestAuth!.clearTenantSelection();
    });

    await waitFor(() => expect(screen.getByTestId('platform-context')).toHaveTextContent('true'));
    expect(screen.getByTestId('status')).toHaveTextContent('authenticated');
    expect(screen.getByTestId('active-tenant')).toHaveTextContent('');
    expect(sessionStorage.getItem('sbom_active_tenant_id')).toBeNull();
    expect(lastMeTenantHeader(fetchMock)).toBeNull();
  });
});

describe('AuthProvider login() returnTo sanitization', () => {
  const windowObj = window as unknown as Record<string, unknown>;
  let originalLocation: Location;
  let assignSpy: ReturnType<typeof vi.fn>;

  beforeEach(() => {
    sessionStorage.clear();
    latestAuth = null;
    vi.restoreAllMocks();
    originalLocation = window.location;
    assignSpy = vi.fn();
  });

  afterEach(() => {
    delete windowObj.location;
    windowObj.location = originalLocation;
  });

  it('requests returnTo=/ when login is initiated while browser path is /auth/callback', async () => {
    delete windowObj.location;
    windowObj.location = {
      ...originalLocation,
      pathname: '/auth/callback',
      search: '?error=configuration_error',
      assign: assignSpy,
    };

    render(wrap(<Probe />));
    await act(async () => {
      await latestAuth!.login();
    });

    expect(assignSpy).toHaveBeenCalledWith('/api/auth/login?returnTo=%2F');
    expect(assignSpy).not.toHaveBeenCalledWith(expect.stringContaining('/auth/callback'));
  });

  it('requests returnTo=/ when login is initiated while browser path is /logged-out', async () => {
    delete windowObj.location;
    windowObj.location = {
      ...originalLocation,
      pathname: '/logged-out',
      search: '?reason=user',
      assign: assignSpy,
    };

    render(wrap(<Probe />));
    await act(async () => {
      await latestAuth!.login();
    });

    expect(assignSpy).toHaveBeenCalledWith('/api/auth/login?returnTo=%2F');
    expect(assignSpy).not.toHaveBeenCalledWith(expect.stringContaining('/logged-out'));
  });

  it('requests returnTo=/ when login is initiated from lifecycle routes (/verification-required, /access-denied, /access-pending)', async () => {
    render(wrap(<Probe />));
    for (const route of ['/verification-required', '/access-denied', '/access-pending']) {
      assignSpy.mockClear();
      delete windowObj.location;
      windowObj.location = {
        ...originalLocation,
        pathname: route,
        search: '?code=403',
        assign: assignSpy,
      };

      await act(async () => {
        await latestAuth!.login();
      });

      expect(assignSpy).toHaveBeenCalledWith('/api/auth/login?returnTo=%2F');
      expect(assignSpy).not.toHaveBeenCalledWith(expect.stringContaining(route));
    }
  });

  it('preserves application path and query string when login is initiated from normal routes', async () => {
    delete windowObj.location;
    windowObj.location = {
      ...originalLocation,
      pathname: '/sboms/42',
      search: '?tab=components',
      assign: assignSpy,
    };

    render(wrap(<Probe />));
    await act(async () => {
      await latestAuth!.login();
    });

    expect(assignSpy).toHaveBeenCalledWith('/api/auth/login?returnTo=%2Fsboms%2F42%3Ftab%3Dcomponents');
  });
});

it.each(['USER_ACCESS_PENDING', 'ACCOUNT_PENDING_APPROVAL'])('keeps %s authenticated without loading tenant data', async status => {
  const fetcher = vi.fn(async (url: string) => url === '/api/auth/session'
    ? jsonResponse({ authenticated: true, provider: 'MICROSOFT_ENTRA' })
    : jsonResponse(meBody(status, [])));
  vi.stubGlobal('fetch', fetcher);
  render(wrap(<Probe />));
  await waitFor(() => expect(screen.getByTestId('bootstrap-state')).toHaveTextContent('access-pending'));
  expect(screen.getByTestId('session-authenticated')).toHaveTextContent('true');
  await waitFor(() => expect(latestAuth?.user?.permissions).toEqual([]));
  expect(latestAuth?.tenants).toEqual([]);
  expect(fetcher.mock.calls.some(([url]) => url.endsWith('/api/tenants'))).toBe(false);
});

it('refreshSession discards privileged caches and resolves server permissions after a self mutation', async () => {
  sessionStorage.clear(); latestAuth = null;
  const fetchMock = vi.fn()
    .mockResolvedValueOnce(jsonResponse({ authenticated: true }))
    .mockResolvedValueOnce(jsonResponse(meBody('ACTIVE', [defaultTenant], '00000000-0000-4000-8000-000000000001')))
    .mockResolvedValueOnce(jsonResponse({ authenticated: true }))
    .mockResolvedValueOnce(jsonResponse({ ...meBody('ACTIVE', [defaultTenant], '00000000-0000-4000-8000-000000000001'), roles: ['VIEWER'], permissions: [] }));
  vi.stubGlobal('fetch', fetchMock);
  const qc = makeQueryClient(); render(wrap(<Probe />, qc));
  await waitFor(() => expect(latestAuth?.bootstrapState).toBe('ready'));
  qc.setQueryData(['tenant-users', 1], ['privileged']);
  await act(async () => { await latestAuth!.refreshSession({ authorizationChanged: true }); });
  expect(qc.getQueryData(['tenant-users', 1])).toBeUndefined();
  expect(latestAuth!.hasPermission('tenant:user:read')).toBe(false);
  expect(latestAuth!.user?.roles).toEqual(['VIEWER']);
});

describe('session service outage recovery', () => {
  beforeEach(() => { sessionStorage.clear(); latestAuth = null; vi.restoreAllMocks(); });

  it.each([429, 500, 503])('fails closed with Retry after HTTP %s without discarding tenant preference', async status => {
    const { setActiveTenantId, getActiveTenantId } = await import('@/lib/auth');
    const tenantId = '00000000-0000-4000-8000-000000000001';
    setActiveTenantId(tenantId);
    const fetcher = vi.fn().mockResolvedValueOnce(jsonResponse({ authenticated: false }, status));
    vi.stubGlobal('fetch', fetcher);
    render(wrap(<Probe />));
    await waitFor(() => expect(latestAuth?.authStatus).toBe('service-unavailable'));
    expect(latestAuth?.isAuthenticated).toBe(false);
    expect(latestAuth?.user).toBeNull();
    expect(getActiveTenantId()).toBe(tenantId);
    expect(fetcher).toHaveBeenCalledTimes(1);
    fetcher.mockResolvedValueOnce(jsonResponse({ authenticated: true, provider: 'NATIVE' }))
      .mockResolvedValueOnce(jsonResponse({ ...meBody('READY', [defaultTenant], tenantId), roles: ['VIEWER'], permissions: ['sbom:read'] }));
    await act(async () => { latestAuth!.retryBootstrap(); });
    await waitFor(() => expect(latestAuth?.bootstrapState).toBe('ready'));
    expect(latestAuth?.user?.roles).toEqual(['VIEWER']);
    expect(latestAuth?.hasPermission('tenant:user:update')).toBe(false);
    expect(getActiveTenantId()).toBe(tenantId);
  });

  it.each([200, 401])('still clears authentication and tenant preference for a confirmed invalid session (HTTP %s)', async status => {
    const { setActiveTenantId, getActiveTenantId } = await import('@/lib/auth');
    setActiveTenantId('00000000-0000-4000-8000-000000000001');
    const fetcher = vi.fn().mockResolvedValue(jsonResponse({ authenticated: false }, status));
    vi.stubGlobal('fetch', fetcher);
    render(wrap(<Probe />));
    await waitFor(() => expect(latestAuth?.bootstrapState).toBe('unauthenticated'));
    expect(latestAuth?.isAuthenticated).toBe(false);
    expect(getActiveTenantId()).toBeNull();
    expect(fetcher).toHaveBeenCalledTimes(1);
  });
});

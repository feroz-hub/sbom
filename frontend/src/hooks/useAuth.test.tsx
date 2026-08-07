// @vitest-environment jsdom

import { QueryClient, QueryClientProvider } from '@tanstack/react-query';
import { act, render, screen, waitFor } from '@testing-library/react';
import { useEffect, type ReactNode } from 'react';
import { beforeEach, describe, expect, it, vi } from 'vitest';

import { AuthProvider, useAuth } from '@/hooks/useAuth';

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
  id: 3,
  email: 'ferozebasha.s@hcltech.com',
  display_name: 'Feroze Basha',
};

function meBody(
  status: string,
  availableTenants: Array<Record<string, unknown>>,
  tenantId: number | null = null,
) {
  return {
    authenticated: true,
    user_id: 3,
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
    user_id: 3,
    email: identity.email,
    display_name: identity.display_name,
    tenant_id: active ? active.id : null,
    roles: active ? ['PLATFORM_ADMIN', 'TENANT_ADMIN'] : ['PLATFORM_ADMIN'],
    permissions: active
      ? ['platform:admin', 'platform:tenant:create', 'tenant:user:read']
      : ['platform:admin', 'platform:tenant:create'],
    is_platform_admin: true,
    auth_context: {
      status: 'READY',
      user: identity,
      tenant_context: { active_tenant: active, available_tenants: available },
    },
  };
}

/** A tenant a platform admin reaches by authority, not by membership. */
function platformReachableTenant(id: number) {
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
  id: 7,
  name: 'Wellysis',
  slug: 'wellysis',
  status: 'ACTIVE',
  membership_status: 'ACTIVE',
  current_role: 'TENANT_ADMIN',
  roles: ['TENANT_ADMIN'],
};
const defaultTenant = {
  id: 1,
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
      id: 7,
      name: 'Wellysis',
      slug: 'wellysis',
      membership_status: 'ACTIVE',
      current_role: 'TENANT_ADMIN',
      roles: ['TENANT_ADMIN'],
    };
    const fetchMock = vi.spyOn(globalThis, 'fetch');
    fetchMock
      .mockResolvedValueOnce(jsonResponse({ authenticated: true }))
      .mockResolvedValueOnce(jsonResponse(meBody('READY', [tenant], 7)));

    render(wrap(<Probe />));

    await waitFor(() => expect(screen.getByTestId('status')).toHaveTextContent('authenticated'));
    expect(screen.getByTestId('authenticated')).toHaveTextContent('true');
    expect(screen.getByTestId('active-tenant')).toHaveTextContent('7');
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
    expect(latestAuth?.user?.roles).toEqual([]);
    expect(latestAuth?.user?.permissions).toEqual([]);
    expect(latestAuth?.hasPermission('tenant:user:read')).toBe(false);
    expect(fetchMock).toHaveBeenCalledTimes(2);
  });

  it('clears an invalid persisted tenant and requires selection when several memberships exist', async () => {
    sessionStorage.setItem('sbom_active_tenant_id', '999');
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
    queryClient.setQueryData(['sboms'], [{ id: 1 }]);

    const fetchMock = vi.spyOn(globalThis, 'fetch');
    fetchMock
      .mockResolvedValueOnce(jsonResponse({ authenticated: true }))
      .mockResolvedValueOnce(jsonResponse(meBody('TENANT_SELECTION_REQUIRED', [wellysis, defaultTenant])))
      // selectTenant re-runs the whole auth context with the chosen tenant.
      .mockResolvedValueOnce(jsonResponse({ authenticated: true }))
      .mockResolvedValueOnce(jsonResponse(meBody('READY', [wellysis, defaultTenant], 7)));

    render(wrap(<Probe />, queryClient));
    await waitFor(() =>
      expect(screen.getByTestId('status')).toHaveTextContent('tenant-selection-required'),
    );

    await act(async () => {
      await latestAuth!.selectTenant('7');
    });

    await waitFor(() => expect(screen.getByTestId('status')).toHaveTextContent('authenticated'));
    expect(sessionStorage.getItem('sbom_active_tenant_id')).toBe('7');
    expect(screen.getByTestId('active-tenant')).toHaveTextContent('7');
    expect(queryClient.getQueryData(['sboms'])).toBeUndefined();
    // The re-resolved context was fetched with the selected tenant's header.
    expect(lastMeTenantHeader(fetchMock)).toBe('7');
  });

  it('sends the newly selected tenant on subsequent auth-context requests when switching', async () => {
    sessionStorage.setItem('sbom_active_tenant_id', '7');
    const fetchMock = vi.spyOn(globalThis, 'fetch');
    fetchMock
      .mockResolvedValueOnce(jsonResponse({ authenticated: true }))
      .mockResolvedValueOnce(jsonResponse(meBody('READY', [wellysis, defaultTenant], 7)))
      .mockResolvedValueOnce(jsonResponse({ authenticated: true }))
      .mockResolvedValueOnce(jsonResponse(meBody('READY', [wellysis, defaultTenant], 1)));

    render(wrap(<Probe />));
    await waitFor(() => expect(screen.getByTestId('status')).toHaveTextContent('authenticated'));
    expect(lastMeTenantHeader(fetchMock)).toBe('7');

    await act(async () => {
      await latestAuth!.selectTenant('1');
    });

    await waitFor(() => expect(screen.getByTestId('active-tenant')).toHaveTextContent('1'));
    expect(lastMeTenantHeader(fetchMock)).toBe('1');
    expect(sessionStorage.getItem('sbom_active_tenant_id')).toBe('1');
  });

  it('clears the active tenant on logout', async () => {
    const fetchMock = vi.spyOn(globalThis, 'fetch');
    fetchMock
      .mockResolvedValueOnce(jsonResponse({ authenticated: true }))
      .mockResolvedValueOnce(jsonResponse(meBody('READY', [wellysis], 7)));

    render(wrap(<Probe />));
    await waitFor(() => expect(screen.getByTestId('status')).toHaveTextContent('authenticated'));
    expect(sessionStorage.getItem('sbom_active_tenant_id')).toBe('7');

    // Never-settling logout call: keeps the jsdom navigation that follows it
    // out of the test while the synchronous teardown still runs.
    fetchMock.mockImplementation(() => new Promise<Response>(() => {}));

    act(() => {
      latestAuth!.logout();
    });

    expect(sessionStorage.getItem('sbom_active_tenant_id')).toBeNull();
    await waitFor(() => expect(screen.getByTestId('status')).toHaveTextContent('unauthenticated'));
    expect(screen.getByTestId('active-tenant')).toHaveTextContent('');
  });

  it('restores a valid persisted tenant on initial load', async () => {
    sessionStorage.setItem('sbom_active_tenant_id', '7');
    const tenant = {
      id: 7,
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
      .mockResolvedValueOnce(jsonResponse(meBody('READY', [tenant], 7)));

    render(wrap(<Probe />));

    await waitFor(() => expect(screen.getByTestId('status')).toHaveTextContent('authenticated'));
    expect(screen.getByTestId('active-tenant')).toHaveTextContent('7');
  });

  it('clears invalid persisted tenant and auto-selects valid single membership', async () => {
    sessionStorage.setItem('sbom_active_tenant_id', '999');
    const tenant = {
      id: 7,
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
      .mockResolvedValueOnce(jsonResponse(meBody('READY', [tenant], 7)));

    render(wrap(<Probe />));

    await waitFor(() => expect(screen.getByTestId('status')).toHaveTextContent('authenticated'));
    expect(screen.getByTestId('active-tenant')).toHaveTextContent('7');
    expect(sessionStorage.getItem('sbom_active_tenant_id')).toBe('7');
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
      .mockResolvedValueOnce(jsonResponse([platformReachableTenant(1)]));

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
    const reachable = Array.from({ length: 100 }, (_, index) => platformReachableTenant(index + 1));
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
      id: 42,
      name: 'Nova',
      slug: 'nova',
      status: 'ACTIVE',
      membership_status: null,
      current_role: 'PLATFORM_ADMIN',
      roles: ['PLATFORM_ADMIN'],
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
      await latestAuth!.selectTenant('42');
    });

    await waitFor(() => expect(screen.getByTestId('active-tenant')).toHaveTextContent('42'));
    expect(screen.getByTestId('status')).toHaveTextContent('authenticated');
    expect(screen.getByTestId('platform-context')).toHaveTextContent('false');
    expect(sessionStorage.getItem('sbom_active_tenant_id')).toBe('42');
    expect(lastMeTenantHeader(fetchMock)).toBe('42');
    // A tenant reached by platform authority is named in the switcher without
    // becoming a membership.
    expect(screen.getByTestId('tenant-names')).toHaveTextContent('Nova');
    expect(latestAuth?.activeTenant?.membershipStatus).toBeNull();
  });

  it('clears the active tenant when a platform admin switches back to Platform', async () => {
    sessionStorage.setItem('sbom_active_tenant_id', '42');
    const nova = {
      id: 42,
      name: 'Nova',
      slug: 'nova',
      status: 'ACTIVE',
      membership_status: null,
      current_role: 'PLATFORM_ADMIN',
      roles: ['PLATFORM_ADMIN'],
    };
    const fetchMock = vi.spyOn(globalThis, 'fetch');
    fetchMock
      .mockResolvedValueOnce(jsonResponse({ authenticated: true }))
      .mockResolvedValueOnce(jsonResponse(platformAdminMeBody({ active: nova })))
      .mockResolvedValueOnce(jsonResponse({ authenticated: true }))
      .mockResolvedValueOnce(jsonResponse(platformAdminMeBody()));

    render(wrap(<Probe />));
    await waitFor(() => expect(screen.getByTestId('active-tenant')).toHaveTextContent('42'));

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

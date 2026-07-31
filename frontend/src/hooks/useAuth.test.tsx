// @vitest-environment jsdom

import { QueryClient, QueryClientProvider } from '@tanstack/react-query';
import { render, screen, waitFor } from '@testing-library/react';
import type { ReactNode } from 'react';
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

function Probe() {
  const auth = useAuth();
  return (
    <div>
      <span data-testid="status">{auth.authStatus}</span>
      <span data-testid="session-authenticated">{String(auth.sessionAuthenticated)}</span>
      <span data-testid="authenticated">{String(auth.isAuthenticated)}</span>
      <span data-testid="active-tenant">{auth.activeTenantId ?? ''}</span>
      <span data-testid="tenant-names">{auth.tenants.map((tenant) => tenant.name).join('|')}</span>
      <span data-testid="email">{auth.user?.email ?? ''}</span>
    </div>
  );
}

function wrap(children: ReactNode) {
  const queryClient = new QueryClient({
    defaultOptions: { queries: { retry: false } },
  });
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

describe('AuthProvider membership-based tenant context', () => {
  beforeEach(() => {
    sessionStorage.clear();
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

  it('populates the switcher from multiple active SBOM memberships and requires local selection', async () => {
    const tenants = [
      {
        id: 7,
        name: 'Wellysis',
        slug: 'wellysis',
        membership_status: 'ACTIVE',
        current_role: 'TENANT_ADMIN',
        roles: ['TENANT_ADMIN'],
      },
      {
        id: 1,
        name: 'Default Tenant',
        slug: 'default',
        membership_status: 'ACTIVE',
        current_role: 'VIEWER',
        roles: ['VIEWER'],
      },
    ];
    const fetchMock = vi.spyOn(globalThis, 'fetch');
    fetchMock
      .mockResolvedValueOnce(jsonResponse({ authenticated: true }))
      .mockResolvedValueOnce(jsonResponse(meBody('TENANT_SELECTION_REQUIRED', tenants)));

    render(wrap(<Probe />));

    await waitFor(() => expect(screen.getByTestId('status')).toHaveTextContent('authenticated'));
    expect(screen.getByTestId('tenant-names')).toHaveTextContent('Wellysis|Default Tenant');
    expect(screen.getByTestId('active-tenant')).toHaveTextContent('');
    expect(fetchMock).toHaveBeenCalledTimes(2);
  });

  it('auto-selects the single active tenant membership for a platform admin when no header was set', async () => {
    const tenant = {
      id: 7,
      name: 'Wellysis',
      slug: 'wellysis',
      status: 'ACTIVE',
      membership_status: 'ACTIVE',
      current_role: 'TENANT_ADMIN',
      roles: ['TENANT_ADMIN'],
    };
    const platformAdminMeBody = {
      authenticated: true,
      user_id: 3,
      email: identity.email,
      display_name: identity.display_name,
      tenant_id: null,
      roles: ['PLATFORM_ADMIN'],
      permissions: ['platform:admin'],
      is_platform_admin: true,
      auth_context: {
        status: 'READY',
        user: identity,
        tenant_context: {
          active_tenant: null,
          available_tenants: [tenant],
        },
      },
    };
    const tenantScopedMeBody = {
      ...platformAdminMeBody,
      tenant_id: 7,
      roles: ['PLATFORM_ADMIN', 'TENANT_ADMIN'],
      permissions: ['platform:admin', 'tenant:user:read'],
    };

    const fetchMock = vi.spyOn(globalThis, 'fetch');
    fetchMock
      .mockResolvedValueOnce(jsonResponse({ authenticated: true }))
      .mockResolvedValueOnce(jsonResponse(platformAdminMeBody))
      .mockResolvedValueOnce(jsonResponse(tenantScopedMeBody));

    render(wrap(<Probe />));

    await waitFor(() => expect(screen.getByTestId('status')).toHaveTextContent('authenticated'));
    expect(screen.getByTestId('active-tenant')).toHaveTextContent('7');
    expect(sessionStorage.getItem('sbom_active_tenant_id')).toBe('7');
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

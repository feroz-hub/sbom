'use client';

import { createContext, useCallback, useContext, useEffect, useMemo, useState, type ReactNode } from 'react';
import { useQueryClient } from '@tanstack/react-query';
import {
  type AuthConfig, clearActiveTenantId, getActiveTenantId, resolveAuthConfig,
  setActiveTenantId,
} from '@/lib/auth';

export interface AuthUser {
  userId: number | null; externalUserId: string; email: string | null; displayName: string | null;
  tenantId: number | null; externalTenantId: string | null; roles: string[]; permissions: string[];
  isPlatformAdmin: boolean;
}
export interface TenantInfo {
  id: number; name: string; slug: string; externalIamTenantId: string; status: string; role: string | null;
}

export type AuthStatus =
  | 'loading'
  | 'unauthenticated'
  | 'authenticated'
  | 'verification-required'
  | 'access-denied'
  | 'service-unavailable';

interface AuthContextValue {
  sessionAuthenticated: boolean;
  isAuthenticated: boolean;
  isLoading: boolean;
  authStatus: AuthStatus;
  user: AuthUser | null;
  activeTenantId: string | null;
  tenants: TenantInfo[];
  config: AuthConfig;
  login: () => Promise<void>;
  logout: () => void;
  reloadAuth: () => void;
  switchTenant: (tenantId: string) => void;
  hasPermission: (permission: string) => boolean;
  hasAnyRole: (...roles: string[]) => boolean;
}

const AuthContext = createContext<AuthContextValue | null>(null);

const DEV_USER: AuthUser = {
  userId: 1, externalUserId: 'dev-user', email: 'dev@local', displayName: 'Dev User', tenantId: 1,
  externalTenantId: 'local-default', roles: ['TENANT_ADMIN'],
  permissions: ['dashboard:read', 'tenant:user:read', 'tenant:user:invite', 'tenant:user:update'],
  isPlatformAdmin: false,
};
const DEV_TENANTS: TenantInfo[] = [{
  id: 1, name: 'Default Tenant', slug: 'default', externalIamTenantId: 'local-default',
  status: 'ACTIVE', role: 'TENANT_ADMIN',
}];

export function AuthProvider({ children }: { children: ReactNode }) {
  const config = useMemo(() => resolveAuthConfig(), []);
  const queryClient = useQueryClient();
  const [sessionAuthenticated, setSessionAuthenticated] = useState(false);
  const [authStatus, setAuthStatus] = useState<AuthStatus>('loading');
  const [user, setUser] = useState<AuthUser | null>(null);
  const [tenants, setTenants] = useState<TenantInfo[]>([]);
  const [activeTenantIdState, setActiveTenantIdState] = useState<string | null>(null);

  const checkAuth = useCallback(async (tenantOverride?: string) => {
    if (!config.enabled) {
      setUser(DEV_USER); setTenants(DEV_TENANTS); setActiveTenantId('1'); setActiveTenantIdState('1');
      setSessionAuthenticated(true);
      setAuthStatus('authenticated');
      return;
    }

    try {
      const sessionResponse = await fetch('/api/auth/session', { credentials: 'include', cache: 'no-store' });
      const session = await sessionResponse.json().catch(() => null);

      if (!sessionResponse.ok || session?.authenticated !== true) {
        setSessionAuthenticated(false);
        setUser(null);
        setAuthStatus('unauthenticated');
        return;
      }

      setSessionAuthenticated(true);

      const { BASE_URL } = await import('@/lib/api');
      const headers: Record<string, string> = {};
      const tenantId = tenantOverride || getActiveTenantId();
      if (tenantId) headers['X-Tenant-ID'] = tenantId;

      const meResponse = await fetch(`${BASE_URL}/api/auth/me`, { credentials: 'include', headers, cache: 'no-store' });
      const body = await meResponse.json().catch(() => null);

      if (meResponse.ok && body) {
        const status = body?.auth_context?.status ?? body?.status ?? null;

        if (status === 'VERIFICATION_REQUIRED' || body?.verification_required === true) {
          setUser({
            userId: body.user_id ?? body.userId ?? null,
            externalUserId: body.external_user_id ?? body.externalUserId ?? '',
            email: body.email ?? null,
            displayName: body.display_name ?? body.displayName ?? null,
            tenantId: body.tenant_id ?? body.tenantId ?? null,
            externalTenantId: body.external_tenant_id ?? body.externalTenantId ?? null,
            roles: body.roles || [], permissions: body.permissions || [], isPlatformAdmin: Boolean(body.is_platform_admin),
          });
          setAuthStatus('verification-required');
          return;
        }

        if (status === 'ACCOUNT_DISABLED' || status === 'DISABLED' || status === 'BLOCKED') {
          setUser({
            userId: body.user_id ?? body.userId ?? null,
            externalUserId: body.external_user_id ?? body.externalUserId ?? '',
            email: body.email ?? null,
            displayName: body.display_name ?? body.displayName ?? null,
            tenantId: body.tenant_id ?? body.tenantId ?? null,
            externalTenantId: body.external_tenant_id ?? body.externalTenantId ?? null,
            roles: body.roles || [], permissions: body.permissions || [], isPlatformAdmin: Boolean(body.is_platform_admin),
          });
          setAuthStatus('access-denied');
          return;
        }

        if (body?.authenticated === true) {
          setUser({
            userId: body.user_id ?? body.userId ?? null,
            externalUserId: body.external_user_id ?? body.externalUserId ?? '',
            email: body.email ?? null,
            displayName: body.display_name ?? body.displayName ?? null,
            tenantId: body.tenant_id ?? body.tenantId ?? null,
            externalTenantId: body.external_tenant_id ?? body.externalTenantId ?? null,
            roles: body.roles || [], permissions: body.permissions || [], isPlatformAdmin: Boolean(body.is_platform_admin),
          });
          setAuthStatus('authenticated');

          try {
            const tenantsResponse = await fetch(`${BASE_URL}/api/tenants`, { credentials: 'include', headers, cache: 'no-store' });
            if (tenantsResponse.ok) {
              setTenants((await tenantsResponse.json()).map((tenant: Record<string, unknown>) => ({
                id: tenant.id, name: tenant.name, slug: tenant.slug,
                externalIamTenantId: tenant.external_iam_tenant_id, status: tenant.status, role: tenant.role,
              })) as TenantInfo[]);
            }
          } catch {
            setTenants([]);
          }

          const selected = tenantOverride || getActiveTenantId() || (body.tenant_id ? String(body.tenant_id) : null);
          if (selected) { setActiveTenantId(selected); setActiveTenantIdState(selected); }

          return;
        }
      }

      if (meResponse.status === 403) {
        const code = body?.code ?? body?.detail?.code ?? body?.error?.code;
        if (code === 'IAM_EMAIL_VERIFICATION_REQUIRED' || code === 'VERIFICATION_REQUIRED') {
          setAuthStatus('verification-required');
          return;
        }
        if (code === 'IAM_ACCOUNT_DISABLED' || code === 'ACCOUNT_DISABLED' || code === 'ACCESS_DENIED') {
          setAuthStatus('access-denied');
          return;
        }
      }

      if (meResponse.status === 401) {
        setAuthStatus('service-unavailable');
        return;
      }

      setAuthStatus('service-unavailable');
    } catch {
      setAuthStatus('service-unavailable');
    }
  }, [config.enabled]);

  useEffect(() => {
    void checkAuth();
  }, [checkAuth]);

  const login = useCallback(async () => {
    if (!config.enabled) return;
    const returnTo = `${window.location.pathname}${window.location.search}`;
    window.location.assign(`/api/auth/login?returnTo=${encodeURIComponent(returnTo)}`);
  }, [config.enabled]);

  const logout = useCallback(() => {
    clearActiveTenantId(); setUser(null); setTenants([]); setActiveTenantIdState(null); queryClient.clear();
    setSessionAuthenticated(false);
    setAuthStatus('unauthenticated');
    if (!config.enabled) return;
    void fetch('/api/auth/logout', { method: 'POST' })
      .then((response) => response.json())
      .then((body) => window.location.assign(body.redirectUrl || '/'))
      .catch(() => window.location.assign('/'));
  }, [config.enabled, queryClient]);

  const reloadAuth = useCallback(() => {
    setAuthStatus('loading');
    void checkAuth();
  }, [checkAuth]);

  const switchTenant = useCallback((tenantId: string) => {
    setActiveTenantId(tenantId); setActiveTenantIdState(tenantId); queryClient.clear();
    void checkAuth(tenantId);
  }, [checkAuth, queryClient]);

  const hasPermission = useCallback(
    (permission: string) => Boolean(user && (user.isPlatformAdmin || user.permissions.includes(permission))),
    [user],
  );

  const hasAnyRole = useCallback((...roles: string[]) => {
    const current = new Set(user?.roles.map((role) => role.toUpperCase()) || []);
    return roles.some((role) => current.has(role.toUpperCase()));
  }, [user]);

  const value = useMemo(() => ({
    sessionAuthenticated,
    isAuthenticated: authStatus === 'authenticated',
    isLoading: authStatus === 'loading',
    authStatus,
    user,
    activeTenantId: activeTenantIdState,
    tenants,
    config,
    login,
    logout,
    reloadAuth,
    switchTenant,
    hasPermission,
    hasAnyRole,
  }), [sessionAuthenticated, authStatus, user, activeTenantIdState, tenants, config, login, logout, reloadAuth, switchTenant, hasPermission, hasAnyRole]);

  return <AuthContext.Provider value={value}>{children}</AuthContext.Provider>;
}

export function useAuth(): AuthContextValue {
  const value = useContext(AuthContext);
  if (!value) throw new Error('useAuth must be used within an AuthProvider');
  return value;
}

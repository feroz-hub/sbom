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
  id: number; name: string; slug: string; externalIamTenantId: string | null; status: string; role: string | null;
  roles: string[]; membershipStatus: string | null; platformContextAvailable: boolean;
}

export type AuthStatus =
  | 'loading'
  | 'unauthenticated'
  | 'authenticated'
  | 'verification-required'
  | 'access-pending'
  | 'access-denied'
  | 'service-unavailable';

interface AuthContextValue {
  sessionAuthenticated: boolean;
  isAuthenticated: boolean;
  isLoading: boolean;
  isTenantContextLoading: boolean;
  authStatus: AuthStatus;
  user: AuthUser | null;
  activeTenant: TenantInfo | null;
  activeTenantId: string | null;
  tenants: TenantInfo[];
  availableTenants: TenantInfo[];
  config: AuthConfig;
  login: () => Promise<void>;
  logout: () => void;
  reloadAuth: () => void;
  refreshSession: () => Promise<void>;
  selectTenant: (tenantId: string) => Promise<void>;
  clearTenantSelection: () => void;
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
  status: 'ACTIVE', role: 'TENANT_ADMIN', roles: ['TENANT_ADMIN'],
  membershipStatus: 'ACTIVE', platformContextAvailable: false,
}];

function tenantInfoFromContext(tenant: Record<string, unknown>): TenantInfo {
  const roles = Array.isArray(tenant.roles)
    ? tenant.roles.map(String)
    : tenant.current_role
      ? [String(tenant.current_role)]
      : [];
  return {
    id: Number(tenant.id),
    name: String(tenant.name ?? ''),
    slug: String(tenant.slug ?? ''),
    externalIamTenantId: (tenant.external_iam_tenant_id as string) ?? null,
    status: (tenant.status as string) ?? 'ACTIVE',
    role: tenant.current_role ? String(tenant.current_role) : null,
    roles,
    membershipStatus: tenant.membership_status
      ? String(tenant.membership_status)
      : null,
    platformContextAvailable: Boolean(tenant.platform_context_available),
  };
}

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
        clearActiveTenantId();
        setSessionAuthenticated(false);
        setUser(null);
        setTenants([]);
        setActiveTenantIdState(null);
        setAuthStatus('unauthenticated');
        return;
      }

      setSessionAuthenticated(true);

      const { BASE_URL } = await import('@/lib/api');
      const headers: Record<string, string> = {};
      const persistedTenantId = tenantOverride || getActiveTenantId();
      if (persistedTenantId) headers['X-Tenant-ID'] = persistedTenantId;

      let meResponse = await fetch(`${BASE_URL}/api/auth/me`, { credentials: 'include', headers, cache: 'no-store' });
      let body = await meResponse.json().catch(() => null);
      const initialErrorCode = body?.code ?? body?.detail?.code ?? body?.error?.code;

      if (meResponse.status === 403 && initialErrorCode === 'IAM_UNAUTHORIZED_TENANT' && headers['X-Tenant-ID']) {
        clearActiveTenantId();
        setActiveTenantIdState(null);
        delete headers['X-Tenant-ID'];
        meResponse = await fetch(`${BASE_URL}/api/auth/me`, { credentials: 'include', headers, cache: 'no-store' });
        body = await meResponse.json().catch(() => null);
      }

      if (meResponse.ok && body) {
        const status = body?.auth_context?.status ?? body?.status ?? null;
        const contextUser = body?.auth_context?.user ?? body?.user ?? {};
        let contextTenants: TenantInfo[] = Array.isArray(
          body?.auth_context?.tenant_context?.available_tenants,
        )
          ? body.auth_context.tenant_context.available_tenants.map(
              (tenant: Record<string, unknown>) => tenantInfoFromContext(tenant),
            )
          : [];

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

        if (status === 'NO_TENANT' || status === 'ACCESS_PENDING') {
          setUser({
            userId: body.user_id ?? body.userId ?? contextUser.id ?? null,
            externalUserId: body.external_user_id ?? body.externalUserId ?? '',
            email: body.email ?? contextUser.email ?? null,
            displayName: body.display_name ?? body.displayName ?? contextUser.display_name ?? null,
            tenantId: null,
            externalTenantId: null,
            roles: body.roles || [],
            permissions: body.permissions || [],
            isPlatformAdmin: Boolean(body.is_platform_admin),
          });
          setTenants([]);
          clearActiveTenantId();
          setActiveTenantIdState(null);
          setAuthStatus('access-pending');
          return;
        }

        if (contextTenants.length === 0) {
          try {
            const tenantsResponse = await fetch(`${BASE_URL}/api/tenants`, { credentials: 'include', headers, cache: 'no-store' });
            if (tenantsResponse.ok) {
              const resJson = await tenantsResponse.json();
              if (Array.isArray(resJson)) {
                contextTenants = resJson.map((tenant: Record<string, unknown>) => ({
                  id: Number(tenant.id), name: String(tenant.name ?? ''), slug: String(tenant.slug ?? ''),
                  externalIamTenantId: (tenant.external_iam_tenant_id as string) ?? null,
                  status: (tenant.status as string) ?? 'ACTIVE',
                  role: tenant.role ? String(tenant.role) : null,
                  roles: Array.isArray(tenant.roles) ? tenant.roles.map(String) : (tenant.role ? [String(tenant.role)] : []),
                  membershipStatus: (tenant.membership_status as string) ?? null,
                  platformContextAvailable: Boolean(tenant.platform_context_available),
                }));
              }
            }
          } catch {
            if (!body.is_platform_admin) contextTenants = [];
          }
        }

        setTenants(contextTenants);

        // Filter active tenant memberships
        const activeTenants = contextTenants.filter(
          (t) => t.status === 'ACTIVE' && (t.membershipStatus === 'ACTIVE' || t.membershipStatus === null || t.platformContextAvailable),
        );

        // Resolution order (a -> f):
        // a, b, c: Check if persisted tenant is valid
        const candidateId = tenantOverride || getActiveTenantId() || (body.tenant_id ? String(body.tenant_id) : null);
        const validPersisted = candidateId ? activeTenants.find((t) => String(t.id) === String(candidateId)) : null;

        if (validPersisted) {
          const selectedIdStr = String(validPersisted.id);
          setActiveTenantId(selectedIdStr);
          setActiveTenantIdState(selectedIdStr);

          const currentBodyTenantIdStr = body.tenant_id !== null && body.tenant_id !== undefined ? String(body.tenant_id) : null;
          if (currentBodyTenantIdStr !== selectedIdStr) {
            const reFetchHeaders: Record<string, string> = { 'X-Tenant-ID': selectedIdStr };
            const subMeRes = await fetch(`${BASE_URL}/api/auth/me`, { credentials: 'include', headers: reFetchHeaders, cache: 'no-store' });
            if (subMeRes.ok) {
              const subBody = await subMeRes.json().catch(() => null);
              if (subBody) {
                body = subBody;
              }
            }
          }

          setUser({
            userId: body.user_id ?? body.userId ?? contextUser.id ?? null,
            externalUserId: body.external_user_id ?? body.externalUserId ?? '',
            email: body.email ?? contextUser.email ?? null,
            displayName: body.display_name ?? body.displayName ?? contextUser.display_name ?? null,
            tenantId: body.tenant_id ?? Number(selectedIdStr),
            externalTenantId: body.external_tenant_id ?? validPersisted.externalIamTenantId ?? null,
            roles: body.roles || [],
            permissions: body.permissions || [],
            isPlatformAdmin: Boolean(body.is_platform_admin),
          });
          setAuthStatus('authenticated');
          return;
        }

        // d: No valid persisted tenant, user has exactly ONE active tenant membership -> auto-select
        if (activeTenants.length === 1) {
          const autoSelectedIdStr = String(activeTenants[0].id);
          setActiveTenantId(autoSelectedIdStr);
          setActiveTenantIdState(autoSelectedIdStr);

          const currentBodyTenantIdStr = body.tenant_id !== null && body.tenant_id !== undefined ? String(body.tenant_id) : null;
          if (currentBodyTenantIdStr !== autoSelectedIdStr) {
            const subMeRes = await fetch(`${BASE_URL}/api/auth/me`, { credentials: 'include', headers: { 'X-Tenant-ID': autoSelectedIdStr }, cache: 'no-store' });
            if (subMeRes.ok) {
              const subBody = await subMeRes.json().catch(() => null);
              if (subBody) {
                body = subBody;
              }
            }
          }

          setUser({
            userId: body.user_id ?? body.userId ?? contextUser.id ?? null,
            externalUserId: body.external_user_id ?? body.externalUserId ?? '',
            email: body.email ?? contextUser.email ?? null,
            displayName: body.display_name ?? body.displayName ?? contextUser.display_name ?? null,
            tenantId: body.tenant_id ?? Number(autoSelectedIdStr),
            externalTenantId: body.external_tenant_id ?? activeTenants[0].externalIamTenantId ?? null,
            roles: body.roles || [],
            permissions: body.permissions || [],
            isPlatformAdmin: Boolean(body.is_platform_admin),
          });
          setAuthStatus('authenticated');
          return;
        }

        // e: Multiple active tenant memberships and no valid persisted selection -> do not arbitrarily choose
        if (activeTenants.length > 1) {
          clearActiveTenantId();
          setActiveTenantIdState(null);
          setUser({
            userId: body.user_id ?? body.userId ?? contextUser.id ?? null,
            externalUserId: body.external_user_id ?? body.externalUserId ?? '',
            email: body.email ?? contextUser.email ?? null,
            displayName: body.display_name ?? body.displayName ?? contextUser.display_name ?? null,
            tenantId: null,
            externalTenantId: null,
            roles: body.roles || [],
            permissions: body.permissions || [],
            isPlatformAdmin: Boolean(body.is_platform_admin),
          });
          setAuthStatus('authenticated');
          return;
        }

        // f: Zero active tenant memberships
        clearActiveTenantId();
        setActiveTenantIdState(null);
        setUser({
          userId: body.user_id ?? body.userId ?? contextUser.id ?? null,
          externalUserId: body.external_user_id ?? body.externalUserId ?? '',
          email: body.email ?? contextUser.email ?? null,
          displayName: body.display_name ?? body.displayName ?? contextUser.display_name ?? null,
          tenantId: null,
          externalTenantId: null,
          roles: body.roles || [],
          permissions: body.permissions || [],
          isPlatformAdmin: Boolean(body.is_platform_admin),
        });
        setAuthStatus(body.is_platform_admin ? 'authenticated' : 'access-pending');
        return;
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
        if (code === 'IAM_NO_ACTIVE_MEMBERSHIP' || code === 'NO_TENANT_MEMBERSHIP' || code === 'ACCESS_PENDING' || body?.email || body?.display_name) {
          setUser({
            userId: body?.user_id ?? body?.userId ?? null,
            externalUserId: body?.external_user_id ?? body?.externalUserId ?? '',
            email: body?.email ?? null,
            displayName: body?.display_name ?? body?.displayName ?? null,
            tenantId: body?.tenant_id ?? body?.tenantId ?? null,
            externalTenantId: body?.external_tenant_id ?? body?.externalTenantId ?? null,
            roles: body?.roles || [], permissions: body?.permissions || [], isPlatformAdmin: Boolean(body?.is_platform_admin),
          });
          setAuthStatus('access-pending');
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

  const selectTenant = useCallback(async (tenantId: string) => {
    setActiveTenantId(tenantId);
    setActiveTenantIdState(tenantId);
    queryClient.clear();
    await checkAuth(tenantId);
  }, [checkAuth, queryClient]);

  const clearTenantSelection = useCallback(() => {
    clearActiveTenantId();
    setActiveTenantIdState(null);
    queryClient.clear();
    void checkAuth();
  }, [checkAuth, queryClient]);

  const switchTenant = useCallback((tenantId: string) => {
    void selectTenant(tenantId);
  }, [selectTenant]);

  const hasPermission = useCallback(
    (permission: string) => Boolean(user && (user.isPlatformAdmin || user.permissions.includes(permission))),
    [user],
  );

  const hasAnyRole = useCallback((...roles: string[]) => {
    const current = new Set(user?.roles.map((role) => role.toUpperCase()) || []);
    return roles.some((role) => current.has(role.toUpperCase()));
  }, [user]);

  const activeTenant = useMemo(
    () => tenants.find((t) => String(t.id) === activeTenantIdState) ?? null,
    [tenants, activeTenantIdState],
  );

  const value = useMemo(() => ({
    sessionAuthenticated,
    isAuthenticated: authStatus === 'authenticated',
    isLoading: authStatus === 'loading',
    isTenantContextLoading: authStatus === 'loading',
    authStatus,
    user,
    activeTenant,
    activeTenantId: activeTenantIdState,
    tenants,
    availableTenants: tenants,
    config,
    login,
    logout,
    reloadAuth,
    refreshSession: checkAuth,
    selectTenant,
    clearTenantSelection,
    switchTenant,
    hasPermission,
    hasAnyRole,
  }), [
    sessionAuthenticated,
    authStatus,
    user,
    activeTenant,
    activeTenantIdState,
    tenants,
    config,
    login,
    logout,
    reloadAuth,
    checkAuth,
    selectTenant,
    clearTenantSelection,
    switchTenant,
    hasPermission,
    hasAnyRole,
  ]);

  return <AuthContext.Provider value={value}>{children}</AuthContext.Provider>;
}

export function useAuth(): AuthContextValue {
  const value = useContext(AuthContext);
  if (!value) throw new Error('useAuth must be used within an AuthProvider');
  return value;
}

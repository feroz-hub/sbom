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
interface AuthContextValue {
  isAuthenticated: boolean; isLoading: boolean; user: AuthUser | null; activeTenantId: string | null;
  tenants: TenantInfo[]; config: AuthConfig; login: () => Promise<void>; logout: () => void;
  switchTenant: (tenantId: string) => void; hasPermission: (permission: string) => boolean;
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
  const [isLoading, setIsLoading] = useState(true);
  const [user, setUser] = useState<AuthUser | null>(null);
  const [tenants, setTenants] = useState<TenantInfo[]>([]);
  const [activeTenantIdState, setActiveTenantIdState] = useState<string | null>(null);

  const fetchUserProfile = useCallback(async (tenantOverride?: string): Promise<boolean> => {
    try {
      const { BASE_URL } = await import('@/lib/api');
      const headers: Record<string, string> = {};
      const tenantId = tenantOverride || getActiveTenantId();
      if (tenantId) headers['X-Tenant-ID'] = tenantId;
      const meResponse = await fetch(`${BASE_URL}/api/auth/me`, { headers, cache: 'no-store' });
      if (!meResponse.ok) return false;
      const me = await meResponse.json();
      setUser({
        userId: me.user_id, externalUserId: me.external_user_id, email: me.email,
        displayName: me.display_name, tenantId: me.tenant_id, externalTenantId: me.external_tenant_id,
        roles: me.roles || [], permissions: me.permissions || [], isPlatformAdmin: Boolean(me.is_platform_admin),
      });
      try {
        const tenantsResponse = await fetch(`${BASE_URL}/api/tenants`, { headers, cache: 'no-store' });
        if (tenantsResponse.ok) {
          setTenants((await tenantsResponse.json()).map((tenant: Record<string, unknown>) => ({
            id: tenant.id, name: tenant.name, slug: tenant.slug,
            externalIamTenantId: tenant.external_iam_tenant_id, status: tenant.status, role: tenant.role,
          })) as TenantInfo[]);
        }
      } catch {
        // The profile is authoritative for authentication. Keep the valid
        // session if the optional tenant switcher cannot be populated.
        setTenants([]);
      }
      const selected = tenantOverride || getActiveTenantId() || (me.tenant_id ? String(me.tenant_id) : null);
      if (selected) { setActiveTenantId(selected); setActiveTenantIdState(selected); }
      return true;
    } catch {
      return false;
    }
  }, []);

  useEffect(() => {
    void (async () => {
      if (!config.enabled) {
        setUser(DEV_USER); setTenants(DEV_TENANTS); setActiveTenantId('1'); setActiveTenantIdState('1');
        setIsLoading(false); return;
      }
      const session = await fetch('/api/auth/session', { cache: 'no-store' }).then((r) => r.ok ? r.json() : null).catch(() => null);
      if (session?.authenticated) await fetchUserProfile();
      setIsLoading(false);
    })();
  }, [config.enabled, fetchUserProfile]);

  const login = useCallback(async () => {
    if (!config.enabled) return;
    const returnTo = `${window.location.pathname}${window.location.search}`;
    window.location.assign(`/api/auth/login?returnTo=${encodeURIComponent(returnTo)}`);
  }, [config.enabled]);

  const logout = useCallback(() => {
    clearActiveTenantId(); setUser(null); setTenants([]); setActiveTenantIdState(null); queryClient.clear();
    if (!config.enabled) return;
    void fetch('/api/auth/logout', { method: 'POST' })
      .then((response) => response.json())
      .then((body) => window.location.assign(body.redirectUrl || '/'))
      .catch(() => window.location.assign('/'));
  }, [config.enabled, queryClient]);

  const switchTenant = useCallback((tenantId: string) => {
    setActiveTenantId(tenantId); setActiveTenantIdState(tenantId); queryClient.clear();
    void fetchUserProfile(tenantId);
  }, [fetchUserProfile, queryClient]);
  const hasPermission = useCallback(
    (permission: string) => Boolean(user && (user.isPlatformAdmin || user.permissions.includes(permission))),
    [user],
  );
  const hasAnyRole = useCallback((...roles: string[]) => {
    const current = new Set(user?.roles.map((role) => role.toUpperCase()) || []);
    return roles.some((role) => current.has(role.toUpperCase()));
  }, [user]);
  const value = useMemo(() => ({
    isAuthenticated: user !== null, isLoading, user, activeTenantId: activeTenantIdState, tenants, config,
    login, logout, switchTenant, hasPermission, hasAnyRole,
  }), [user, isLoading, activeTenantIdState, tenants, config, login, logout, switchTenant, hasPermission, hasAnyRole]);
  return <AuthContext.Provider value={value}>{children}</AuthContext.Provider>;
}

export function useAuth(): AuthContextValue {
  const value = useContext(AuthContext);
  if (!value) throw new Error('useAuth must be used within an AuthProvider');
  return value;
}

'use client';

/**
 * Authentication context and provider for HCL IAM OIDC integration.
 *
 * Wraps the React tree with auth state: user identity, active tenant,
 * roles, permissions, and token management. When `NEXT_PUBLIC_AUTH_ENABLED`
 * is false (dev mode), provides a synthetic admin context so the app
 * works without an IAM instance.
 */

import {
  createContext,
  useCallback,
  useContext,
  useEffect,
  useMemo,
  useRef,
  useState,
  type ReactNode,
} from 'react';
import { useQueryClient } from '@tanstack/react-query';
import {
  type AuthConfig,
  buildAuthorizationUrl,
  buildLogoutUrl,
  clearActiveTenantId,
  clearTokens,
  getAccessToken,
  getActiveTenantId,
  isTokenExpired,
  parseJwtClaims,
  refreshAccessToken,
  resolveAuthConfig,
  setActiveTenantId,
  storeReturnUrl,
} from '@/lib/auth';

// ─── Types ───────────────────────────────────────────────────────────────────

export interface AuthUser {
  userId: number | null;
  externalUserId: string;
  email: string | null;
  displayName: string | null;
  tenantId: number | null;
  externalTenantId: string | null;
  roles: string[];
  permissions: string[];
  isPlatformAdmin: boolean;
}

export interface TenantInfo {
  id: number;
  name: string;
  slug: string;
  externalIamTenantId: string;
  status: string;
  role: string | null;
}

interface AuthContextValue {
  /** Whether the user is authenticated (has a valid token or dev mode). */
  isAuthenticated: boolean;
  /** Whether auth initialization is in progress. */
  isLoading: boolean;
  /** Current user profile (from /api/auth/me). */
  user: AuthUser | null;
  /** Currently active tenant ID (for X-Tenant-ID header). */
  activeTenantId: string | null;
  /** List of tenants the user belongs to. */
  tenants: TenantInfo[];
  /** Auth config (enabled, issuer, etc.). */
  config: AuthConfig;
  /** Redirect to HCL IAM login. */
  login: () => Promise<void>;
  /** Clear tokens and redirect to HCL IAM logout. */
  logout: () => void;
  /** Switch the active tenant. Clears all tenant-specific query caches. */
  switchTenant: (tenantId: string) => void;
  /** Check if the user has a specific permission. */
  hasPermission: (permission: string) => boolean;
  /** Check if the user has any of the specified roles. */
  hasAnyRole: (...roles: string[]) => boolean;
}

const AuthContext = createContext<AuthContextValue | null>(null);

// ─── Dev mode defaults ───────────────────────────────────────────────────────

const DEV_USER: AuthUser = {
  userId: 1,
  externalUserId: 'local-dev-admin',
  email: 'local-admin@localhost',
  displayName: 'Local Development Admin',
  tenantId: 1,
  externalTenantId: 'local-default',
  roles: ['PLATFORM_ADMIN'],
  permissions: [
    'sbom:read', 'sbom:upload', 'sbom:update', 'sbom:delete', 'sbom:export',
    'project:read', 'project:create', 'project:update', 'project:delete',
    'component:read', 'component:update',
    'lifecycle:read', 'lifecycle:override',
    'vex:read', 'vex:write',
    'remediation:read', 'remediation:write', 'remediation:close',
    'dashboard:read',
    'tenant:user:read', 'tenant:user:invite', 'tenant:user:update',
    'tenant:settings:update',
    'schedule:read', 'schedule:write',
    'analysis:read', 'analysis:run',
    'platform:admin',
  ],
  isPlatformAdmin: true,
};

const DEV_TENANTS: TenantInfo[] = [
  {
    id: 1,
    name: 'Default Tenant',
    slug: 'default',
    externalIamTenantId: 'local-default',
    status: 'ACTIVE',
    role: 'PLATFORM_ADMIN',
  },
];

// ─── Provider ────────────────────────────────────────────────────────────────

export function AuthProvider({ children }: { children: ReactNode }) {
  const config = useMemo(() => resolveAuthConfig(), []);
  const queryClient = useQueryClient();

  const [isLoading, setIsLoading] = useState(true);
  const [user, setUser] = useState<AuthUser | null>(null);
  const [tenants, setTenants] = useState<TenantInfo[]>([]);
  const [activeTenantIdState, setActiveTenantIdState] = useState<string | null>(null);
  const refreshTimerRef = useRef<ReturnType<typeof setTimeout>>();

  const isAuthenticated = user !== null;

  // Fetch user profile from /api/auth/me
  const fetchUserProfile = useCallback(async (tenantOverride?: string): Promise<boolean> => {
    try {
      const { BASE_URL } = await import('@/lib/api');
      const headers: Record<string, string> = {};
      const token = getAccessToken();
      if (token) {
        headers['Authorization'] = `Bearer ${token}`;
      }
      const tid = tenantOverride || getActiveTenantId();
      if (tid) {
        headers['X-Tenant-ID'] = tid;
      }

      const meRes = await fetch(`${BASE_URL}/api/auth/me`, { headers });
      if (!meRes.ok) {
        if (meRes.status === 401 || meRes.status === 403) return false;
        return false;
      }

      const me = await meRes.json();
      setUser({
        userId: me.user_id,
        externalUserId: me.external_user_id,
        email: me.email,
        displayName: me.display_name,
        tenantId: me.tenant_id,
        externalTenantId: me.external_tenant_id,
        roles: me.roles || [],
        permissions: me.permissions || [],
        isPlatformAdmin: me.is_platform_admin || false,
      });

      // Fetch tenant list
      const tenantsRes = await fetch(`${BASE_URL}/api/tenants`, { headers });
      if (tenantsRes.ok) {
        const tenantList = await tenantsRes.json();
        setTenants(
          tenantList.map((t: Record<string, unknown>) => ({
            id: t.id,
            name: t.name,
            slug: t.slug,
            externalIamTenantId: t.external_iam_tenant_id,
            status: t.status,
            role: t.role,
          })),
        );
      }

      // Store active tenant
      if (me.tenant_id && !tenantOverride) {
        const storedTid = getActiveTenantId();
        if (!storedTid) {
          setActiveTenantId(String(me.tenant_id));
          setActiveTenantIdState(String(me.tenant_id));
        } else {
          setActiveTenantIdState(storedTid);
        }
      }

      return true;
    } catch {
      return false;
    }
  }, []);

  // Schedule token refresh
  const scheduleRefresh = useCallback(() => {
    if (refreshTimerRef.current) {
      clearTimeout(refreshTimerRef.current);
    }
    if (!config.enabled) return;

    const token = getAccessToken();
    if (!token) return;

    const claims = parseJwtClaims(token);
    if (!claims || typeof claims.exp !== 'number') return;

    // Refresh 60 seconds before expiry
    const refreshAt = claims.exp * 1000 - Date.now() - 60_000;
    if (refreshAt <= 0) {
      // Token is already (nearly) expired, refresh now
      refreshAccessToken(config).then((ok) => {
        if (ok) scheduleRefresh();
      });
      return;
    }

    refreshTimerRef.current = setTimeout(async () => {
      const ok = await refreshAccessToken(config);
      if (ok) {
        scheduleRefresh();
      } else {
        // Refresh failed — user needs to re-login
        clearTokens();
        setUser(null);
      }
    }, Math.min(refreshAt, 2_147_483_647)); // setTimeout max
  }, [config]);

  // Initialize auth state
  useEffect(() => {
    async function init() {
      if (!config.enabled) {
        // Dev mode: use synthetic admin
        setUser(DEV_USER);
        setTenants(DEV_TENANTS);
        setActiveTenantIdState('1');
        setActiveTenantId('1');
        setIsLoading(false);
        return;
      }

      const token = getAccessToken();
      if (!token || isTokenExpired()) {
        // Try refresh
        if (getAccessToken()) {
          const refreshed = await refreshAccessToken(config);
          if (refreshed) {
            const ok = await fetchUserProfile();
            if (ok) {
              scheduleRefresh();
              setIsLoading(false);
              return;
            }
          }
        }
        // No valid token
        setIsLoading(false);
        return;
      }

      // Valid token exists — load profile
      const ok = await fetchUserProfile();
      if (ok) {
        scheduleRefresh();
      }
      setIsLoading(false);
    }

    init();

    return () => {
      if (refreshTimerRef.current) {
        clearTimeout(refreshTimerRef.current);
      }
    };
  }, [config, fetchUserProfile, scheduleRefresh]);

  // Login: redirect to HCL IAM
  const login = useCallback(async () => {
    if (!config.enabled) return;
    // Store current URL for post-login redirect
    if (typeof window !== 'undefined') {
      storeReturnUrl(window.location.pathname + window.location.search);
    }
    const url = await buildAuthorizationUrl(config);
    window.location.href = url;
  }, [config]);

  // Logout: clear everything and redirect to HCL IAM
  const logout = useCallback(() => {
    clearTokens();
    clearActiveTenantId();
    setUser(null);
    setTenants([]);
    setActiveTenantIdState(null);
    queryClient.clear();

    if (config.enabled) {
      const logoutUrl = buildLogoutUrl(config);
      window.location.href = logoutUrl;
    }
  }, [config, queryClient]);

  // Switch tenant
  const switchTenant = useCallback(
    (tenantId: string) => {
      setActiveTenantId(tenantId);
      setActiveTenantIdState(tenantId);

      // Clear all tenant-specific caches
      queryClient.clear();

      // Re-fetch user profile with new tenant context
      fetchUserProfile(tenantId);
    },
    [queryClient, fetchUserProfile],
  );

  // Permission check
  const hasPermission = useCallback(
    (permission: string) => {
      if (!user) return false;
      return user.permissions.includes(permission);
    },
    [user],
  );

  // Role check
  const hasAnyRole = useCallback(
    (...roles: string[]) => {
      if (!user) return false;
      const userRoles = new Set(user.roles.map((r) => r.toUpperCase()));
      return roles.some((r) => userRoles.has(r.toUpperCase()));
    },
    [user],
  );

  const value = useMemo<AuthContextValue>(
    () => ({
      isAuthenticated,
      isLoading,
      user,
      activeTenantId: activeTenantIdState,
      tenants,
      config,
      login,
      logout,
      switchTenant,
      hasPermission,
      hasAnyRole,
    }),
    [
      isAuthenticated,
      isLoading,
      user,
      activeTenantIdState,
      tenants,
      config,
      login,
      logout,
      switchTenant,
      hasPermission,
      hasAnyRole,
    ],
  );

  return <AuthContext.Provider value={value}>{children}</AuthContext.Provider>;
}

// ─── Hook ────────────────────────────────────────────────────────────────────

export function useAuth(): AuthContextValue {
  const ctx = useContext(AuthContext);
  if (!ctx) {
    throw new Error('useAuth must be used within an AuthProvider');
  }
  return ctx;
}

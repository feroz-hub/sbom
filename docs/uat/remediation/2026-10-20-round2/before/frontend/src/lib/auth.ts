import { PUBLIC_ID } from '@/lib/publicId';
/** Browser-safe authentication configuration and tenant preference helpers. */

export interface AuthConfig {
  enabled: boolean;
  issuer: string;
  clientId: string;
  redirectUri: string;
  postLogoutRedirectUri: string;
  scopes: string;
}

export function resolveAuthConfig(): AuthConfig {
  const origin = typeof window === 'undefined' ? 'https://localhost:3000' : window.location.origin;
  return {
    enabled: process.env.NEXT_PUBLIC_AUTH_ENABLED === 'true',
    issuer: process.env.NEXT_PUBLIC_HCL_IAM_ISSUER || '',
    clientId: process.env.NEXT_PUBLIC_HCL_IAM_CLIENT_ID || '',
    redirectUri: process.env.NEXT_PUBLIC_HCL_IAM_REDIRECT_URI || `${origin}/auth/callback`,
    postLogoutRedirectUri:
      process.env.NEXT_PUBLIC_HCL_IAM_POST_LOGOUT_REDIRECT_URI ||
      process.env.NEXT_PUBLIC_HCL_IAM_POST_LOGOUT_URI ||
      `${origin}/logged-out`,
    scopes: process.env.NEXT_PUBLIC_HCL_IAM_SCOPES || 'openid profile email offline_access sbom-analyser-api',
  };
}

const ACTIVE_TENANT_KEY = 'sbom_active_tenant_id';
export const ACTIVE_TENANT_COOKIE = 'sbom_active_tenant_id';

function syncActiveTenantCookie(value: string | null): void {
  if (typeof document === 'undefined') return;
  const secure = typeof location !== 'undefined' && location.protocol === 'https:' ? '; Secure' : '';
  if (value && PUBLIC_ID.test(value)) {
    document.cookie = `${ACTIVE_TENANT_COOKIE}=${encodeURIComponent(value)}; Path=/; SameSite=Strict; Max-Age=86400${secure}`;
    return;
  }
  document.cookie = `${ACTIVE_TENANT_COOKIE}=; Path=/; SameSite=Strict; Max-Age=0${secure}`;
}

export function getActiveTenantId(): string | null {
  if (typeof sessionStorage === 'undefined') return null;
  const value = sessionStorage.getItem(ACTIVE_TENANT_KEY);
  // This preference survives a deployment/database change in an existing tab.
  // Legacy integers and malformed values cannot become UUID tenant headers.
  if (value !== null && !PUBLIC_ID.test(value)) {
    clearActiveTenantId();
    return null;
  }
  return value;
}

export function setActiveTenantId(tenantId: string): void {
  if (!PUBLIC_ID.test(tenantId)) {
    clearActiveTenantId();
    return;
  }
  sessionStorage.setItem(ACTIVE_TENANT_KEY, tenantId);
  syncActiveTenantCookie(tenantId);
}

export function clearActiveTenantId(): void {
  if (typeof sessionStorage !== 'undefined') sessionStorage.removeItem(ACTIVE_TENANT_KEY);
  syncActiveTenantCookie(null);
}

export { safeReturnPath } from './auth/return-path';

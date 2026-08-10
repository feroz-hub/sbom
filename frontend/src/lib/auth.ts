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
      origin,
    scopes: process.env.NEXT_PUBLIC_HCL_IAM_SCOPES || 'openid profile email offline_access sbom-analyser-api',
  };
}

const ACTIVE_TENANT_KEY = 'sbom_active_tenant_id';

export function getActiveTenantId(): string | null {
  return typeof sessionStorage === 'undefined' ? null : sessionStorage.getItem(ACTIVE_TENANT_KEY);
}

export function setActiveTenantId(tenantId: string): void {
  sessionStorage.setItem(ACTIVE_TENANT_KEY, tenantId);
}

export function clearActiveTenantId(): void {
  if (typeof sessionStorage !== 'undefined') sessionStorage.removeItem(ACTIVE_TENANT_KEY);
}

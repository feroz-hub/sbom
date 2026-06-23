import { describe, it, expect, vi, beforeEach } from 'vitest';
import {
  oidcEndpoints,
  resolveOidcEndpoints,
  resolveAuthConfig,
  storeTokens,
  getAccessToken,
  setActiveTenantId,
  getActiveTenantId,
  clearTokens,
} from '@/lib/auth';

describe('oidc endpoints', () => {
  it('derives Keycloak-style URLs from issuer', () => {
    const eps = oidcEndpoints('https://iam.example.com/realms/sbom');
    expect(eps.authorization).toContain('/protocol/openid-connect/auth');
    expect(eps.token).toContain('/protocol/openid-connect/token');
  });

  it('prefers explicit env URLs over issuer derivation', () => {
    vi.stubEnv('NEXT_PUBLIC_HCL_IAM_AUTHORIZATION_URL', 'https://custom/auth');
    vi.stubEnv('NEXT_PUBLIC_HCL_IAM_TOKEN_URL', 'https://custom/token');
    vi.stubEnv('NEXT_PUBLIC_HCL_IAM_LOGOUT_URL', 'https://custom/logout');
    const config = resolveAuthConfig();
    const eps = resolveOidcEndpoints(config);
    expect(eps.authorization).toBe('https://custom/auth');
    expect(eps.token).toBe('https://custom/token');
    expect(eps.logout).toBe('https://custom/logout');
    vi.unstubAllEnvs();
  });
});

describe('token storage', () => {
  beforeEach(() => {
    const store: Record<string, string> = {};
    vi.stubGlobal('sessionStorage', {
      getItem: (k: string) => store[k] ?? null,
      setItem: (k: string, v: string) => {
        store[k] = v;
      },
      removeItem: (k: string) => {
        delete store[k];
      },
      clear: () => {
        Object.keys(store).forEach((k) => delete store[k]);
      },
    });
    clearTokens();
  });

  it('stores and retrieves access token', () => {
    storeTokens({ access_token: 'test-token-123' });
    expect(getAccessToken()).toBe('test-token-123');
  });

  it('stores active tenant id', () => {
    setActiveTenantId('42');
    expect(getActiveTenantId()).toBe('42');
  });
});

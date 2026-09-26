import { afterEach, expect, it, vi } from 'vitest';
vi.mock('server-only', () => ({}));
import { serverAuthConfig } from './server-config';

afterEach(() => vi.unstubAllEnvs());
it('allows authenticated Native-only BFF without HCL configuration', () => {
  vi.stubEnv('NEXT_PUBLIC_AUTH_ENABLED', 'true');
  vi.stubEnv('NEXT_PUBLIC_HCL_AUTH_ENABLED', 'false');
  vi.stubEnv('NEXT_PUBLIC_HCL_IAM_ISSUER', '');
  vi.stubEnv('NEXT_PUBLIC_HCL_IAM_CLIENT_ID', '');
  expect(serverAuthConfig().enabled).toBe(true);
});
it('preserves required HCL configuration when HCL is enabled', () => {
  vi.stubEnv('NEXT_PUBLIC_AUTH_ENABLED', 'true');
  vi.stubEnv('NEXT_PUBLIC_HCL_AUTH_ENABLED', 'true');
  vi.stubEnv('NEXT_PUBLIC_HCL_IAM_ISSUER', '');
  expect(() => serverAuthConfig()).toThrow('Missing OIDC configuration');
});

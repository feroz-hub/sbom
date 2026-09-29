vi.mock('server-only', () => ({}));
import { afterEach, beforeEach, expect, it, vi } from 'vitest';
import { entraConfig } from './entra-config';

beforeEach(() => {
  for (const [key, value] of Object.entries({ ENTRA_ENABLED: 'true', NEXT_PUBLIC_AUTH_ENABLED: 'true', APP_ORIGIN: 'https://sbom.test',
    ENTRA_TENANT_ID: '11111111-1111-4111-8111-111111111111', ENTRA_FRONTEND_CLIENT_ID: '22222222-2222-4222-8222-222222222222',
    ENTRA_API_CLIENT_ID: '33333333-3333-4333-8333-333333333333', ENTRA_API_SCOPE: 'api://33333333-3333-4333-8333-333333333333/access_as_user' })) vi.stubEnv(key, value);
});
afterEach(() => vi.unstubAllEnvs());
it('derives one tenant-specific authority and canonical callback', () => {
  expect(entraConfig()).toMatchObject({ authority: 'https://login.microsoftonline.com/11111111-1111-4111-8111-111111111111', redirectUri: 'https://sbom.test/auth/entra-callback' });
});
it.each([['ENTRA_TENANT_ID', 'common'], ['ENTRA_TENANT_ID', 'organizations'], ['ENTRA_TENANT_ID', 'consumers'], ['ENTRA_API_SCOPE', 'api://api/.default'], ['ENTRA_API_SCOPE', ''], ['APP_ORIGIN', 'http://sbom.test'], ['ENTRA_FRONTEND_CLIENT_ID', '33333333-3333-4333-8333-333333333333']])('rejects invalid %s', (key, value) => {
  vi.stubEnv(key, value); expect(entraConfig).toThrow(/configuration invalid/);
});
it('needs no Microsoft configuration when disabled', () => {
  vi.stubEnv('ENTRA_ENABLED', 'false'); vi.stubEnv('ENTRA_TENANT_ID', ''); expect(entraConfig()).toBeNull();
});

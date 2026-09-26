import { afterEach, expect, it, vi } from 'vitest';
import { validateProductionAuth } from './production-config';
afterEach(() => vi.unstubAllEnvs());
it('fails safely for production native without shared secrets', () => {
  vi.stubEnv('NODE_ENV', 'production'); vi.stubEnv('NEXT_PUBLIC_AUTH_ENABLED', 'true'); vi.stubEnv('NATIVE_AUTH_ENABLED', 'true'); vi.stubEnv('AUTH_SESSION_STORE', 'memory');
  vi.stubEnv('AUTH_SESSION_ENCRYPTION_KEY', 'secret'); vi.stubEnv('APP_ORIGIN', 'http://unsafe');
  expect(validateProductionAuth).toThrow(/shared_session_store/);
  try { validateProductionAuth(); } catch (e) { expect(String(e)).not.toContain('secret'); }
});
it('accepts required production configuration', () => {
  vi.stubEnv('NODE_ENV', 'production'); vi.stubEnv('NEXT_PUBLIC_AUTH_ENABLED', 'true'); vi.stubEnv('NATIVE_AUTH_ENABLED', 'true'); vi.stubEnv('AUTH_SESSION_STORE', 'redis');
  vi.stubEnv('AUTH_SESSION_ENCRYPTION_KEY', Buffer.alloc(32, 1).toString('base64')); vi.stubEnv('APP_ORIGIN', 'https://sbom.test'); vi.stubEnv('AUTH_SESSION_REDIS_URL', 'redis://localhost:6379/1');
  expect(validateProductionAuth).not.toThrow();
});
it('does not impose native configuration on HCL-only deployment', () => {
  vi.stubEnv('NODE_ENV', 'production'); vi.stubEnv('NEXT_PUBLIC_AUTH_ENABLED', 'true'); vi.stubEnv('NATIVE_AUTH_ENABLED', 'false'); expect(validateProductionAuth).not.toThrow();
});

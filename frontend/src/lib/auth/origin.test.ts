import { afterEach, describe, expect, it, vi } from 'vitest';
import { trustedMutationOrigin } from './origin';
afterEach(() => vi.unstubAllEnvs());
describe('cookie mutation origin', () => {
  it.each([null, 'https://evil.test', 'null', 'http://localhost:3000'])('rejects %s', origin => {
    vi.stubEnv('APP_ORIGIN', 'https://sbom.test');
    expect(trustedMutationOrigin(new Request('https://sbom.test', { headers: origin ? { origin } : {} }))).toBe(false);
  });
  it('accepts the configured origin and rejects cross-site fetch metadata', () => {
    vi.stubEnv('APP_ORIGIN', 'https://sbom.test');
    expect(trustedMutationOrigin(new Request('https://sbom.test', { headers: { origin: 'https://sbom.test' } }))).toBe(true);
    expect(trustedMutationOrigin(new Request('https://sbom.test', { headers: { origin: 'https://sbom.test', 'sec-fetch-site': 'cross-site' } }))).toBe(false);
  });
});

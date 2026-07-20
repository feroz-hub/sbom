import { afterEach, describe, expect, it, vi } from 'vitest';

vi.mock('server-only', () => ({}));

import { resolveFrontendPath, serverAuthConfig } from './server-config';

afterEach(() => {
  delete process.env.HCL_IAM_CA_BUNDLE;
});

describe('portable server authentication paths', () => {
  it('resolves a relative CA bundle from the frontend working directory', () => {
    process.env.HCL_IAM_CA_BUNDLE = '../.certificates/hcl-cs-local.crt';

    expect(serverAuthConfig().caBundle).toBe(
      `${process.cwd()}/../.certificates/hcl-cs-local.crt`,
    );
  });

  it('preserves absolute paths and empty configuration', () => {
    expect(resolveFrontendPath('/opt/sbom/hcl-ca.crt')).toBe('/opt/sbom/hcl-ca.crt');
    expect(resolveFrontendPath('')).toBe('');
  });
});

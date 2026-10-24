import path from 'node:path';

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

      path.resolve(process.cwd(), '../.certificates/hcl-cs-local.crt'),

    );

  });
 
  it('preserves POSIX absolute paths', () => {

    expect(resolveFrontendPath('/opt/sbom/hcl-ca.crt')).toBe(

      '/opt/sbom/hcl-ca.crt',

    );

  });
 
  it('preserves Windows absolute paths', () => {

    expect(

      resolveFrontendPath('C:\\Projects\\certificates\\rootCA.pem'),

    ).toBe('C:\\Projects\\certificates\\rootCA.pem');

  });
 
  it('preserves empty configuration', () => {

    expect(resolveFrontendPath('')).toBe('');

  });

});
 
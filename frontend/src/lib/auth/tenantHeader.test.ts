import { describe, expect, it } from 'vitest';
import { applyServerDerivedTenantHeader } from './tenantHeader';

describe('authenticated BFF tenant derivation', () => {
  it('adds a validated tenant id for native EventSource requests', () => {
    const headers = new Headers({ Accept: 'text/event-stream' });
    applyServerDerivedTenantHeader(headers, '17');
    expect(headers.get('X-Tenant-ID')).toBe('17');
  });

  it('never accepts URL/token-like cookie content', () => {
    const headers = new Headers();
    applyServerDerivedTenantHeader(headers, '17?access_token=unsafe');
    expect(headers.has('X-Tenant-ID')).toBe(false);
  });

  it('does not overwrite the normal request helper header', () => {
    const headers = new Headers({ 'X-Tenant-ID': '5' });
    applyServerDerivedTenantHeader(headers, '17');
    expect(headers.get('X-Tenant-ID')).toBe('5');
  });
});

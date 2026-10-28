// @vitest-environment jsdom

import { beforeEach, describe, expect, it } from 'vitest';
import {
  ACTIVE_TENANT_COOKIE,
  clearActiveTenantId,
  getActiveTenantId,
  setActiveTenantId,
} from './auth';

describe('active tenant propagation for authenticated streams', () => {
  beforeEach(() => {
    sessionStorage.clear();
    document.cookie = `${ACTIVE_TENANT_COOKIE}=; Path=/; Max-Age=0`;
  });

  it('mirrors the non-secret tenant id into same-origin cookie context', () => {
    setActiveTenantId('00000000-0000-4000-8000-000000000011');
    expect(getActiveTenantId()).toBe('00000000-0000-4000-8000-000000000011');
    expect(document.cookie).toContain(`${ACTIVE_TENANT_COOKIE}=00000000-0000-4000-8000-000000000011`);
  });

  it('removes both tenant preference stores on clear', () => {
    setActiveTenantId('00000000-0000-4000-8000-000000000011');
    clearActiveTenantId();
    expect(getActiveTenantId()).toBeNull();
    expect(document.cookie).not.toContain(`${ACTIVE_TENANT_COOKIE}=`);
  });

  it('does not write malformed tenant ids into the cookie', () => {
    setActiveTenantId('17?token=unsafe');
    expect(getActiveTenantId()).toBeNull();
    expect(document.cookie).not.toContain(ACTIVE_TENANT_COOKIE);
  });

  it.each(['1', '17', 'NaN', 'undefined', '', 'not-a-uuid', '00000000-0000-1000-8000-000000000011'])(
    'clears an existing invalid tenant preference before making requests: %s', value => {
      sessionStorage.setItem('sbom_active_tenant_id', value);
      document.cookie = `${ACTIVE_TENANT_COOKIE}=${encodeURIComponent(value)}; Path=/`;
      expect(getActiveTenantId()).toBeNull();
      expect(sessionStorage.getItem('sbom_active_tenant_id')).toBeNull();
      expect(document.cookie).not.toContain(`${ACTIVE_TENANT_COOKIE}=`);
    },
  );
});

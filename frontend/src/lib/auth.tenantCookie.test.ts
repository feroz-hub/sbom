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
    setActiveTenantId('17');
    expect(getActiveTenantId()).toBe('17');
    expect(document.cookie).toContain(`${ACTIVE_TENANT_COOKIE}=17`);
  });

  it('removes both tenant preference stores on clear', () => {
    setActiveTenantId('17');
    clearActiveTenantId();
    expect(getActiveTenantId()).toBeNull();
    expect(document.cookie).not.toContain(`${ACTIVE_TENANT_COOKIE}=`);
  });

  it('does not write malformed tenant ids into the cookie', () => {
    setActiveTenantId('17?token=unsafe');
    expect(getActiveTenantId()).toBeNull();
    expect(document.cookie).not.toContain(ACTIVE_TENANT_COOKIE);
  });
});

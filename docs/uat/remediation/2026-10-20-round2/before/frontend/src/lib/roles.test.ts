import { describe, expect, it } from 'vitest';
import { getRoleCode, getRoleLabel } from './roles';

describe('roles utility', () => {
  it('returns role name when provided as an object', () => {
    const role1 = { id: 1, code: 'PLATFORM_ADMIN', name: 'Platform Administrator' };
    const role2 = { id: 2, code: 'ANALYST', name: 'Analyst' };

    expect(getRoleLabel(role1)).toBe('Platform Administrator');
    expect(getRoleLabel(role2)).toBe('Analyst');
  });

  it('formats known role codes with user-friendly labels when name is missing', () => {
    const role = { id: 3, code: 'SECURITY_ANALYST' };
    expect(getRoleLabel(role)).toBe('Security Analyst');
  });

  it('falls back to string id if name and code are missing', () => {
    const role = { id: 4 };
    expect(getRoleLabel(role)).toBe('4');
  });

  it('handles string compatibility with user-friendly formatting for known roles', () => {
    expect(getRoleLabel('VIEWER')).toBe('Viewer');
    expect(getRoleLabel('TENANT_ADMIN')).toBe('Tenant Admin');
    expect(getRoleLabel('CUSTOM_ROLE')).toBe('CUSTOM_ROLE');
  });

  it('handles empty or undefined values safely', () => {
    expect(getRoleLabel(null)).toBe('No role');
    expect(getRoleLabel(undefined)).toBe('No role');
  });

  it('extracts role codes correctly', () => {
    expect(getRoleCode({ id: 1, code: 'PLATFORM_ADMIN', name: 'Platform Administrator' })).toBe('PLATFORM_ADMIN');
    expect(getRoleCode('VIEWER')).toBe('VIEWER');
    expect(getRoleCode(null)).toBe('');
  });
});

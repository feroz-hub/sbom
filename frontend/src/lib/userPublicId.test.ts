import { describe, it, expect } from 'vitest';
import { publicId } from './publicId';
import { validateTenantForm } from './tenantForm';

const user = '550e8400-e29b-41d4-a716-446655440000';
describe('IAM User UUID-only selection', () => {
  it.each([123, '123', 'malformed', '550e8400-e29b-11d4-a716-446655440000', '550e8400-e29b-41d4-7716-446655440000', null])('refuses invalid user reference %s', id => {
    expect(publicId(id)).toBeNull();
    expect(validateTenantForm({ name: 'Synthetic', slug: 'synthetic', initial_admin_user_id: id as string }).initial_admin_user_id).toBeTruthy();
  });
  it('accepts a UUIDv4 initial administrator without numeric coercion', () => {
    expect(publicId(user.toUpperCase())).toBe(user);
    expect(validateTenantForm({ name: 'Synthetic', slug: 'synthetic', initial_admin_user_id: user })).toEqual({});
  });
});

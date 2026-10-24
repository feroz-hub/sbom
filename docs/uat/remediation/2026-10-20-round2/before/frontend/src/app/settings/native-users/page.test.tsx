import { expect, it, vi } from 'vitest';
import NativeUsersPage from './page';
import TenantUsersPage from '../tenant/page';
const redirect = vi.hoisted(() => vi.fn(() => { throw new Error('redirect'); }));
vi.mock('next/navigation', () => ({ redirect }));
it.each([NativeUsersPage, TenantUsersPage])('redirects legacy user administration to the canonical route', Page => {
  expect(() => Page()).toThrow('redirect');
  expect(redirect).toHaveBeenLastCalledWith('/settings/users');
});

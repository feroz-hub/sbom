// @vitest-environment jsdom
import { fireEvent, render, screen } from '@testing-library/react';
import { describe, expect, it, vi } from 'vitest';
import UsersAccessPage from './page';
const auth = vi.hoisted(() => ({ user: { isPlatformAdmin: false }, hasPermission: vi.fn(), isLoading: false }));
vi.mock('@/hooks/useAuth', () => ({ useAuth: () => auth }));
vi.mock('@/components/admin/UserLifecycle', () => ({ default: ({ onAdd }: { onAdd?: () => void }) => <><p>Global accounts</p>{onAdd && <button onClick={onAdd}>Add User</button>}</> }));
vi.mock('@/components/admin/TenantUsersAccess', () => ({ default: () => <p>Tenant membership view</p> }));
vi.mock('@/components/admin/NativeUserInviteForm', () => ({ default: () => <p>Invitation form</p> }));
describe('Users & Access scope', () => {
  it('renders global accounts only for a platform admin with platform read', () => {
    auth.user.isPlatformAdmin = true;
    auth.hasPermission.mockReturnValue(true);
    render(<UsersAccessPage />);
    expect(screen.getByText('Global accounts')).toBeInTheDocument();
    expect(screen.queryByText('Tenant membership view')).not.toBeInTheDocument();
    fireEvent.click(screen.getByRole('button', { name: 'Add User' }));
    expect(screen.getByText('Invitation form')).toBeInTheDocument();
  });
  it.each([false, true])('uses only membership administration without platform read (platform=%s)', platform => {
    auth.user.isPlatformAdmin = platform;
    auth.hasPermission.mockImplementation((p: string) => p === 'tenant:user:read');
    render(<UsersAccessPage />);
    expect(screen.getByText('Tenant membership view')).toBeInTheDocument();
    expect(screen.queryByText('Global accounts')).not.toBeInTheDocument();
    expect(screen.queryByRole('button', { name: 'Add User' })).not.toBeInTheDocument();
  });
});

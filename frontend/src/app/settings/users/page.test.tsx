// @vitest-environment jsdom
import { render, screen } from '@testing-library/react';
import { describe, expect, it, vi } from 'vitest';
import UsersAccessPage from './page';
const auth = vi.hoisted(() => ({ user: { isPlatformAdmin: false }, hasPermission: vi.fn(), isLoading: false }));
vi.mock('@/hooks/useAuth', () => ({ useAuth: () => auth }));
vi.mock('@/components/admin/UserLifecycle', () => ({ default: ({ onAdd }: { onAdd?: () => void }) => <><p>Global accounts</p>{onAdd && <button onClick={onAdd}>Add User</button>}</> }));
vi.mock('@/components/admin/TenantUsersAccess', () => ({ default: () => <p>Tenant membership view</p> }));
vi.mock('@/components/admin/NativeUserInviteForm', () => ({ default: () => <p>Invitation form</p> }));
describe('Users & Access scope', () => {
  it('never renders a global account directory for platform administrators', () => {
    auth.user.isPlatformAdmin = true;
    auth.hasPermission.mockReturnValue(true);
    render(<UsersAccessPage />);
    expect(screen.queryByText('Global accounts')).not.toBeInTheDocument();
    expect(screen.getByText('Tenant membership view')).toBeInTheDocument();
    expect(screen.queryByText('Invitation form')).not.toBeInTheDocument();
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

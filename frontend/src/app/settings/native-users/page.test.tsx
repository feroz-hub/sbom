// @vitest-environment jsdom
import { fireEvent, render, screen } from '@testing-library/react';
import { describe, expect, it, vi } from 'vitest';
import NativeUsersPage from './page';

const auth = vi.hoisted(() => ({ hasPermission: vi.fn() }));
vi.mock('@/hooks/useAuth', () => ({ useAuth: () => auth }));
vi.mock('@/components/admin/UserLifecycle', () => ({ default: ({ onAdd }: { onAdd?: () => void }) => <><p>User directory</p>{onAdd && <button onClick={onAdd}>Add User</button>}</> }));
vi.mock('@/components/admin/NativeUserInviteForm', () => ({ default: () => <p>Invitation form</p> }));

describe('Native user page actions', () => {
  it('hides invitation actions from a Viewer', () => {
    auth.hasPermission.mockReturnValue(false);
    render(<NativeUsersPage />);
    expect(screen.queryByRole('button', { name: 'Add User' })).not.toBeInTheDocument();
    expect(screen.queryByText('Invitation form')).not.toBeInTheDocument();
  });

  it.each(['tenant:user:invite', 'platform:user:manage_status'])('shows invitations with %s', permission => {
    auth.hasPermission.mockImplementation((value: string) => value === permission);
    render(<NativeUsersPage />);
    fireEvent.click(screen.getByRole('button', { name: 'Add User' }));
    expect(screen.getByRole('dialog', { name: 'Add native user' })).toBeInTheDocument();
    expect(screen.getByText('Invitation form')).toBeInTheDocument();
  });
});

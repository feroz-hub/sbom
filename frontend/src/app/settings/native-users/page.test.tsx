// @vitest-environment jsdom
import { render, screen } from '@testing-library/react';
import { describe, expect, it, vi } from 'vitest';
import NativeUsersPage from './page';

const auth = vi.hoisted(() => ({ hasPermission: vi.fn() }));
vi.mock('@/hooks/useAuth', () => ({ useAuth: () => auth }));
vi.mock('@/components/admin/UserLifecycle', () => ({ default: () => <p>User directory</p> }));
vi.mock('@/components/admin/NativeUserInviteForm', () => ({ default: () => <p>Invitation form</p> }));

describe('Native user page actions', () => {
  it('hides invitation actions from a Viewer', () => {
    auth.hasPermission.mockReturnValue(false);
    render(<NativeUsersPage />);
    expect(screen.queryByText('Invite native user')).not.toBeInTheDocument();
    expect(screen.queryByText('Invitation form')).not.toBeInTheDocument();
  });

  it.each(['tenant:user:invite', 'platform:user:manage_status'])('shows invitations with %s', permission => {
    auth.hasPermission.mockImplementation((value: string) => value === permission);
    render(<NativeUsersPage />);
    expect(screen.getByText('Invite native user')).toBeInTheDocument();
  });
});

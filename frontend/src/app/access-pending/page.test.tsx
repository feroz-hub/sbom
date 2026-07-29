// @vitest-environment jsdom

import { render, screen } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { beforeEach, describe, expect, it, vi } from 'vitest';

const auth = vi.hoisted(() => ({
  refreshSession: vi.fn(),
  logout: vi.fn(),
}));
const router = vi.hoisted(() => ({
  push: vi.fn(),
  refresh: vi.fn(),
}));

vi.mock('@/hooks/useAuth', () => ({
  useAuth: () => ({
    user: { email: 'pending@example.test', userId: 9 },
    refreshSession: auth.refreshSession,
    logout: auth.logout,
  }),
}));
vi.mock('next/navigation', () => ({
  useRouter: () => router,
}));

import AccessPendingPage from './page';

describe('AccessPendingPage', () => {
  beforeEach(() => {
    vi.clearAllMocks();
    auth.refreshSession.mockResolvedValue(undefined);
  });

  it('rechecks the existing session and authorization context without starting OIDC', async () => {
    const user = userEvent.setup();
    render(<AccessPendingPage />);
    expect(screen.getByText(/pending@example.test/)).toBeInTheDocument();

    await user.click(screen.getByRole('button', { name: 'Retry Access' }));

    expect(auth.refreshSession).toHaveBeenCalledTimes(1);
    expect(router.push).toHaveBeenCalledWith('/');
    expect(router.refresh).toHaveBeenCalledTimes(1);
    expect(window.location.href).not.toContain('/api/auth/login');
  });

  it('signs out only when explicitly requested', async () => {
    const user = userEvent.setup();
    render(<AccessPendingPage />);
    await user.click(screen.getByRole('button', { name: 'Sign Out' }));
    expect(auth.logout).toHaveBeenCalledTimes(1);
  });
});

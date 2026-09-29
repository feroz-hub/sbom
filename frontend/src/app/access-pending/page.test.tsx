// @vitest-environment jsdom

import { render, screen } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { beforeEach, describe, expect, it, vi } from 'vitest';

const auth = vi.hoisted(() => ({
  refreshSession: vi.fn(),
  logout: vi.fn(),
  localStatus: 'ACTIVE',
}));
const router = vi.hoisted(() => ({
  push: vi.fn(),
  refresh: vi.fn(),
}));

vi.mock('@/hooks/useAuth', () => ({
  useAuth: () => ({
    user: { email: 'pending@example.test', userId: 9, localStatus: auth.localStatus },
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
    auth.localStatus = 'ACTIVE';
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

it('explains successful Microsoft authentication awaiting local approval', () => {
  auth.localStatus = 'PENDING';
  render(<AccessPendingPage />);
  expect(screen.getByRole('heading', { name: 'Authentication successful' })).toBeInTheDocument();
  expect(screen.getByText('Your access to SBOM Analyzer is awaiting Platform Administrator approval.')).toBeInTheDocument();
});

// @vitest-environment jsdom

import { QueryClient, QueryClientProvider } from '@tanstack/react-query';
import { render, screen } from '@testing-library/react';
import type { ReactNode } from 'react';
import { beforeEach, describe, expect, it, vi } from 'vitest';
import type { BootstrapState } from '@/hooks/useAuth';

const mockPathname = vi.hoisted(() => ({ current: '/' }));
const mockAuth = vi.hoisted(() => ({
  bootstrapState: 'checking-session' as BootstrapState,
  bootstrapError: null as string | null,
  config: { enabled: true },
  login: vi.fn(),
  retryBootstrap: vi.fn(),
  hasPermission: () => true,
  user: null,
  tenants: [],
}));

vi.mock('next/navigation', () => ({
  usePathname: () => mockPathname.current,
  useRouter: () => ({
    push: vi.fn(),
    replace: vi.fn(),
    prefetch: vi.fn(),
  }),
  useSearchParams: () => new URLSearchParams(),
}));

vi.mock('@/hooks/useAuth', () => ({
  useAuth: () => mockAuth,
}));

import { AppShell } from '../AppShell';

function wrap(children: ReactNode) {
  const queryClient = new QueryClient({ defaultOptions: { queries: { retry: false } } });
  return render(
    <QueryClientProvider client={queryClient}>
      {children}
    </QueryClientProvider>,
  );
}

describe('AppShell route isolation & bootstrap loader UX', () => {
  beforeEach(() => {
    vi.clearAllMocks();
    mockPathname.current = '/';
    mockAuth.bootstrapState = 'checking-session';
    mockAuth.bootstrapError = null;
    mockAuth.tenants = [];
  });

  it('renders one shared full-screen branded loader without sidebar or navigation during bootstrap', () => {
    wrap(<AppShell><div>Protected Content</div></AppShell>);

    expect(screen.getByText('SBOM Analyzer')).toBeInTheDocument();
    expect(screen.getByText('Verifying authentication…')).toBeInTheDocument();
    expect(screen.queryByText('Protected Content')).not.toBeInTheDocument();
    expect(screen.queryByLabelText('Primary navigation')).not.toBeInTheDocument();
    expect(screen.queryByText('API healthy')).not.toBeInTheDocument();
  });

  it('isolates public/auth transition routes from sidebar and shell layout', () => {
    mockPathname.current = '/auth/callback';
    wrap(<AppShell><div>Callback Child</div></AppShell>);

    expect(screen.getByText('Callback Child')).toBeInTheDocument();
    expect(screen.queryByLabelText('Primary navigation')).not.toBeInTheDocument();
    expect(screen.queryByText('API healthy')).not.toBeInTheDocument();
  });

  it('renders recovery UX on bootstrap timeout with Retry and Sign in again actions', () => {
    mockPathname.current = '/';
    mockAuth.bootstrapState = 'error';
    mockAuth.bootstrapError = 'Sign-in is taking longer than expected.';

    wrap(<AppShell><div>Protected Content</div></AppShell>);

    expect(screen.getByText('Sign-in is taking longer than expected')).toBeInTheDocument();
    expect(screen.getByRole('button', { name: 'Retry' })).toBeInTheDocument();
    expect(screen.getByRole('button', { name: 'Sign in again' })).toBeInTheDocument();
    expect(screen.queryByLabelText('Primary navigation')).not.toBeInTheDocument();
  });

  it('renders protected app shell with sidebar when bootstrap state is ready', () => {
    mockPathname.current = '/';
    mockAuth.bootstrapState = 'ready';

    wrap(<AppShell><div>Protected Dashboard Content</div></AppShell>);

    expect(screen.getByText('Protected Dashboard Content')).toBeInTheDocument();
    expect(screen.getByLabelText('Primary navigation')).toBeInTheDocument();
  });
});

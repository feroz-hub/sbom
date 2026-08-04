// @vitest-environment jsdom

import { render, screen } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { beforeEach, describe, expect, it, vi } from 'vitest';

import type { TenantInfo } from '@/hooks/useAuth';
import { AuthGuard } from '../AuthGuard';

const mockReplace = vi.fn();
const mockPush = vi.fn();
const mockLogin = vi.fn();
const mockSelectTenant = vi.fn();

let mockPathname = '/';

vi.mock('next/navigation', () => ({
  usePathname: () => mockPathname,
  useRouter: () => ({ push: mockPush, replace: mockReplace, refresh: vi.fn() }),
}));

// Only ``useAuth`` is faked — ``isSelectableTenant`` stays real so the guard and
// the provider agree on which memberships are offered.
vi.mock('@/hooks/useAuth', async () => {
  const actual = await vi.importActual<typeof import('@/hooks/useAuth')>('@/hooks/useAuth');
  return { ...actual, useAuth: () => mockAuthContext };
});

function tenant(overrides: Partial<TenantInfo> & { id: number; name: string }): TenantInfo {
  return {
    slug: overrides.name.toLowerCase(),
    externalIamTenantId: null,
    status: 'ACTIVE',
    role: 'TENANT_ADMIN',
    roles: ['TENANT_ADMIN'],
    membershipStatus: 'ACTIVE',
    platformContextAvailable: false,
    ...overrides,
  };
}

const tenants = [
  tenant({ id: 7, name: 'Wellysis' }),
  tenant({ id: 1, name: 'Acme', role: 'VIEWER', roles: ['VIEWER'] }),
  // Disabled membership — must not be offered as a choice.
  tenant({ id: 9, name: 'Retired', membershipStatus: 'DISABLED', status: 'DISABLED' }),
];

let mockAuthContext: Record<string, unknown>;

function contextFor(bootstrapState: string, authStatus: string) {
  return {
    authStatus,
    bootstrapState,
    config: { enabled: true },
    login: mockLogin,
    reloadAuth: vi.fn(),
    hasPermission: () => true,
    hasAnyRole: () => true,
    tenants,
    selectTenant: mockSelectTenant,
  };
}

describe('AuthGuard tenant selection', () => {
  beforeEach(() => {
    vi.clearAllMocks();
    mockPathname = '/';
    mockAuthContext = contextFor('tenant-selection-required', 'tenant-selection-required');
  });

  it('renders the tenant selection screen instead of protected children', () => {
    render(
      <AuthGuard>
        <div>dashboard content</div>
      </AuthGuard>,
    );

    expect(screen.getByRole('heading', { name: /select tenant/i })).toBeInTheDocument();
    expect(screen.queryByText('dashboard content')).not.toBeInTheDocument();
  });

  it('offers only selectable active memberships', () => {
    render(
      <AuthGuard>
        <div>dashboard content</div>
      </AuthGuard>,
    );

    expect(screen.getByRole('button', { name: /Wellysis/ })).toBeInTheDocument();
    expect(screen.getByRole('button', { name: /Acme/ })).toBeInTheDocument();
    expect(screen.queryByRole('button', { name: /Retired/ })).not.toBeInTheDocument();
  });

  it('calls selectTenant with the chosen tenant id', async () => {
    const user = userEvent.setup();
    render(
      <AuthGuard>
        <div>dashboard content</div>
      </AuthGuard>,
    );

    await user.click(screen.getByRole('button', { name: /Acme/ }));

    expect(mockSelectTenant).toHaveBeenCalledWith('1');
  });

  it('does not redirect tenant selection to access-denied, access-pending, or sign-in', () => {
    render(
      <AuthGuard>
        <div>dashboard content</div>
      </AuthGuard>,
    );

    expect(mockReplace).not.toHaveBeenCalled();
    expect(mockPush).not.toHaveBeenCalled();
    expect(mockLogin).not.toHaveBeenCalled();
  });

  it('renders protected children once a tenant is selected and bootstrap is ready', () => {
    mockAuthContext = contextFor('ready', 'authenticated');

    render(
      <AuthGuard>
        <div>dashboard content</div>
      </AuthGuard>,
    );

    expect(screen.getByText('dashboard content')).toBeInTheDocument();
    expect(screen.queryByRole('heading', { name: /select tenant/i })).not.toBeInTheDocument();
  });
});

// @vitest-environment jsdom

import { render, screen } from '@testing-library/react';
import { describe, expect, it, vi } from 'vitest';
import VerificationRequiredPage from '../verification-required/page';
import AccessPendingPage from '../access-pending/page';
import AccessDeniedPage from '../access-denied/page';
import { RoleBadges, VerificationBadge, UserStatusBadge, MembershipStatusBadge } from '@/components/admin/StatusBadges';

vi.mock('next/navigation', () => ({
  useRouter: () => ({
    push: vi.fn(),
    replace: vi.fn(),
    refresh: vi.fn(),
  }),
}));

const mockLogout = vi.fn();
const mockReloadAuth = vi.fn();
const mockRefreshSession = vi.fn();

let mockActiveTenant: { membershipStatus?: string } | null = null;
const mockUser: { email?: string; userId?: number } | null = { email: 'user@hcltech.com', userId: 10 };

vi.mock('@/hooks/useAuth', () => ({
  useAuth: () => ({
    user: mockUser,
    activeTenant: mockActiveTenant,
    logout: mockLogout,
    reloadAuth: mockReloadAuth,
    refreshSession: mockRefreshSession,
  }),
}));

describe('User State Pages & Copy Contracts', () => {
  it('renders Email Verification Required page with exact title and description', () => {
    render(<VerificationRequiredPage />);

    expect(screen.getByText('Verify your email')).toBeInTheDocument();
    expect(
      screen.getByText(
        'You signed in successfully through HCL.CS. Verify your email address before requesting access to SBOM tenants.',
      ),
    ).toBeInTheDocument();
  });

  it('renders Access Pending page with exact title and description', () => {
    render(<AccessPendingPage />);

    expect(screen.getByText('Access assignment required')).toBeInTheDocument();
    expect(
      screen.getByText(
        'Your HCL.CS identity is verified, but you have not been assigned a platform role or active tenant membership.',
      ),
    ).toBeInTheDocument();
  });

  it('renders Tenant Access Disabled state when membership is disabled', () => {
    mockActiveTenant = { membershipStatus: 'DISABLED' };
    render(<AccessDeniedPage />);

    expect(screen.getByText('Tenant access disabled')).toBeInTheDocument();
    expect(
      screen.getByText(
        'Your HCL.CS sign-in is valid, but your membership in this tenant is currently disabled.',
      ),
    ).toBeInTheDocument();
  });

  it('renders SBOM Account Disabled state when account is disabled', () => {
    mockActiveTenant = null;
    render(<AccessDeniedPage />);

    expect(screen.getByText('SBOM account disabled')).toBeInTheDocument();
    expect(
      screen.getByText(
        'Your HCL.CS identity is valid, but your SBOM account has been disabled.',
      ),
    ).toBeInTheDocument();
  });
});

describe('Status Badges & Role Presentation', () => {
  it('formats role codes into human-readable role badges', () => {
    render(<RoleBadges roles={['TENANT_ADMIN', 'SECURITY_ANALYST', 'DEVELOPER', 'VIEWER']} />);

    expect(screen.getByText('Tenant Admin')).toBeInTheDocument();
    expect(screen.getByText('Security Analyst')).toBeInTheDocument();
    expect(screen.getByText('Developer')).toBeInTheDocument();
    expect(screen.getByText('Viewer')).toBeInTheDocument();
  });

  it('renders explicit separate status badges for verification, membership, and user account', () => {
    const { rerender } = render(
      <div>
        <VerificationBadge verified={true} />
        <MembershipStatusBadge status="ACTIVE" />
        <UserStatusBadge status="ACTIVE" />
      </div>,
    );

    expect(screen.getByText('Verification: Verified')).toBeInTheDocument();
    expect(screen.getByText('Current membership: Active')).toBeInTheDocument();
    expect(screen.getByText('User account: Active')).toBeInTheDocument();

    rerender(
      <div>
        <VerificationBadge verified={false} />
        <MembershipStatusBadge status="DISABLED" />
        <UserStatusBadge status="DISABLED" />
      </div>,
    );

    expect(screen.getByText('Verification: Verification required')).toBeInTheDocument();
    expect(screen.getByText('Current membership: Disabled')).toBeInTheDocument();
    expect(screen.getByText('User account: Disabled')).toBeInTheDocument();
  });
});

// @vitest-environment jsdom

import { QueryClient, QueryClientProvider } from '@tanstack/react-query';
import { render, screen, waitFor } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { beforeEach, describe, expect, it, vi } from 'vitest';
import { ToastProvider } from '@/hooks/useToast';

const api = vi.hoisted(() => ({
  getTenantMembers: vi.fn(),
  getAssignableTenantRoles: vi.fn(),
  addTenantMember: vi.fn(),
  replaceTenantMemberRoles: vi.fn(),
  activateTenantMember: vi.fn(),
  deactivateTenantMember: vi.fn(),
  removeTenantMember: vi.fn(),
  searchTenantUserCandidates: vi.fn(),
  searchPlatformUsers: vi.fn(),
  getTenantAuditHistory: vi.fn(),
}));

vi.mock('next/navigation', () => ({
  useRouter: () => ({
    push: vi.fn(),
    replace: vi.fn(),
    refresh: vi.fn(),
  }),
}));

vi.mock('@/hooks/useAuth', () => ({
  useAuth: () => ({
    user: { tenantId: 1, externalUserId: 'subject-1', userId: 999, isPlatformAdmin: true },
    activeTenantId: 1,
    activeTenant: { id: 1, name: 'Default Tenant', slug: 'default', externalIamTenantId: 'local-default', status: 'ACTIVE', role: 'TENANT_ADMIN', membershipStatus: 'ACTIVE' },
    tenants: [{ id: 1, name: 'Default Tenant', slug: 'default', externalIamTenantId: 'local-default', status: 'ACTIVE', role: 'TENANT_ADMIN', membershipStatus: 'ACTIVE' }],
    hasPermission: () => true,
    isLoading: false,
    isTenantContextLoading: false,
    refreshSession: vi.fn(),
  }),
}));
vi.mock('@/hooks/usePermission', () => ({ usePermission: () => true }));
vi.mock('@/lib/api', async (importOriginal) => ({
  ...(await importOriginal<typeof import('@/lib/api')>()),
  ...api,
}));

import TenantUsersPage from './page';

const member = {
  membership_id: 9,
  user_id: 12,
  external_iam_user_id: 'subject-12',
  email: 'user@example.test',
  display_name: 'Example User',
  user_status: 'ACTIVE',
  email_verified: true,
  verification_required: false,
  role: 'VIEWER' as const,
  roles: ['VIEWER'] as const,
  role_assignment_version: 1,
  status: 'ACTIVE' as const,
};

function renderPage() {
  const client = new QueryClient({ defaultOptions: { queries: { retry: false }, mutations: { retry: false } } });
  return render(<QueryClientProvider client={client}><ToastProvider><TenantUsersPage /></ToastProvider></QueryClientProvider>);
}

describe('TenantUsersPage', () => {
  beforeEach(() => {
    vi.clearAllMocks();
    api.getTenantMembers.mockResolvedValue([member]);
    api.getAssignableTenantRoles.mockResolvedValue({ roles: ['TENANT_ADMIN', 'SECURITY_ANALYST', 'DEVELOPER', 'VIEWER'] });
    api.addTenantMember.mockResolvedValue(member);
    api.replaceTenantMemberRoles.mockResolvedValue({
      membership_id: 9,
      user_id: 12,
      membership_status: 'ACTIVE',
      role_assignment_version: 2,
      primary_role: 'DEVELOPER',
      roles: ['DEVELOPER', 'VIEWER'],
      effective_permissions: [],
    });
    api.activateTenantMember.mockResolvedValue(member);
    api.deactivateTenantMember.mockResolvedValue({ ...member, status: 'DISABLED' });
    api.removeTenantMember.mockResolvedValue(undefined);
    api.getTenantAuditHistory.mockResolvedValue([]);
    vi.spyOn(window, 'confirm').mockReturnValue(true);
  });

  it('lists members with effective role badges, clean header, and read-only rows', async () => {
    renderPage();
    const userElements = await screen.findAllByText('Example User');
    expect(userElements[0]).toBeInTheDocument();
    expect(screen.getAllByText('Viewer')[0]).toBeInTheDocument();
    expect(screen.getAllByRole('button', { name: 'Open actions for Example User' })[0]).toBeInTheDocument();

    expect(screen.getAllByText('HCL.CS')[0]).toBeInTheDocument();
    expect(screen.getAllByText('Managed in SBOM')[0]).toBeInTheDocument();
    expect(screen.queryByText(/External tenant mapping/i)).not.toBeInTheDocument();
    expect(screen.queryByText(/Technical identity details/i)).not.toBeInTheDocument();
  });

  it('adds a member with an initial tenant role', async () => {
    const user = userEvent.setup();
    api.searchTenantUserCandidates.mockResolvedValue([
      {
        id: 99,
        email: 'new.user@hcltech.com',
        display_name: 'New User',
        status: 'ACTIVE',
        email_verified: true,
        verification_required: false,
        external_subject: 'new-hcl-sub',
      },
    ]);
    renderPage();
    await screen.findAllByText('Example User');
    const input = screen.getByPlaceholderText(/Search existing SBOM users/i);
    await user.type(input, 'New');
    const foundUser = await screen.findByText('New User');
    await user.click(foundUser);
    await user.selectOptions(screen.getByLabelText('Initial roles'), 'SECURITY_ANALYST');
    await user.click(screen.getByRole('button', { name: 'Add Member' }));
    await waitFor(() => expect(api.addTenantMember).toHaveBeenCalledWith(1, {
      user_id: 99, roles: ['SECURITY_ANALYST', 'VIEWER'],
    }));
  });

  it('manages roles via Manage roles modal, deactivates via Disable membership dialog, and removes with strong confirmation', async () => {
    const user = userEvent.setup();
    renderPage();

    // 1. Open Action Menu
    await screen.findAllByText('Example User');
    await user.click(screen.getAllByRole('button', { name: 'Open actions for Example User' })[0]);

    // 2. Open Manage Roles Modal
    await user.click(screen.getByRole('menuitem', { name: /Manage roles/i }));
    expect(screen.getByRole('heading', { name: 'Manage roles — Example User' })).toBeInTheDocument();

    // Check Developer role checkbox & click Save changes
    await user.click(screen.getByRole('checkbox', { name: /Developer/i }));
    await user.click(screen.getByRole('button', { name: 'Save changes' }));

    await waitFor(() => expect(api.replaceTenantMemberRoles).toHaveBeenCalledWith(
      1,
      12,
      ['VIEWER', 'DEVELOPER'],
      1,
    ));

    // 3. Disable Membership
    await user.click(screen.getAllByRole('button', { name: 'Open actions for Example User' })[0]);
    await user.click(screen.getByRole('menuitem', { name: /Disable membership/i }));
    expect(screen.getByRole('heading', { name: 'Disable tenant membership?' })).toBeInTheDocument();

    const dialog = screen.getByRole('dialog');
    const disableConfirmBtn = dialog.querySelector('button.bg-red-600') as HTMLButtonElement;
    await user.click(disableConfirmBtn);
    await waitFor(() => expect(api.deactivateTenantMember).toHaveBeenCalledWith(1, 9));

    // 4. Remove Member with Strong Confirmation Checkbox
    await user.click(screen.getAllByRole('button', { name: 'Open actions for Example User' })[0]);
    await user.click(screen.getByRole('menuitem', { name: /Remove from tenant/i }));
    expect(screen.getByRole('heading', { name: 'Remove user from tenant?' })).toBeInTheDocument();

    const removeDialog = screen.getByRole('dialog');
    const removeBtn = removeDialog.querySelector('button.bg-red-600') as HTMLButtonElement;
    expect(removeBtn).toBeDisabled();

    await user.click(screen.getByRole('checkbox', { name: /I understand this user will lose access to this tenant/i }));
    expect(removeBtn).not.toBeDisabled();

    await user.click(removeBtn);
    await waitFor(() => expect(api.removeTenantMember).toHaveBeenCalledWith(1, 9));
  });

  it('renders an explicit 403 message without initiating login', async () => {
    const { HttpError } = await import('@/lib/api');
    api.getTenantMembers.mockRejectedValue(new HttpError('Insufficient permission', 403));
    renderPage();
    expect(await screen.findByRole('alert')).toHaveTextContent('You do not have permission to perform this action.');
  });

  it('activates a disabled membership after confirmation', async () => {
    const user = userEvent.setup();
    api.getTenantMembers.mockResolvedValue([{ ...member, status: 'DISABLED' }]);
    renderPage();

    await screen.findAllByText('Example User');
    await user.click(screen.getAllByRole('button', { name: 'Open actions for Example User' })[0]);
    await user.click(screen.getByRole('menuitem', { name: /Enable membership/i }));

    expect(screen.getByRole('heading', { name: 'Enable tenant membership?' })).toBeInTheDocument();

    const enableDialog = screen.getByRole('dialog');
    const enableBtn = enableDialog.querySelector('button.bg-\\[var\\(--btn-primary\\)\\]') || enableDialog.querySelectorAll('button')[1];
    await user.click(enableBtn);

    await waitFor(() => expect(api.activateTenantMember).toHaveBeenCalledWith(1, 9));
  });

  it('distinguishes an expired 401 session from authorization denial', async () => {
    const { HttpError } = await import('@/lib/api');
    api.getTenantMembers.mockRejectedValue(new HttpError('Session expired', 401));
    renderPage();
    expect(await screen.findByRole('alert')).toHaveTextContent('Your session has expired. Please sign in again.');
  });
});

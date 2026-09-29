// @vitest-environment jsdom

import { QueryClient, QueryClientProvider } from '@tanstack/react-query';
import { act, render, screen, waitFor, within } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { axe } from 'vitest-axe';
import { Suspense } from 'react';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import { ToastProvider } from '@/hooks/useToast';

/**
 * Platform → Tenants → Manage must offer the SAME member/role UX as
 * `/settings/tenant` (RoleBadges + action menu + modals), while every call
 * targets the tenant in the URL rather than the acting user's active tenant.
 *
 * The active tenant below is deliberately 1 while the route tenant is 7 —
 * any operation that leaks the active tenant id fails these tests.
 */
const ROUTE_TENANT_ID = 7;
const ACTIVE_TENANT_ID = 1;

const refreshSession = vi.hoisted(() => vi.fn());
const auth = vi.hoisted(() => ({ allowed: true, invite: false, manageStatus: false, readUsers: false }));
const api = vi.hoisted(() => ({
  getPlatformTenant: vi.fn(),
  resendPlatformTenantActivation: vi.fn(),
  getTenantMembers: vi.fn(),
  getAssignableTenantRoles: vi.fn(),
  addTenantMember: vi.fn(),
  replaceTenantMemberRoles: vi.fn(),
  activateTenantMember: vi.fn(),
  deactivateTenantMember: vi.fn(),
  removeTenantMember: vi.fn(),
  updatePlatformTenantStatus: vi.fn(),
  searchTenantUserCandidates: vi.fn(),
  searchPlatformUsers: vi.fn(),
  getTenantAuditHistory: vi.fn(),
}));

vi.mock('next/navigation', () => ({
  useRouter: () => ({ push: vi.fn(), replace: vi.fn(), refresh: vi.fn(), prefetch: vi.fn() }),
  usePathname: () => `/settings/platform/tenants/${ROUTE_TENANT_ID}`,
}));

vi.mock('@/hooks/useAuth', () => ({
  useAuth: () => ({
    user: { tenantId: ACTIVE_TENANT_ID, userId: 999, isPlatformAdmin: true },
    activeTenantId: ACTIVE_TENANT_ID,
    activeTenant: { id: ACTIVE_TENANT_ID, name: 'Default Tenant', slug: 'default', status: 'ACTIVE' },
    tenants: [{ id: ACTIVE_TENANT_ID, name: 'Default Tenant', slug: 'default', status: 'ACTIVE' }],
    hasPermission: (permission: string) => auth.allowed && (permission === 'platform:tenant:create' || (auth.invite && permission === 'tenant:user:invite') || (auth.manageStatus && permission === 'platform:user:manage_status') || (auth.readUsers && permission === 'platform:user:read')),
    isLoading: false,
    isTenantContextLoading: false,
    refreshSession,
  }),
}));
vi.mock('@/hooks/usePermission', () => ({ usePermission: () => true }));
vi.mock('@/lib/api', async (importOriginal) => ({
  ...(await importOriginal<typeof import('@/lib/api')>()),
  ...api,
}));

import PlatformTenantDetailPage from './page';

const tenant = {
  id: ROUTE_TENANT_ID,
  name: 'Acme Security',
  slug: 'acme-security',
  external_iam_tenant_id: null,
  status: 'ACTIVE' as const,
  created_at: '2026-08-01T00:00:00Z',
  member_count: 1,
};

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

/** Stable across re-renders — `use()` must see the same promise instance. */
const routeParams = Promise.resolve({ tenantId: String(ROUTE_TENANT_ID) });

/**
 * The page reads its route params with `use(params)`, so the first render
 * suspends. Awaiting inside `act` lets React resolve the thenable and commit
 * the real tree before the assertions run.
 */
async function renderPage() {
  const client = new QueryClient({ defaultOptions: { queries: { retry: false }, mutations: { retry: false } } });
  let utils!: ReturnType<typeof render>;
  await act(async () => {
    utils = render(
      <QueryClientProvider client={client}>
        <ToastProvider>
          <Suspense fallback={<div>Loading…</div>}>
            <PlatformTenantDetailPage params={routeParams} />
          </Suspense>
        </ToastProvider>
      </QueryClientProvider>,
    );
  });
  return utils;
}

async function openActionsMenu() {
  const user = userEvent.setup();
  await renderPage();
  await screen.findAllByText('Example User');
  await user.click(screen.getAllByRole('button', { name: 'Open actions for Example User' })[0]);
  return user;
}

describe('PlatformTenantDetailPage — member management UX', () => {
  beforeEach(() => {
    vi.clearAllMocks();
    auth.allowed = true;
    api.getPlatformTenant.mockResolvedValue(tenant);
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
  });

  it('renders effective roles as badges in the latest table layout', async () => {
    await renderPage();

    await screen.findAllByText('Example User');
    // RoleBadges renders the role inside its labelled container, not a control.
    const badgeGroups = screen.getAllByLabelText('Tenant roles');
    expect(badgeGroups.length).toBeGreaterThan(0);
    expect(badgeGroups[0]).toHaveTextContent('Viewer');
    // …and each role is a RoleBadge, with its describing aria-label.
    expect(within(badgeGroups[0]).getAllByLabelText(/^Viewer role \(effective\)/).length).toBe(1);

    // Column headers match /settings/tenant.
    for (const header of ['User', 'Verification', 'Effective roles', 'Membership', 'User account', 'Actions']) {
      expect(screen.getAllByRole('columnheader', { name: header }).length).toBeGreaterThan(0);
    }
  });

  it('no longer renders the old inline role multi-select or text action buttons', async () => {
    await renderPage();
    await screen.findAllByText('Example User');

    // The per-row role editor is gone…
    expect(screen.queryByLabelText('Roles for Example User')).not.toBeInTheDocument();
    const multiSelects = document.querySelectorAll('select[multiple]');
    // …the only multi-select left is the add-member "Initial roles" control,
    // which is hidden until a user is picked.
    expect(multiSelects.length).toBe(0);

    // …and so are the old inline text buttons.
    expect(screen.queryByRole('button', { name: 'Deactivate' })).not.toBeInTheDocument();
    expect(screen.queryByRole('button', { name: 'Activate' })).not.toBeInTheDocument();
    expect(screen.queryByRole('button', { name: 'Remove' })).not.toBeInTheDocument();
  });

  it('opens ManageRolesModal from the action menu and saves against the route tenant', async () => {
    const user = await openActionsMenu();

    await user.click(screen.getByRole('menuitem', { name: /Manage roles/i }));
    expect(screen.getByRole('heading', { name: 'Manage roles — Example User' })).toBeInTheDocument();
    // Platform context is named in the modal.
    expect(screen.getByRole('dialog')).toHaveTextContent('Acme Security');

    await user.click(screen.getByRole('checkbox', { name: /Developer/i }));
    await user.click(screen.getByRole('button', { name: 'Save changes' }));

    await waitFor(() => expect(api.replaceTenantMemberRoles).toHaveBeenCalledWith(
      ROUTE_TENANT_ID,
      12,
      ['VIEWER', 'DEVELOPER'],
      1,
    ));
    expect(api.replaceTenantMemberRoles).not.toHaveBeenCalledWith(
      ACTIVE_TENANT_ID,
      expect.anything(),
      expect.anything(),
      expect.anything(),
    );
  });

  it('disables a membership through DisableMembershipDialog', async () => {
    const user = await openActionsMenu();

    await user.click(screen.getByRole('menuitem', { name: /Disable membership/i }));
    expect(screen.getByRole('heading', { name: 'Disable tenant membership?' })).toBeInTheDocument();

    const dialog = screen.getByRole('dialog');
    await user.click(within(dialog).getByRole('button', { name: 'Disable membership' }));

    await waitFor(() => expect(api.deactivateTenantMember).toHaveBeenCalledWith(ROUTE_TENANT_ID, 9));
  });

  it('enables a disabled membership through EnableMembershipDialog', async () => {
    api.getTenantMembers.mockResolvedValue([{ ...member, status: 'DISABLED' }]);
    const user = await openActionsMenu();

    await user.click(screen.getByRole('menuitem', { name: /Enable membership/i }));
    expect(screen.getByRole('heading', { name: 'Enable tenant membership?' })).toBeInTheDocument();

    const dialog = screen.getByRole('dialog');
    await user.click(within(dialog).getByRole('button', { name: 'Enable membership' }));

    await waitFor(() => expect(api.activateTenantMember).toHaveBeenCalledWith(ROUTE_TENANT_ID, 9));
  });

  it('removes a member through RemoveMemberDialog with its confirmation checkbox', async () => {
    const user = await openActionsMenu();

    await user.click(screen.getByRole('menuitem', { name: /Remove from tenant/i }));
    expect(screen.getByRole('heading', { name: 'Remove user from tenant?' })).toBeInTheDocument();

    const dialog = screen.getByRole('dialog');
    const removeBtn = within(dialog).getByRole('button', { name: 'Remove from tenant' });
    expect(removeBtn).toBeDisabled();

    await user.click(screen.getByRole('checkbox', { name: /I understand this user will lose access to this tenant/i }));
    expect(removeBtn).not.toBeDisabled();
    await user.click(removeBtn);

    await waitFor(() => expect(api.removeTenantMember).toHaveBeenCalledWith(ROUTE_TENANT_ID, 9));
  });

  it('loads members and audit history for the route tenant, never the active tenant', async () => {
    await renderPage();
    await screen.findAllByText('Example User');

    expect(api.getTenantMembers).toHaveBeenCalledWith(ROUTE_TENANT_ID);
    expect(api.getTenantMembers).not.toHaveBeenCalledWith(ACTIVE_TENANT_ID);
    await waitFor(() => expect(api.getTenantAuditHistory).toHaveBeenCalledWith(ROUTE_TENANT_ID));
    expect(api.getAssignableTenantRoles).toHaveBeenCalledWith(ROUTE_TENANT_ID);
  });

  it('adds a member to the route tenant with the chosen initial roles', async () => {
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
    const user = userEvent.setup();
    await renderPage();
    await screen.findAllByText('Example User');

    await user.type(screen.getByPlaceholderText(/Search existing SBOM users/i), 'New');
    await user.click(await screen.findByText('New User'));
    await user.selectOptions(screen.getByLabelText('Initial roles'), 'SECURITY_ANALYST');
    await user.click(screen.getByRole('button', { name: 'Add Member' }));

    await waitFor(() => expect(api.addTenantMember).toHaveBeenCalledWith(ROUTE_TENANT_ID, {
      user_id: 99,
      roles: ['SECURITY_ANALYST', 'VIEWER'],
    }));
  });
});

describe('PlatformTenantDetailPage — preserved platform context', () => {
  beforeEach(() => {
    vi.clearAllMocks();
    auth.allowed = true;
    api.getPlatformTenant.mockResolvedValue(tenant);
    api.getTenantMembers.mockResolvedValue([member]);
    api.getAssignableTenantRoles.mockResolvedValue({ roles: ['VIEWER'] });
    api.updatePlatformTenantStatus.mockResolvedValue({ tenant_id: ROUTE_TENANT_ID, status: 'DISABLED' });
    api.getTenantAuditHistory.mockResolvedValue([]);
  });

  it('keeps the breadcrumb, tenant overview and header', async () => {
    await renderPage();

    expect(await screen.findByRole('link', { name: 'Tenants' })).toHaveAttribute(
      'href',
      '/settings/platform/tenants',
    );
    const overview = screen.getByRole('heading', { name: 'Tenant Overview' }).closest('section');
    expect(overview).toHaveTextContent('acme-security');
    expect(screen.getAllByRole('link', { name: 'Manage Users' })[0]).toHaveAttribute('href', '#tenant-users');
    expect(screen.getAllByText('Acme Security').length).toBeGreaterThan(0);
  });

  it('keeps the platform tenant enable/disable control', async () => {
    const user = userEvent.setup();
    await renderPage();

    await user.click(await screen.findByRole('button', { name: 'Disable Tenant' }));
    expect(api.updatePlatformTenantStatus).not.toHaveBeenCalled();
    await user.click(within(screen.getByRole('dialog')).getByRole('button', { name: 'Disable tenant' }));

    await waitFor(() => expect(api.updatePlatformTenantStatus).toHaveBeenCalledWith(ROUTE_TENANT_ID, 'DISABLED'));
  });

  it('denies access without the platform permission and issues no member requests', async () => {
    auth.allowed = false;
    try {
      await renderPage();

      expect(await screen.findByRole('alert')).toHaveTextContent('Access denied.');
      expect(api.getTenantMembers).not.toHaveBeenCalled();
      expect(api.getPlatformTenant).not.toHaveBeenCalled();
    } finally {
      auth.allowed = true;
    }
  });
});

const pendingTenant = { ...tenant, status: 'PENDING', initial_administrator: { user_id: 42, display_name: 'Initial Admin', email: 'admin@example.test' } };

describe('Platform tenant onboarding and recovery', () => {
  beforeEach(() => {
    vi.clearAllMocks();
    auth.allowed = true; auth.invite = true; auth.manageStatus = true; auth.readUsers = true;
    api.getPlatformTenant.mockResolvedValue(pendingTenant);
    api.resendPlatformTenantActivation.mockResolvedValue({ delivery: { status: 'SENT' } });
  });
  afterEach(() => { auth.invite = false; auth.manageStatus = false; auth.readUsers = false; });

  it('shows structured pending tenant information without inventing invitation/account data', async () => {
    await renderPage();
    expect(await screen.findByRole('heading', { name: tenant.name, level: 1 })).toBeInTheDocument();
    expect(screen.getAllByText('Tenant status: Pending activation')).toHaveLength(2);
    expect(screen.getByRole('heading', { name: 'Initial Tenant Administrator' })).toBeInTheDocument();
    expect(screen.getByRole('heading', { name: 'Tenant activation' })).toBeInTheDocument();
    expect(screen.getAllByRole('link', { name: 'Manage Users' })[0]).toHaveAttribute('href', '/settings/native-users');
    expect(screen.queryByText('Invitation status: Sent')).not.toBeInTheDocument();
    expect(screen.queryByText('Account status')).not.toBeInTheDocument();
    expect(api.getTenantMembers).not.toHaveBeenCalled();
    expect(api.getAssignableTenantRoles).not.toHaveBeenCalled();
    expect(screen.queryByRole('button', { name: 'Enable Tenant' })).not.toBeInTheDocument();
  });

  it('confirms before resend, supports cancellation, and targets the route tenant/admin', async () => {
    const user = userEvent.setup();
    await renderPage();
    await user.click((await screen.findAllByRole('button', { name: 'Resend Activation' }))[0]);
    expect(screen.getByRole('dialog')).toHaveTextContent('admin@example.test');
    expect(api.resendPlatformTenantActivation).not.toHaveBeenCalled();
    await user.keyboard('{Escape}');
    expect(screen.queryByRole('dialog')).not.toBeInTheDocument();
    await user.click(screen.getAllByRole('button', { name: 'Resend Activation' })[0]);
    await user.click(within(screen.getByRole('dialog')).getByRole('button', { name: 'Resend activation' }));
    await screen.findByText('Activation email sent successfully.');
    expect(api.resendPlatformTenantActivation).toHaveBeenCalledExactlyOnceWith(ROUTE_TENANT_ID, 42);
  });

  it('disables repeated sends while the existing request is pending', async () => {
    api.resendPlatformTenantActivation.mockImplementation(() => new Promise(() => {}));
    const user = userEvent.setup();
    await renderPage();
    await user.click((await screen.findAllByRole('button', { name: 'Resend Activation' }))[0]);
    await user.click(within(screen.getByRole('dialog')).getByRole('button', { name: 'Resend activation' }));
    await waitFor(() => expect(within(screen.getByRole('dialog')).getByRole('button', { name: /Resending/ })).toBeDisabled());
    expect(api.resendPlatformTenantActivation).toHaveBeenCalledTimes(1);
  });

  it.each(['PENDING', 'FAILED'])('reports %s delivery honestly', async status => {
    api.resendPlatformTenantActivation.mockResolvedValue({ delivery: { status } });
    const user = userEvent.setup(); await renderPage();
    await user.click((await screen.findAllByRole('button', { name: 'Resend Activation' }))[0]);
    await user.click(within(screen.getByRole('dialog')).getByRole('button', { name: 'Resend activation' }));
    await screen.findByText(status === 'PENDING' ? 'Activation email queued for delivery.' : 'The activation email could not be confirmed as sent. Please try again later or contact your administrator.');
    expect(screen.queryByText('Activation email sent successfully.')).not.toBeInTheDocument();
  });

  it.each(['invite', 'manageStatus'] as const)('hides resend without %s permission', async permission => {
    auth[permission] = false; await renderPage();
    await screen.findByRole('heading', { name: tenant.name, level: 1 });
    expect(screen.queryByRole('button', { name: 'Resend Activation' })).not.toBeInTheDocument();
  });

  it('does not expose resend errors from the server', async () => {
    api.resendPlatformTenantActivation.mockRejectedValue(new Error('private token diagnostic'));
    const user = userEvent.setup(); await renderPage();
    await user.click((await screen.findAllByRole('button', { name: 'Resend Activation' }))[0]);
    await user.click(within(screen.getByRole('dialog')).getByRole('button', { name: 'Resend activation' }));
    await screen.findByText('Unable to resend activation. Please try again or check the account in user management.');
    expect(screen.queryByText(/private token/)).not.toBeInTheDocument();
  });

  it('offers retry after a safe load error', async () => {
    api.getPlatformTenant.mockRejectedValueOnce(new Error('SQL private diagnostic'));
    const user = userEvent.setup(); await renderPage();
    await screen.findByText('Unable to load tenant');
    expect(screen.queryByText(/SQL private/)).not.toBeInTheDocument();
    await user.click(screen.getByRole('button', { name: 'Try again' }));
    await screen.findByRole('heading', { name: tenant.name, level: 1 });
  });

  it('shows a not-found state for a missing tenant', async () => {
    const { ApiError } = await import('@/lib/api');
    api.getPlatformTenant.mockRejectedValue(new ApiError('private detail', 404));
    await renderPage(); await screen.findByText('Tenant not found');
    expect(screen.getByRole('link', { name: 'Back to tenants' })).toHaveAttribute('href', '/settings/platform/tenants');
    expect(screen.queryByRole('button', { name: 'Try again' })).not.toBeInTheDocument();
  });

  it('shows a skeleton instead of empty content during loading', async () => {
    api.getPlatformTenant.mockImplementation(() => new Promise(() => {}));
    await renderPage(); expect(screen.getByRole('status')).toHaveTextContent('Loading tenant details');
    expect(screen.getByRole('main')).toHaveAttribute('aria-busy', 'true');
  });

  it('handles missing administrator details without exposing nulls or resend', async () => {
    api.getPlatformTenant.mockResolvedValue({ ...pendingTenant, initial_administrator: null });
    await renderPage(); await screen.findByText('Initial administrator information is not available for this tenant.');
    expect(screen.queryByRole('button', { name: 'Resend Activation' })).not.toBeInTheDocument();
  });
});

 it('has accessible pending tenant sections', async () => {
   auth.allowed = true;
   api.getPlatformTenant.mockResolvedValue(pendingTenant);
   const { container } = await renderPage();
   await screen.findByRole('heading', { name: tenant.name, level: 1 });
   expect((await axe(container)).violations).toEqual([]);
 });

 it('renders disabled tenants without activation or membership queries', async () => {
   vi.clearAllMocks(); auth.allowed = true;
   api.getPlatformTenant.mockResolvedValue({ ...tenant, status: 'DISABLED' });
   await renderPage();
   await screen.findByText('Tenant access disabled');
   expect(screen.queryByRole('button', { name: 'Resend Activation' })).not.toBeInTheDocument();
   expect(screen.getByRole('button', { name: 'Enable Tenant' })).toBeInTheDocument();
   expect(api.getTenantMembers).not.toHaveBeenCalled();
 });

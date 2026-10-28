// @vitest-environment jsdom

import { invalidateTenantMembershipSurfaces } from '@/lib/queryInvalidation';
import { QueryClient, QueryClientProvider, useQueryClient } from '@tanstack/react-query';
import { act, render, screen, waitFor, within } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { beforeEach, describe, expect, it, vi } from 'vitest';
import { ToastProvider } from '@/hooks/useToast';

let mockPlatform = true;
let mockReadOnly = false;
let mockCanRead = true;
let mockCanInvite = true;
let mockCanUpdate = true;
let mockTenantId = 1;
let mockUserId = '00000000-0000-4000-8000-0000000003e7';
const refreshSession = vi.fn();
vi.mock('@/components/admin/NativeUserInviteForm', () => ({ default: ({ onCreated }: { onCreated: () => void }) => { const qc = useQueryClient(); return <button onClick={async () => { await invalidateTenantMembershipSurfaces(qc, 1); onCreated(); }}>Complete invitation</button>; } }));

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
    user: { tenantId: mockTenantId, externalUserId: 'subject-1', userId: mockUserId, isPlatformAdmin: mockPlatform },
    activeTenantId: mockTenantId,
    activeTenant: { id: mockTenantId, name: `Tenant ${mockTenantId}`, slug: 'default', externalIamTenantId: 'local-default', status: 'ACTIVE', role: 'TENANT_ADMIN', membershipStatus: 'ACTIVE' },
    tenants: [{ id: 1, name: 'Default Tenant', slug: 'default', externalIamTenantId: 'local-default', status: 'ACTIVE', role: 'TENANT_ADMIN', membershipStatus: 'ACTIVE' }],
    hasPermission: (permission: string) => {
      if (permission === 'tenant:user:read') return mockCanRead;
      if (mockReadOnly) return false;
      if (permission === 'tenant:user:invite') return mockCanInvite;
      if (permission === 'tenant:user:update') return mockCanUpdate;
      return true;
    },
    isLoading: false,
    isTenantContextLoading: false,
    refreshSession,
  }),
}));
vi.mock('@/hooks/usePermission', async original => ({ ...(await original<typeof import('@/hooks/usePermission')>()), usePermission: () => true }));
vi.mock('@/lib/api', async (importOriginal) => ({
  ...(await importOriginal<typeof import('@/lib/api')>()),
  ...api,
}));

import TenantUsersPage from '@/components/admin/TenantUsersAccess';

const member = {
  membership_id: 9,
  user_id: '00000000-0000-4000-8000-00000000000c',
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
  const tree = () => <QueryClientProvider client={client}><ToastProvider><TenantUsersPage /></ToastProvider></QueryClientProvider>;
  const result = render(tree());
  return { ...result, client, switchTenant: (id: number) => { mockTenantId = id; result.rerender(tree()); } };
}

describe('TenantUsersPage', () => {
  beforeEach(() => {
    mockCanRead = true;
    mockCanInvite = true;
    mockCanUpdate = true;
    mockTenantId = 1;
    mockUserId = '00000000-0000-4000-8000-0000000003e7';
    mockReadOnly = false;
  mockPlatform = true;
    vi.clearAllMocks();
    api.getTenantMembers.mockResolvedValue([member]);
    api.getAssignableTenantRoles.mockResolvedValue({ roles: ['TENANT_ADMIN', 'SECURITY_ANALYST', 'DEVELOPER', 'VIEWER'] });
    api.addTenantMember.mockResolvedValue(member);
    api.replaceTenantMemberRoles.mockResolvedValue({
      membership_id: 9,
      user_id: '00000000-0000-4000-8000-00000000000c',
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

    expect(screen.getByText('Access Information')).toBeInTheDocument();
    expect(screen.getByRole('heading', { name: 'Member Directory' })).toBeInTheDocument();
    expect(screen.queryByText(/External tenant mapping/i)).not.toBeInTheDocument();
    expect(screen.queryByText(/Technical identity details/i)).not.toBeInTheDocument();
  });
  it('invites from the tenant view and refreshes members and audit after success', async () => {
    mockPlatform = false;
    const invalidate = vi.spyOn(QueryClient.prototype, 'invalidateQueries');
    const user = userEvent.setup();
    renderPage();
    await user.click(screen.getByRole('button', { name: 'Invite New User' }));
    expect(screen.getByRole('dialog', { name: 'Invite new user' })).toBeInTheDocument();
    await user.click(screen.getByRole('button', { name: 'Complete invitation' }));
    await waitFor(() => expect(screen.queryByRole('dialog')).not.toBeInTheDocument());
    expect(invalidate).toHaveBeenCalledWith({ queryKey: ['tenant-users', 1] });
    expect(invalidate).toHaveBeenCalledWith({ queryKey: ['tenant-audit-history', 1] });
    expect(screen.getByRole('button', { name: 'Add Existing Member' })).toBeInTheDocument();
    invalidate.mockRestore();
  });
  it('does not show mutation controls with tenant read permission alone', async () => {
    mockReadOnly = true;
    renderPage();
    await screen.findAllByText('Example User');
    expect(screen.queryByRole('button', { name: 'Invite New User' })).not.toBeInTheDocument();
    expect(screen.queryByRole('button', { name: 'Add Existing Member' })).not.toBeInTheDocument();
    expect(screen.queryByRole('button', { name: 'Open actions for Example User' })).not.toBeInTheDocument();
  });

  it.each(['New User', 'new.user@hcltech.com'])('allows tenant admins to search by name/email (%s) and submit a public User UUID', async query => {
    mockPlatform = false;
    api.searchTenantUserCandidates.mockResolvedValue([{ id: '00000000-0000-4000-8000-000000000063', display_name: 'New User', email: 'new.user@hcltech.com', status: 'ACTIVE', email_verified: true, verification_required: false }]);
    const user = userEvent.setup();
    renderPage();
    await screen.findAllByText('Example User');
    expect(screen.queryByLabelText('Existing user ID')).not.toBeInTheDocument();
    expect(screen.queryByRole('spinbutton')).not.toBeInTheDocument();
    expect(screen.queryByRole('button', { name: 'Add Member' })).not.toBeInTheDocument();
    await user.click(screen.getByRole('button', { name: 'Add Existing Member' }));
    await waitFor(() => expect(screen.getByRole('dialog', { name: 'Add Existing Member' })).toHaveFocus());
    await user.type(screen.getByRole('combobox', { name: 'Search existing user' }), query);
    await user.click(await screen.findByText('New User'));
    expect(screen.getByRole('group', { name: 'Initial roles' })).toBeInTheDocument();
    await user.click(screen.getByRole('button', { name: 'Add Member' }));
    await waitFor(() => expect(api.addTenantMember).toHaveBeenCalledWith(1, { user_id: '00000000-0000-4000-8000-000000000063', roles: ['VIEWER'] }));
    expect(api.searchPlatformUsers).not.toHaveBeenCalled();
    expect(api.searchTenantUserCandidates).toHaveBeenCalledWith(1, query);
    expect(screen.queryByText(/User ID:/)).not.toBeInTheDocument();
  });

  it('adds a member with an initial tenant role', async () => {
    const user = userEvent.setup();
    api.searchTenantUserCandidates.mockResolvedValue([
      {
        id: '00000000-0000-4000-8000-000000000063',
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
    await user.click(screen.getByRole('button', { name: 'Add Existing Member' }));
    await waitFor(() => expect(screen.getByRole('dialog', { name: 'Add Existing Member' })).toHaveFocus());
    const input = screen.getByRole('combobox', { name: 'Search existing user' });
    await user.type(input, 'New');
    const foundUser = await screen.findByText('New User');
    await user.click(foundUser);
    expect(screen.queryByText('Show technical details')).not.toBeInTheDocument();
    await user.click(screen.getByRole('checkbox', { name: /Security Analyst/ }));
    await user.click(screen.getByRole('button', { name: 'Add Member' }));
    await waitFor(() => expect(api.addTenantMember).toHaveBeenCalledWith(1, {
      user_id: '00000000-0000-4000-8000-000000000063', roles: ['VIEWER', 'SECURITY_ANALYST'],
    }));
  });

  it('manages roles via Manage roles modal, deactivates via Disable membership dialog, and removes with strong confirmation', async () => {
    const invalidate = vi.spyOn(QueryClient.prototype, 'invalidateQueries');
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
      '00000000-0000-4000-8000-00000000000c',
      ['VIEWER', 'DEVELOPER'],
      1,
    ));

    // 3. Disable Membership
    expect(invalidate).toHaveBeenCalledWith({ queryKey: ['tenant-users', 1] });
    expect(invalidate).toHaveBeenCalledWith({ queryKey: ['tenant-audit-history', 1] });
    await waitFor(() => expect(api.getTenantMembers.mock.calls.length).toBeGreaterThan(1));
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
    invalidate.mockRestore();
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
  it('filters only fetched members by display name or email, announces matches and clears search', async () => {
    const user = userEvent.setup();
    api.getTenantMembers.mockResolvedValue([member, { ...member, membership_id: 10, user_id: '00000000-0000-4000-8000-00000000000d', display_name: 'Another Person', email: 'second@example.test' }]);
    renderPage();
    await screen.findAllByText('Another Person');
    const search = screen.getByRole('searchbox', { name: 'Search members' });
    await user.type(search, ' EXAMPLE USER ');
    expect(screen.getAllByText('Example User')).toHaveLength(2);
    expect(screen.queryByText('Another Person')).not.toBeInTheDocument();
    expect(screen.getByText('1 of 2 members match your search')).toBeInTheDocument();
    await user.clear(search);
    await user.type(search, 'second@');
    expect(screen.getAllByText('Another Person')).toHaveLength(2);
    expect(screen.queryByText('Example User')).not.toBeInTheDocument();
    await user.clear(search);
    await user.type(search, 'no matching person');
    expect(screen.getByText(/No matching members/)).toBeInTheDocument();
    expect(screen.getByText('0 of 2 members match your search')).toBeInTheDocument();
    await user.click(screen.getByRole('button', { name: 'Clear member search' }));
    expect(search).toHaveValue('');
    expect(search).toHaveFocus();
    expect(screen.getAllByText('Example User')).toHaveLength(2);
    expect(api.searchTenantUserCandidates).not.toHaveBeenCalled();
    expect(api.searchPlatformUsers).not.toHaveBeenCalled();
    expect(api.getTenantMembers).toHaveBeenCalledTimes(1);
  });

  it('renders an explicit loading state and the fetched empty directory', async () => {
    let resolve!: (members: unknown[]) => void;
    api.getTenantMembers.mockReturnValue(new Promise(done => { resolve = done; }));
    renderPage();
    expect(screen.getByText('Loading members…')).toBeInTheDocument();
    expect(screen.queryByText('No tenant memberships currently exist.')).not.toBeInTheDocument();
    await act(async () => resolve([]));
    expect(await screen.findByText('No tenant memberships currently exist.')).toBeInTheDocument();
    expect(screen.queryByRole('table')).not.toBeInTheDocument();
  });

  it('cancels member addition, restores toolbar focus and resets selection on reopening', async () => {
    const user = userEvent.setup();
    api.searchTenantUserCandidates.mockResolvedValue([{ id: '00000000-0000-4000-8000-000000000063', display_name: 'New User', email: 'new@example.test', status: 'ACTIVE', email_verified: true }]);
    renderPage();
    const open = screen.getByRole('button', { name: 'Add Existing Member' });
    await user.click(open);
    await waitFor(() => expect(screen.getByRole('dialog', { name: 'Add Existing Member' })).toHaveFocus());
    await user.type(screen.getByRole('combobox', { name: 'Search existing user' }), 'New');
    await user.click(await screen.findByText('New User'));
    expect(screen.getByRole('checkbox', { name: /Viewer/ })).toBeChecked();
    await user.click(screen.getByRole('button', { name: 'Cancel' }));
    expect(screen.queryByRole('dialog')).not.toBeInTheDocument();
    expect(open).toHaveFocus();
    await user.click(open);
    await waitFor(() => expect(screen.getByRole('dialog', { name: 'Add Existing Member' })).toHaveFocus());
    expect(screen.queryByText('New User')).not.toBeInTheDocument();
    expect(screen.getByRole('button', { name: 'Add Member' })).toBeDisabled();
    await user.keyboard('{Escape}');
    expect(screen.queryByRole('dialog')).not.toBeInTheDocument();
    expect(api.addTenantMember).not.toHaveBeenCalled();
  });

  it('keeps addition pending, surfaces errors, retries and invalidates tenant caches after success', async () => {
    const user = userEvent.setup();
    let reject!: (reason: Error) => void;
    api.addTenantMember.mockReturnValueOnce(new Promise((_, fail) => { reject = fail; }));
    api.searchTenantUserCandidates.mockResolvedValue([{ id: '00000000-0000-4000-8000-000000000063', display_name: 'New User', email: 'new@example.test', status: 'ACTIVE', email_verified: true }]);
    const { client } = renderPage();
    const invalidate = vi.spyOn(client, 'invalidateQueries');
    await user.click(screen.getByRole('button', { name: 'Add Existing Member' }));
    await waitFor(() => expect(screen.getByRole('dialog', { name: 'Add Existing Member' })).toHaveFocus());
    await user.type(screen.getByRole('combobox', { name: 'Search existing user' }), 'New');
    await user.click(await screen.findByText('New User'));
    await user.click(screen.getByRole('checkbox', { name: /Viewer/ }));
    expect(screen.getByRole('button', { name: 'Add Member' })).toBeDisabled();
    await user.click(screen.getByRole('checkbox', { name: /Viewer/ }));
    await user.click(screen.getByRole('button', { name: 'Add Member' }));
    expect(screen.getByRole('button', { name: 'Cancel' })).toBeDisabled();
    await user.keyboard('{Escape}');
    expect(screen.getByRole('dialog', { name: 'Add Existing Member' })).toBeInTheDocument();
    await act(async () => reject(new Error('Addition failed')));
    expect(await within(screen.getByRole('dialog')).findByRole('alert')).toHaveTextContent('Failed to add member to tenant.');
    await user.click(screen.getByRole('button', { name: 'Add Member' }));
    await waitFor(() => expect(screen.queryByRole('dialog')).not.toBeInTheDocument());
    expect(invalidate).toHaveBeenCalledWith({ queryKey: ['tenant-users', 1] });
    expect(invalidate).toHaveBeenCalledWith({ queryKey: ['tenant-audit-history', 1] });
    expect(screen.getByText(/was added to the tenant/)).toBeInTheDocument();
  });

  it('offers only returned assignable roles and never submits an unavailable default role', async () => {
    const user = userEvent.setup();
    api.getAssignableTenantRoles.mockResolvedValue({ roles: ['DEVELOPER'] });
    api.searchTenantUserCandidates.mockResolvedValue([{ id: '00000000-0000-4000-8000-000000000063', display_name: 'New User', status: 'ACTIVE' }]);
    renderPage();
    await user.click(screen.getByRole('button', { name: 'Add Existing Member' }));
    await waitFor(() => expect(screen.getByRole('dialog', { name: 'Add Existing Member' })).toHaveFocus());
    await user.type(screen.getByRole('combobox', { name: 'Search existing user' }), 'New');
    await user.click(await screen.findByText('New User'));
    expect(screen.queryByRole('checkbox', { name: /Viewer/ })).not.toBeInTheDocument();
    expect(screen.queryByRole('checkbox', { name: /Tenant Admin/ })).not.toBeInTheDocument();
    expect(screen.getByRole('button', { name: 'Add Member' })).toBeDisabled();
    await user.click(screen.getByRole('checkbox', { name: /Developer/ }));
    await user.click(screen.getByRole('button', { name: 'Add Member' }));
    await waitFor(() => expect(api.addTenantMember).toHaveBeenCalledWith(1, { user_id: '00000000-0000-4000-8000-000000000063', roles: ['DEVELOPER'] }));
  });

  it('resets search and open dialogs on tenant switching and ignores an old mutation completion', async () => {
    const user = userEvent.setup();
    let resolve!: (value: unknown) => void;
    api.addTenantMember.mockReturnValue(new Promise(done => { resolve = done; }));
    api.searchTenantUserCandidates.mockResolvedValue([{ id: '00000000-0000-4000-8000-000000000063', display_name: 'New User', status: 'ACTIVE' }]);
    api.getTenantMembers.mockImplementation((id: number) => Promise.resolve(id === 1 ? [member] : [{ ...member, membership_id: 20, display_name: 'Second Tenant Member' }]));
    const { switchTenant, client } = renderPage();
    const invalidate = vi.spyOn(client, 'invalidateQueries');
    await screen.findAllByText('Example User');
    await user.type(screen.getByRole('searchbox', { name: 'Search members' }), 'Example');
    await user.click(screen.getByRole('button', { name: 'Add Existing Member' }));
    await waitFor(() => expect(screen.getByRole('dialog', { name: 'Add Existing Member' })).toHaveFocus());
    await user.type(screen.getByRole('combobox', { name: 'Search existing user' }), 'New');
    await user.click(await screen.findByText('New User'));
    await user.click(screen.getByRole('button', { name: 'Add Member' }));
    switchTenant(2);
    expect(screen.queryByRole('dialog')).not.toBeInTheDocument();
    expect(screen.getByRole('searchbox', { name: 'Search members' })).toHaveValue('');
    await screen.findAllByText('Second Tenant Member');
    expect(screen.queryByText('Example User')).not.toBeInTheDocument();
    await act(async () => resolve(member));
    expect(invalidate).not.toHaveBeenCalled();
    expect(screen.queryByText(/was added to the tenant/)).not.toBeInTheDocument();
    expect(api.getTenantMembers).toHaveBeenCalledWith(2);
    expect(api.getAssignableTenantRoles).toHaveBeenCalledWith(2);
    await user.click(screen.getByRole('button', { name: 'Add Existing Member' }));
    await waitFor(() => expect(screen.getByRole('dialog', { name: 'Add Existing Member' })).toHaveFocus());
    await user.type(screen.getByRole('combobox', { name: 'Search existing user' }), 'Other');
    await screen.findByText('New User');
    expect(api.searchTenantUserCandidates).toHaveBeenLastCalledWith(2, 'Other');
  });

  it.each(['Disable membership', 'Remove from tenant'])('preserves the self-membership warning for %s', async action => {
    mockUserId = member.user_id;
    const user = userEvent.setup();
    renderPage();
    await screen.findAllByText('Example User');
    await user.click(screen.getAllByRole('button', { name: 'Open actions for Example User' })[0]);
    await user.click(screen.getByRole('menuitem', { name: action }));
    expect(within(screen.getByRole('dialog')).getByText(/Warning: You are/)).toBeInTheDocument();
    expect(api.deactivateTenantMember).not.toHaveBeenCalled();
    expect(api.removeTenantMember).not.toHaveBeenCalled();
  });

  it('does not fetch tenant data when member read permission is absent', () => {
    mockCanRead = false;
    renderPage();
    expect(screen.getByRole('alert')).toHaveTextContent('You do not have permission to view tenant members.');
    expect(api.getTenantMembers).not.toHaveBeenCalled();
    expect(api.getAssignableTenantRoles).not.toHaveBeenCalled();
    expect(api.getTenantAuditHistory).not.toHaveBeenCalled();
  });

  it('gates invite and member-update actions independently', async () => {
    mockCanInvite = false;
    renderPage();
    await screen.findAllByText('Example User');
    expect(screen.queryByRole('button', { name: 'Add Existing Member' })).not.toBeInTheDocument();
    expect(screen.queryByRole('button', { name: 'Invite New User' })).not.toBeInTheDocument();
    expect(screen.getAllByRole('button', { name: 'Open actions for Example User' })).toHaveLength(2);
  });

  it('blocks addition while roles cannot load and lets the user retry the role query', async () => {
    api.getAssignableTenantRoles.mockRejectedValueOnce(new Error('offline'));
    api.searchTenantUserCandidates.mockResolvedValue([{ id: '00000000-0000-4000-8000-000000000063', display_name: 'New User', status: 'ACTIVE' }]);
    const user = userEvent.setup();
    renderPage();
    await user.click(screen.getByRole('button', { name: 'Add Existing Member' }));
    await waitFor(() => expect(screen.getByRole('dialog')).toHaveFocus());
    await user.type(screen.getByRole('combobox', { name: 'Search existing user' }), 'New');
    await user.click(await screen.findByText('New User'));
    expect(await screen.findByRole('alert')).toHaveTextContent('Could not load assignable roles.');
    expect(screen.getByRole('button', { name: 'Add Member' })).toBeDisabled();
    expect(screen.queryByRole('checkbox')).not.toBeInTheDocument();
    await user.click(screen.getByRole('button', { name: 'Try again' }));
    expect(await screen.findByRole('checkbox', { name: /Viewer/ })).toBeChecked();
    expect(screen.getByRole('button', { name: 'Add Member' })).toBeEnabled();
  });

  it('refreshes the session when adding the current account', async () => {
    mockUserId = '00000000-0000-4000-8000-000000000063';
    api.searchTenantUserCandidates.mockResolvedValue([{ id: '00000000-0000-4000-8000-000000000063', display_name: 'My Account', status: 'ACTIVE' }]);
    const user = userEvent.setup();
    renderPage();
    await user.click(screen.getByRole('button', { name: 'Add Existing Member' }));
    await waitFor(() => expect(screen.getByRole('dialog')).toHaveFocus());
    await user.type(screen.getByRole('combobox', { name: 'Search existing user' }), 'My');
    await user.click(await screen.findByText('My Account'));
    await user.click(screen.getByRole('button', { name: 'Add Member' }));
    await waitFor(() => expect(refreshSession).toHaveBeenCalledWith({ authorizationChanged: true }));
  });

  it('keeps members without a name or email in the unfiltered directory', async () => {
    api.getTenantMembers.mockResolvedValue([{ ...member, display_name: null, email: null }]);
    renderPage();
    expect(await screen.findAllByText('Member')).toHaveLength(2);
    expect(screen.getByLabelText('1 total members')).toBeInTheDocument();
  });

});

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
  updateTenantMemberRole: vi.fn(),
  activateTenantMember: vi.fn(),
  deactivateTenantMember: vi.fn(),
  removeTenantMember: vi.fn(),
}));

vi.mock('@/hooks/useAuth', () => ({
  useAuth: () => ({ user: { tenantId: 1 } }),
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
  role: 'VIEWER' as const,
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
    api.updateTenantMemberRole.mockResolvedValue({ ...member, role: 'DEVELOPER' });
    api.activateTenantMember.mockResolvedValue(member);
    api.deactivateTenantMember.mockResolvedValue({ ...member, status: 'DISABLED' });
    api.removeTenantMember.mockResolvedValue(undefined);
    vi.spyOn(window, 'confirm').mockReturnValue(true);
  });

  it('lists members and never offers PLATFORM_ADMIN', async () => {
    renderPage();
    expect(await screen.findByText('Example User')).toBeInTheDocument();
    expect(screen.getByText('user@example.test')).toBeInTheDocument();
    expect(screen.queryByRole('option', { name: 'PLATFORM_ADMIN' })).not.toBeInTheDocument();
  });

  it('adds a member with an initial tenant role', async () => {
    const user = userEvent.setup();
    renderPage();
    await screen.findByText('Example User');
    await user.type(screen.getByLabelText('HCL.CS subject'), 'new-hcl-sub');
    await user.selectOptions(screen.getByLabelText('Initial role'), 'SECURITY_ANALYST');
    await user.click(screen.getByRole('button', { name: 'Add member' }));
    await waitFor(() => expect(api.addTenantMember).toHaveBeenCalledWith(1, {
      external_user_id: 'new-hcl-sub', role: 'SECURITY_ANALYST',
    }));
  });

  it('changes role, deactivates, and removes with confirmation', async () => {
    const user = userEvent.setup();
    renderPage();
    const roleSelect = await screen.findByLabelText('Role for Example User');
    await user.selectOptions(roleSelect, 'DEVELOPER');
    await user.click(screen.getByRole('button', { name: 'Change role' }));
    await waitFor(() => expect(api.updateTenantMemberRole).toHaveBeenCalledWith(1, 9, 'DEVELOPER'));
    await user.click(screen.getByRole('button', { name: 'Deactivate' }));
    await user.click(screen.getByRole('dialog').querySelector('button.bg-red-600')!);
    await waitFor(() => expect(api.deactivateTenantMember).toHaveBeenCalledWith(1, 9));
    await user.click(screen.getByRole('button', { name: 'Remove' }));
    await user.click(screen.getByRole('button', { name: 'Remove member' }));
    await waitFor(() => expect(api.removeTenantMember).toHaveBeenCalledWith(1, 9));
    expect(window.confirm).not.toHaveBeenCalled();
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
    await user.click(await screen.findByRole('button', { name: 'Activate' }));
    await waitFor(() => expect(api.activateTenantMember).toHaveBeenCalledWith(1, 9));
    expect(window.confirm).not.toHaveBeenCalled();
  });

  it('distinguishes an expired 401 session from authorization denial', async () => {
    const { HttpError } = await import('@/lib/api');
    api.getTenantMembers.mockRejectedValue(new HttpError('Session expired', 401));
    renderPage();
    expect(await screen.findByRole('alert')).toHaveTextContent('Your session has expired. Please sign in again.');
  });
});

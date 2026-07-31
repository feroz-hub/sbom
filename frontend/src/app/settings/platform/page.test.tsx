// @vitest-environment jsdom

import { QueryClient, QueryClientProvider } from '@tanstack/react-query';
import { render, screen, waitFor } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { beforeEach, describe, expect, it, vi } from 'vitest';
import { ToastProvider } from '@/hooks/useToast';

const api = vi.hoisted(() => ({
  getPlatformAdministrators: vi.fn(),
  searchPlatformUsers: vi.fn(),
  grantPlatformAdministrator: vi.fn(),
  revokePlatformAdministrator: vi.fn(),
  getTenantAuditHistory: vi.fn(),
}));

vi.mock('@/hooks/useAuth', () => ({
  useAuth: () => ({
    user: { tenantId: 1, externalUserId: 'subject-1' },
    tenants: [{ id: 1, name: 'Default Tenant', slug: 'default' }],
    hasPermission: () => true,
    isLoading: false,
  }),
}));
vi.mock('@/hooks/usePermission', () => ({ usePermission: () => true }));
vi.mock('@/lib/api', async (importOriginal) => ({
  ...(await importOriginal<typeof import('@/lib/api')>()),
  ...api,
}));

import PlatformAdminsPage from './page';

const adminItem = {
  grant_id: 1,
  assignment_id: 1,
  user_id: 1,
  email: 'hclcs.admin@localhost.test',
  display_name: 'HCL.CS Administrator',
  role: 'PLATFORM_ADMIN' as const,
  roles: ['PLATFORM_ADMIN'],
  grant_status: 'ACTIVE',
  user_status: 'ACTIVE',
  email_verified: true,
  verification_required: false,
  is_effective: true,
  effective: true,
  created_at: '2026-06-30T10:00:00Z',
};

function renderPage() {
  const client = new QueryClient({ defaultOptions: { queries: { retry: false }, mutations: { retry: false } } });
  return render(
    <QueryClientProvider client={client}>
      <ToastProvider>
        <PlatformAdminsPage />
      </ToastProvider>
    </QueryClientProvider>,
  );
}

describe('PlatformAdminsPage', () => {
  beforeEach(() => {
    vi.clearAllMocks();
    api.getPlatformAdministrators.mockResolvedValue([adminItem]);
    api.searchPlatformUsers.mockResolvedValue([
      {
        id: 3,
        email: 'candidate@localhost.test',
        display_name: 'Candidate Admin',
        status: 'ACTIVE',
        roles: [],
        email_verified: true,
        verification_required: false,
      },
    ]);
    api.grantPlatformAdministrator.mockResolvedValue(adminItem);
    api.revokePlatformAdministrator.mockResolvedValue({ ...adminItem, grant_status: 'REVOKED' });
    api.getTenantAuditHistory.mockResolvedValue([]);
    vi.spyOn(window, 'confirm').mockReturnValue(true);
  });

  it('lists active platform administrators and revokes after confirmation', async () => {
    const user = userEvent.setup();
    renderPage();
    expect(await screen.findByText('HCL.CS Administrator')).toBeInTheDocument();
    expect(screen.getByText('hclcs.admin@localhost.test')).toBeInTheDocument();

    await user.click(screen.getByRole('button', { name: 'Revoke' }));
    await user.click(screen.getByRole('button', { name: 'Revoke authority' }));
    await waitFor(() => expect(api.revokePlatformAdministrator).toHaveBeenCalledWith(1));
  });

  it('searches existing users and grants platform administrator role', async () => {
    const user = userEvent.setup();
    renderPage();
    await screen.findByText('HCL.CS Administrator');

    await user.type(
      screen.getByPlaceholderText('Search existing SBOM users by email or name…'),
      'Candidate',
    );
    await user.click(await screen.findByRole('button', { name: /Candidate Admin/ }));
    await user.click(screen.getByRole('button', { name: 'Grant Platform Administrator' }));
    await waitFor(() => expect(api.grantPlatformAdministrator).toHaveBeenCalledWith(3));
  });

  it('keeps user, verification, grant, and effective states separate', async () => {
    renderPage();
    expect(await screen.findByText('HCL.CS Administrator')).toBeInTheDocument();
    expect(screen.getByText(/Verified/)).toBeInTheDocument();
    expect(screen.getAllByText(/Platform Admin/)[0]).toBeInTheDocument();
    expect(screen.getAllByText('Effective').length).toBeGreaterThanOrEqual(1);
    expect(screen.getAllByText('ACTIVE').length).toBeGreaterThanOrEqual(1);
  });
});

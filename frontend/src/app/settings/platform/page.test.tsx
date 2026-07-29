// @vitest-environment jsdom

import { QueryClient, QueryClientProvider } from '@tanstack/react-query';
import { render, screen, waitFor } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { beforeEach, describe, expect, it, vi } from 'vitest';

import { ToastProvider } from '@/hooks/useToast';

const api = vi.hoisted(() => ({
  getPlatformAdministrators: vi.fn(),
  grantPlatformAdministrator: vi.fn(),
  revokePlatformAdministrator: vi.fn(),
  searchPlatformUsers: vi.fn(),
  searchTenantUserCandidates: vi.fn(),
}));

vi.mock('@/hooks/useAuth', () => ({
  useAuth: () => ({
    hasPermission: () => true,
    isLoading: false,
  }),
}));
vi.mock('@/lib/api', async (importOriginal) => ({
  ...(await importOriginal<typeof import('@/lib/api')>()),
  ...api,
}));

import PlatformAdministratorsPage from './page';

function renderPage() {
  const client = new QueryClient({
    defaultOptions: { queries: { retry: false }, mutations: { retry: false } },
  });
  return render(
    <QueryClientProvider client={client}>
      <ToastProvider>
        <PlatformAdministratorsPage />
      </ToastProvider>
    </QueryClientProvider>,
  );
}

describe('PlatformAdministratorsPage', () => {
  beforeEach(() => {
    vi.clearAllMocks();
    api.getPlatformAdministrators.mockResolvedValue([{
      grant_id: 1,
      user_id: 2,
      email: 'hclcs.admin@localhost.test',
      display_name: 'HCL.CS Administrator',
      local_status: 'ACTIVE',
      email_verified: true,
      verification_required: false,
      role: 'PLATFORM_ADMIN',
      grant_status: 'ACTIVE',
      is_effective: true,
      created_at: '2026-07-01T00:00:00Z',
    }]);
    api.searchPlatformUsers.mockResolvedValue([{
      id: 3,
      email: 'candidate@example.test',
      display_name: 'Candidate Admin',
      username: 'candidate',
      status: 'ACTIVE',
      email_verified: true,
      verification_required: false,
    }]);
    api.grantPlatformAdministrator.mockResolvedValue({
      grant_id: 2,
      user_id: 3,
      email: 'candidate@example.test',
      display_name: 'Candidate Admin',
      local_status: 'ACTIVE',
      email_verified: true,
      verification_required: false,
      role: 'PLATFORM_ADMIN',
      grant_status: 'ACTIVE',
      is_effective: true,
      created_at: '2026-07-29T00:00:00Z',
    });
  });

  it('grants platform authority with the selected numeric local user ID', async () => {
    const user = userEvent.setup();
    renderPage();
    expect(await screen.findByText('HCL.CS Administrator')).toBeInTheDocument();
    await user.type(
      screen.getByPlaceholderText(/Search existing SBOM users/),
      'Candidate',
    );
    await user.click(await screen.findByRole('button', { name: /Candidate Admin/ }));
    await user.click(screen.getByRole('button', { name: 'Grant Platform Administrator' }));
    await waitFor(() => expect(api.grantPlatformAdministrator).toHaveBeenCalledWith(3));
  });

  it('keeps user, verification, grant, and effective states separate', async () => {
    renderPage();
    expect(await screen.findByText('HCL.CS Administrator')).toBeInTheDocument();
    expect(screen.getByText('Verified')).toBeInTheDocument();
    expect(screen.getByText('PLATFORM_ADMIN')).toBeInTheDocument();
    expect(screen.getAllByText('Effective').length).toBeGreaterThanOrEqual(2);
    expect(screen.getAllByText('ACTIVE').length).toBeGreaterThanOrEqual(1);
  });
});

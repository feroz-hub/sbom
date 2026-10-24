// @vitest-environment jsdom
import { Suspense } from 'react';
import { QueryClient, QueryClientProvider } from '@tanstack/react-query';
import { act, render, screen, waitFor, within } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { beforeEach, expect, it, vi } from 'vitest';
import Page from './page';

const state = vi.hoisted(() => ({ allowed: true, governance: false, platform: true, get: vi.fn(), directory: vi.fn(), recover: vi.fn(), status: vi.fn(), candidate: { id: 8, email: 'admin@example.test', display_name: 'New Admin' } }));
vi.mock('@/hooks/useAuth', () => ({ useAuth: () => ({ user: { userId: '00000000-0000-4000-8000-000000000001', permissions: [] }, isPlatformContext: state.platform, isLoading: false, hasPermission: (permission: string) => state.allowed && (permission !== 'platform:tenant_admin:manage' || state.governance) }) }));
vi.mock('@/hooks/useNotifications', () => ({ useNotifications: () => ({ showSuccess: vi.fn(), showError: vi.fn() }) }));
vi.mock('@/lib/api', async original => ({ ...await original<typeof import('@/lib/api')>(), getPlatformTenant: (...args: unknown[]) => state.get(...args), getPlatformTenantAdministrators: (...args: unknown[]) => state.directory(...args), recoverPlatformTenantAdmin: (...args: unknown[]) => state.recover(...args), updatePlatformTenantStatus: (...args: unknown[]) => state.status(...args) }));
vi.mock('@/components/admin/UserSearchCombobox', () => ({ UserSearchCombobox: ({ onSelect }: { onSelect: (user: typeof state.candidate) => void }) => <button onClick={() => onSelect(state.candidate)}>Select New Admin</button> }));

beforeEach(() => {
  vi.clearAllMocks(); state.allowed = true; state.governance = false; state.platform = true;
  state.get.mockResolvedValue({ id: "00000000-0000-4000-8000-000000000007", name: 'Olympus', status: 'ACTIVE', member_count: 10, current_administrators: [{ user_id: '00000000-0000-4000-8000-000000000002', display_name: 'Current Admin', email: 'current@example.test' }] });
  state.recover.mockResolvedValue({}); state.status.mockResolvedValue({});
  state.directory.mockResolvedValue({ tenant_id: '00000000-0000-4000-8000-000000000007', administrators: [{
    tenant_id: '00000000-0000-4000-8000-000000000007', membership_id: '00000000-0000-4000-8000-000000000008', user_id: '00000000-0000-4000-8000-000000000002',
    display_name: 'Current Admin', email: 'current@example.test', status: 'ACTIVE', account_status: 'ACTIVE', is_effective: true,
    roles: ['TENANT_ADMIN'], primary_role: 'TENANT_ADMIN', role_assignment_version: 3,
  }], replacement_roles: [{ code: 'VIEWER', name: 'Viewer', scope: 'TENANT' }] });
});
async function renderPage() {
  const params = Promise.resolve({ tenantId: "00000000-0000-4000-8000-000000000007" });
  await act(async () => { render(<QueryClientProvider client={new QueryClient({ defaultOptions: { queries: { retry: false } } })}><Suspense fallback={<p>Loading</p>}><Page params={params} /></Suspense></QueryClientProvider>); });
}
it('shows summary and governance, not a generic tenant member editor', async () => {
  await renderPage();
  expect(await screen.findByRole('heading', { name: 'Olympus', level: 1 })).toBeInTheDocument();
  expect(screen.getByText('10 memberships · 1 active Tenant Administrators')).toBeInTheDocument();
  expect(screen.getByText('Current Admin — current@example.test')).toBeInTheDocument();
  expect(screen.queryByText('Tenant Members')).not.toBeInTheDocument();
  expect(screen.queryByText('Generic member editor')).not.toBeInTheDocument();
  expect(screen.queryByText('Add existing member')).not.toBeInTheDocument();
  expect(state.get).toHaveBeenCalledWith("00000000-0000-4000-8000-000000000007");
});
it('renders one shared breadcrumb with ancestor links and a non-linked current tenant', async () => {
  state.get.mockResolvedValue({ id: "00000000-0000-4000-8000-000000000007", name: 'Wellysis', slug: 'wellysis', status: 'ACTIVE', member_count: 0, current_administrators: [] });
  await renderPage();
  await screen.findByRole('heading', { name: 'Wellysis', level: 1 });
  const trails = screen.getAllByRole('navigation', { name: 'Breadcrumb' });
  expect(trails).toHaveLength(1);
  const trail = within(trails[0]);
  expect(trail.getByRole('link', { name: 'Platform' })).toHaveAttribute('href', '/platform');
  expect(trail.getByRole('link', { name: 'Tenants' })).toHaveAttribute('href', '/settings/platform/tenants');
  expect(trail.getByText('Wellysis')).toHaveAttribute('aria-current', 'page');
  expect(trail.queryByRole('link', { name: 'Wellysis' })).not.toBeInTheDocument();
  expect(trail.getAllByRole('link')).toHaveLength(2);
});
it('uses a dedicated administrator recovery API with fixed role semantics', async () => {
  await renderPage(); const user = userEvent.setup();
  const save = await screen.findByRole('button', { name: 'Assign Tenant Administrator' });
  expect(save).toBeDisabled();
  await user.click(screen.getByRole('button', { name: 'Select New Admin' }));
  await user.click(save);
  await waitFor(() => expect(state.recover).toHaveBeenCalledWith("00000000-0000-4000-8000-000000000007", 8));
});
it('requires actual platform-context permission', async () => {
  state.allowed = false; await renderPage();
  expect(await screen.findByRole('alert')).toHaveTextContent('Platform tenant read permission is required');
  expect(state.get).not.toHaveBeenCalled();
});
it('renders the authorized governance section once and loads the membership directory', async () => {
  state.governance = true; await renderPage();
  await screen.findByRole('heading', { name: 'Current Admin' });
  expect(screen.getAllByRole('heading', { name: 'Tenant Administrators' })).toHaveLength(1);
  expect(screen.getByRole('button', { name: 'Revoke Admin Role' })).toBeInTheDocument();
  expect(screen.getByRole('button', { name: 'Deactivate Membership' })).toBeInTheDocument();
  expect(screen.getByRole('button', { name: 'Remove From Tenant' })).toBeInTheDocument();
  expect(state.directory).toHaveBeenCalledWith('00000000-0000-4000-8000-000000000007', expect.any(AbortSignal));
  expect(screen.queryByText('Current Tenant Administrators')).not.toBeInTheDocument();
});
it('blocks direct navigation from tenant context despite stale platform permissions', async () => {
  state.platform = false; state.governance = true; await renderPage();
  expect(await screen.findByRole('alert')).toHaveTextContent('Platform tenant read permission is required');
  expect(state.get).not.toHaveBeenCalled(); expect(state.directory).not.toHaveBeenCalled();
  expect(screen.queryByRole('button', { name: 'Revoke Admin Role' })).not.toBeInTheDocument();
});

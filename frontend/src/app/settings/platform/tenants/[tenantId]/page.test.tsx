// @vitest-environment jsdom
import { Suspense } from 'react';
import { QueryClient, QueryClientProvider } from '@tanstack/react-query';
import { act, render, screen, waitFor, within } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { beforeEach, expect, it, vi } from 'vitest';
import Page from './page';

const state = vi.hoisted(() => ({ allowed: true, get: vi.fn(), recover: vi.fn(), status: vi.fn(), candidate: { id: 8, email: 'admin@example.test', display_name: 'New Admin' } }));
vi.mock('@/hooks/useAuth', () => ({ useAuth: () => ({ user: { userId: 1, permissions: [] }, isLoading: false, hasPermission: () => state.allowed }) }));
vi.mock('@/hooks/useNotifications', () => ({ useNotifications: () => ({ showSuccess: vi.fn(), showError: vi.fn() }) }));
vi.mock('@/lib/api', () => ({ getPlatformTenant: (...args: unknown[]) => state.get(...args), recoverPlatformTenantAdmin: (...args: unknown[]) => state.recover(...args), updatePlatformTenantStatus: (...args: unknown[]) => state.status(...args) }));
vi.mock('@/components/admin/UserSearchCombobox', () => ({ UserSearchCombobox: ({ onSelect }: { onSelect: (user: typeof state.candidate) => void }) => <button onClick={() => onSelect(state.candidate)}>Select New Admin</button> }));

beforeEach(() => {
  vi.clearAllMocks(); state.allowed = true;
  state.get.mockResolvedValue({ id: 7, name: 'Olympus', status: 'ACTIVE', member_count: 10, current_administrators: [{ user_id: 2, display_name: 'Current Admin', email: 'current@example.test' }] });
  state.recover.mockResolvedValue({}); state.status.mockResolvedValue({});
});
async function renderPage() {
  const params = Promise.resolve({ tenantId: '7' });
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
  expect(state.get).toHaveBeenCalledWith(7);
});
it('renders one shared breadcrumb with ancestor links and a non-linked current tenant', async () => {
  state.get.mockResolvedValue({ id: 7, name: 'Wellysis', slug: 'wellysis', status: 'ACTIVE', member_count: 0, current_administrators: [] });
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
  await waitFor(() => expect(state.recover).toHaveBeenCalledWith(7, 8));
});
it('requires actual platform-context permission', async () => {
  state.allowed = false; await renderPage();
  expect(await screen.findByRole('alert')).toHaveTextContent('Platform tenant read permission is required');
  expect(state.get).not.toHaveBeenCalled();
});

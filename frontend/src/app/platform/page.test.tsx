// @vitest-environment jsdom
import { QueryClient, QueryClientProvider } from '@tanstack/react-query';
import { fireEvent, render, screen, within } from '@testing-library/react';
import { beforeEach, expect, it, vi } from 'vitest';
import PlatformDashboard from './page';

const state = vi.hoisted(() => ({
  admin: true,
  permissions: new Set<string>(),
  summary: vi.fn(),
  tenants: vi.fn(),
}));
vi.mock('@/hooks/useAuth', () => ({
  useAuth: () => ({
    user: { isPlatformAdmin: state.admin },
    isLoading: false,
    activeTenantId: null,
    hasPermission: (p: string) => state.permissions.has(p),
  }),
}));
vi.mock('@/lib/api', () => ({
  getPlatformSummary: () => state.summary(),
  listPlatformTenants: (...args: unknown[]) => state.tenants(...args),
}));
vi.mock('@/components/layout/TopBar', () => ({
  TopBar: ({ title, action }: { title: string; action?: React.ReactNode }) => (
    <header>
      <h1>{title}</h1>
      {action}
    </header>
  ),
}));
beforeEach(() => {
  vi.clearAllMocks();
  state.admin = true;
  state.permissions = new Set([
    'platform:tenant:read',
    'platform:tenant:create',
    'platform:administrator:read',
    'platform:health:read',
    'platform:ai:read',
    'platform:lifecycle-provider:read',
  ]);
  state.summary.mockResolvedValue({
    total_tenants: 2,
    active_tenants: 2,
    disabled_tenants: 0,
    pending_tenants: 0,
    total_memberships: 4,
    tenants_without_admin: 0,
    platform_admins: 1,
  });
  state.tenants.mockResolvedValue([
    {
      id: 1,
      name: 'Olympus',
      slug: 'olympus',
      status: 'ACTIVE',
      member_count: 4,
      current_administrators: [{ user_id: 2 }],
      created_at: '2026-09-12T00:00:00Z',
    },
  ]);
});
function show() {
  render(
    <QueryClientProvider
      client={
        new QueryClient({ defaultOptions: { queries: { retry: false } } })
      }
    >
      <PlatformDashboard />
    </QueryClientProvider>,
  );
}
it('opens for a pure Platform Admin without tenant permission or active tenant', async () => {
  show();
  expect(
    screen.getByRole('heading', { name: 'Platform Dashboard' }),
  ).toBeInTheDocument();
  expect(await screen.findByLabelText('Total Tenants: 2')).toBeInTheDocument();
});
it.each([false, true])(
  'requires both platform identity and permission (admin=%s)',
  (admin) => {
    state.admin = admin;
    state.permissions = new Set(
      admin ? ['tenant:user:read'] : ['platform:tenant:read'],
    );
    show();
    expect(screen.getByRole('alert')).toHaveTextContent(
      'Platform Administrator access is required.',
    );
    expect(state.summary).not.toHaveBeenCalled();
    expect(state.tenants).not.toHaveBeenCalled();
  },
);
it('renders meaningful zero states and all seven metrics', async () => {
  show();
  expect(
    await screen.findByText('All tenants have active administrators'),
  ).toBeInTheDocument();
  expect(screen.getByText('No disabled tenants')).toBeInTheDocument();
  expect(screen.getByText('No pending tenant setup')).toBeInTheDocument();
  expect(
    within(
      screen.getByRole('region', { name: 'Platform metrics' }),
    ).getAllByRole('article'),
  ).toHaveLength(7);
});
it('links creation to the existing form and tenant overview to governance details', async () => {
  show();
  expect(
    screen.getAllByRole('link', { name: 'Create Tenant' })[0],
  ).toHaveAttribute('href', '/settings/platform/tenants#create-tenant');
  expect(
    await screen.findByRole('link', { name: 'View Olympus' }),
  ).toHaveAttribute('href', '/settings/platform/tenants/1');
  expect(
    screen.getByRole('link', { name: 'View all tenants' }),
  ).toHaveAttribute('href', '/settings/platform/tenants');
  expect(state.tenants).toHaveBeenCalledWith('', 1, 5);
});
it('renders permission-aware governance links, not plain footer links', () => {
  show();
  for (const [name, href] of [
    ['AI Configuration', '/platform/configuration/ai'],
    ['Lifecycle Providers', '/platform/configuration/lifecycle'],
    ['Platform Administrators', '/settings/platform'],
    ['Platform Health', '/settings/iam'],
  ]) {
    expect(
      screen.getByRole('link', { name: new RegExp(name) }),
    ).toHaveAttribute('href', href);
  }
});
it('does not offer creation or configuration without their permissions', () => {
  state.permissions = new Set(['platform:tenant:read']);
  show();
  expect(
    screen.queryByRole('link', { name: 'Create Tenant' }),
  ).not.toBeInTheDocument();
  expect(
    screen.queryByRole('link', { name: /AI Configuration/ }),
  ).not.toBeInTheDocument();
});
it('retains metrics when tenant overview fails and offers a separate retry', async () => {
  state.tenants.mockRejectedValue(new Error('failed'));
  show();
  expect(
    await screen.findByRole('button', { name: 'Retry tenants' }),
  ).toBeInTheDocument();
  expect(screen.getByLabelText('Total Tenants: 2')).toBeInTheDocument();
  expect(screen.queryByText('No tenants yet')).not.toBeInTheDocument();
});
it('refreshes both existing data queries', async () => {
  show();
  await screen.findByRole('button', { name: 'Refresh' });
  fireEvent.click(screen.getByRole('button', { name: 'Refresh' }));
  expect(state.summary).toHaveBeenCalledTimes(2);
  expect(state.tenants).toHaveBeenCalledTimes(2);
});
it('uses responsive containment, semantic table and dark-safe tokens', async () => {
  show();
  await screen.findByRole('table');
  expect(screen.getByRole('region', { name: 'Platform metrics' })).toHaveClass(
    'grid-cols-1',
    'md:grid-cols-2',
    'xl:grid-cols-4',
  );
  expect(
    screen.getByRole('region', { name: 'Tenant overview table' }),
  ).toHaveClass('overflow-x-auto');
  expect(screen.getByRole('main')).toHaveClass('min-w-0');
  expect(
    screen.getByLabelText('Total Tenants: 2').closest('article'),
  ).toHaveClass('bg-surface', 'border-border');
});

// @vitest-environment jsdom
import { QueryClient, QueryClientProvider } from '@tanstack/react-query';
import { fireEvent, render, screen, within } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
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
it.each([
  ['Total Tenants', 2, 'All tenants across the platform, including active, disabled, and pending tenants.'],
  ['Active Tenants', 2, 'Tenants whose status is Active.'],
  ['Disabled Tenants', 0, 'Tenants whose status is Disabled.'],
  ['Pending Setup', 0, 'Tenants whose status is Pending, awaiting setup completion.'],
  ['Total Memberships', 4, 'All tenant memberships, including active, pending, and disabled memberships. A user belonging to multiple tenants is counted once per tenant.'],
  ['Tenants Without Active Admin', 0, 'Tenants of any status with no active, verified user who has an active membership and an active assignment to the active Tenant Administrator role.'],
  ['Platform Administrators', 1, 'Active, verified users with an active Platform Administrator grant. Disabled grants and inactive or unverified users are excluded.'],
])('provides consistent hover, keyboard and tap help for %s', async (title, value, description) => {
  const user = userEvent.setup();
  show();
  const metric = await screen.findByLabelText(`${title}: ${value}`);
  const card = metric.closest('article')!;
  expect(within(card).getByRole('heading', { name: title })).toBeInTheDocument();
  const info = within(card).getByRole('button', { name: `About ${title}` });
  expect(info).toHaveClass('h-8', 'w-8', 'shrink-0');
  expect(info.querySelector('svg')).toHaveClass('h-4', 'w-4');
  expect(screen.queryByRole('tooltip')).not.toBeInTheDocument();

  await user.hover(info);
  const help = screen.getByRole('tooltip');
  expect(help).toHaveTextContent(description);
  if (title === 'Tenants Without Active Admin' || title === 'Platform Administrators') {
    expect(help).toHaveTextContent('Verification must be complete: a verified email or Microsoft Entra identity, with no verification still required.');
  }
  expect(help.parentElement).toBe(document.body);
  expect(help).toHaveClass('fixed', 'bg-surface', 'border-border', 'text-foreground');
  expect(info).toHaveAccessibleDescription(help.textContent!);
  await user.keyboard('{Escape}');
  expect(screen.queryByRole('tooltip')).not.toBeInTheDocument();

  fireEvent.focus(info);
  expect(screen.getByRole('tooltip')).toHaveTextContent(description);
  fireEvent.blur(info);
  expect(screen.queryByRole('tooltip')).not.toBeInTheDocument();

  await user.pointer({ keys: '[TouchA]', target: info });
  expect(screen.getByRole('tooltip')).toHaveTextContent(description);
  await user.pointer({ keys: '[TouchA]', target: info });
  expect(screen.queryByRole('tooltip')).not.toBeInTheDocument();
  await user.pointer({ keys: '[TouchA]', target: info });
  expect(screen.getByRole('tooltip')).toBeInTheDocument();
  await user.pointer({ keys: '[TouchA]', target: document.body });
  expect(screen.queryByRole('tooltip')).not.toBeInTheDocument();
});
it('links creation to the existing form and tenant overview to governance details', async () => {
  show();
  expect(
    screen.getAllByRole('link', { name: 'Create Tenant' })[0],
  ).toHaveAttribute('href', '/settings/platform/tenants#create-tenant');
  expect(
    await screen.findByRole('link', { name: 'Open Olympus tenant' }),
  ).toHaveAttribute('href', '/settings/platform/tenants/1');
  const tenantLink = screen.getByRole('link', { name: 'Open Olympus tenant' });
  expect(tenantLink).toHaveAttribute('title', 'Open tenant details');
  expect(tenantLink).not.toHaveTextContent('View');
  tenantLink.focus();
  expect(tenantLink).toHaveFocus();
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

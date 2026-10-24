// @vitest-environment jsdom
import { QueryClient, QueryClientProvider } from '@tanstack/react-query';
import { render, screen, fireEvent } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { beforeEach, expect, it, vi } from 'vitest';
import { UserMenu } from './UserMenu';
import { AppShell } from './AppShell';
import { TopBar } from './TopBar';
import { ThemeProvider } from '@/components/theme/ThemeProvider';
import type { AuthUser, TenantInfo } from '@/hooks/useAuth';

const state = vi.hoisted(() => ({
  user: null as AuthUser | null,
  tenants: [] as TenantInfo[],
  activeTenantId: null as string | null,
  logout: vi.fn(),
  selectTenant: vi.fn(),
  clearTenantSelection: vi.fn(),
  replace: vi.fn(),
  path: '/projects',
}));
vi.mock('next/navigation', () => ({
  usePathname: () => state.path,
  useSearchParams: () => new URLSearchParams(),
  useRouter: () => ({ replace: state.replace }),
}));
vi.mock('@/hooks/useAuth', () => ({
  useAuth: () => ({
    ...state,
    config: { enabled: true },
    bootstrapState: 'ready',
    hasPermission: () => false,
  }),
}));
vi.mock('@/lib/api', () => ({
  getHealth: vi.fn().mockResolvedValue({ status: 'ok' }),
}));
vi.mock('@/components/ai-fixes/GlobalAiBatchProgress', () => ({
  GlobalAiBatchBanner: () => null,
}));
const tenant = (id: number, name: string): TenantInfo => ({
  id,
  name,
  slug: name.toLowerCase(),
  status: 'ACTIVE',
  membershipStatus: 'ACTIVE',
  roles: ['TENANT_ADMIN'],
  role: 'TENANT_ADMIN',
  externalIamTenantId: null,
  platformContextAvailable: false,
});
beforeEach(() => {
  vi.clearAllMocks();
  state.path = '/projects';
  state.tenants = [tenant(1, 'Olympus')];
  state.activeTenantId = '1';
  state.user = {
    userId: 1,
    externalUserId: 'SECRET-SUBJECT',
    email: 'feroze@example.test',
    displayName: 'Feroze Basha',
    roles: ['TENANT_ADMIN'],
    permissions: [],
    isPlatformAdmin: false,
    tenantId: 1,
    externalTenantId: null,
  };
  state.selectTenant.mockResolvedValue(undefined);
});
function show(shell = false, withTopBar = true) {
  render(
    <QueryClientProvider
      client={
        new QueryClient({ defaultOptions: { queries: { retry: false } } })
      }
    >
      <ThemeProvider>
        {shell ? (
          <AppShell>
            {withTopBar && <TopBar title="Projects" />}
            <div>Project content</div>
          </AppShell>
        ) : (
          <UserMenu />
        )}
      </ThemeProvider>
    </QueryClientProvider>,
  );
}
async function open() {
  const user = userEvent.setup();
  await user.click(
    screen.getByRole('button', { name: 'Account menu for Feroze Basha' }),
  );
  return user;
}
it('provides sign-out even on a protected page without its own header', async () => {
  show(true, false); await open();
  expect(screen.getByRole('menuitem', { name: 'Sign Out' })).toBeInTheDocument();
});
it('does not render the authenticated account menu on public routes', () => {
  state.path = '/logged-out'; show(true, false);
  expect(screen.queryByRole('button', { name: /Account menu/ })).not.toBeInTheDocument();
});
it('uses a safe fallback rather than displaying an external subject', async () => {
  state.user!.displayName = null; state.user!.email = null;
  show(); const user = userEvent.setup();
  await user.click(screen.getByRole('button', { name: 'Account menu for User' }));
  expect(screen.queryByText('SECRET-SUBJECT')).not.toBeInTheDocument();
});
it('retains readable theme-token surfaces in dark mode', async () => {
  document.documentElement.classList.add('dark'); show(); await open();
  expect(screen.getByRole('menu')).toHaveClass('bg-surface', 'border-border');
  expect(screen.getByRole('menuitem', { name: 'Sign Out' })).toHaveClass('dark:text-red-300');
  document.documentElement.classList.remove('dark');
});
it.each([
  '/projects',
  '/sboms',
  '/analysis',
  '/vex-investigation',
  '/kev',
  '/settings/users',
  '/platform',
  '/platform/configuration/ai',
])('mounts exactly one global menu on %s', async (path) => {
  state.path = path;
  show(true);
  expect(
    screen.getByRole('banner', { name: 'Authenticated application header' }),
  ).toBeInTheDocument();
  expect(
    screen.getAllByRole('button', { name: 'Account menu for Feroze Basha' }),
  ).toHaveLength(1);
  await open();
  expect(
    screen.getByRole('menuitem', { name: 'Sign Out' }),
  ).toBeInTheDocument();
});
it('shows current tenant and live tenant role, never subject or unavailable profile', async () => {
  show();
  await open();
  expect(screen.getByText('Olympus')).toBeInTheDocument();
  expect(screen.getByText('Tenant Admin')).toBeInTheDocument();
  expect(screen.queryByText('SECRET-SUBJECT')).not.toBeInTheDocument();
  expect(
    screen.queryByRole('menuitem', { name: 'My Profile' }),
  ).not.toBeInTheDocument();
});
it('shows platform context without arbitrary workspace choices', async () => {
  state.user!.isPlatformAdmin = true;
  state.user!.tenantId = null;
  state.user!.roles = ['PLATFORM_ADMIN'];
  state.activeTenantId = null;
  state.tenants = [];
  show();
  await open();
  expect(screen.getByText('Platform context')).toBeInTheDocument();
  expect(
    screen.queryByRole('menuitem', { name: 'Open tenant workspace' }),
  ).not.toBeInTheDocument();
});
it('returns a dual-role tenant user to platform through the existing context action', async () => {
  state.user!.isPlatformAdmin = true;
  show();
  const user = await open();
  await user.click(
    screen.getByRole('menuitem', { name: 'Return to Platform' }),
  );
  expect(state.clearTenantSelection).toHaveBeenCalledOnce();
  expect(state.replace).toHaveBeenCalledWith('/platform');
  expect(state.logout).not.toHaveBeenCalled();
});
it('offers only active explicit memberships and switches through the existing action', async () => {
  state.tenants.push(tenant(2, 'AstraMed'), {
    ...tenant(3, 'Forbidden'),
    membershipStatus: 'DISABLED',
  });
  show();
  const user = await open();
  await user.click(screen.getByRole('menuitem', { name: 'Switch tenant' }));
  expect(screen.queryByText('Forbidden')).not.toBeInTheDocument();
  await user.click(screen.getByRole('menuitem', { name: /AstraMed/ }));
  expect(state.selectTenant).toHaveBeenCalledWith('2');
  expect(state.logout).not.toHaveBeenCalled();
});
it('opens explicit tenant workspaces for platform authority without granting membership', async () => {
  state.user!.isPlatformAdmin = true;
  state.user!.tenantId = null;
  state.activeTenantId = null;
  show();
  const user = await open();
  await user.click(
    screen.getByRole('menuitem', { name: 'Open tenant workspace' }),
  );
  await user.click(screen.getByRole('menuitem', { name: /Olympus/ }));
  expect(state.selectTenant).toHaveBeenCalledWith('1');
  expect(state.replace).toHaveBeenCalledWith('/');
});
it('calls logout once and disables repeated submissions while signing out', async () => {
  show();
  await open();
  const button = screen.getByRole('menuitem', { name: 'Sign Out' });
  fireEvent.click(button);
  fireEvent.click(button);
  expect(state.logout).toHaveBeenCalledOnce();
  expect(screen.getByRole('menuitem', { name: 'Signing out…' })).toBeDisabled();
});
it('supports arrows, Enter and Escape with focus return', async () => {
  state.tenants.push(tenant(2, 'AstraMed'));
  show();
  const user = await open();
  await user.keyboard('{ArrowDown}');
  expect(screen.getByRole('menuitem', { name: 'Switch tenant' })).toHaveFocus();
  await user.keyboard('{ArrowDown}');
  expect(screen.getByRole('menuitem', { name: 'Sign Out' })).toHaveFocus();
  await user.keyboard('{Escape}');
  expect(screen.queryByRole('menu')).not.toBeInTheDocument();
  expect(screen.getByRole('button', { name: /Account menu/ })).toHaveFocus();
  await user.keyboard('{Enter}');
  await user.keyboard('{End}{Enter}');
  expect(state.logout).toHaveBeenCalledOnce();
});
it('closes on outside click and uses theme-safe surfaces', async () => {
  show();
  await open();
  expect(screen.getByRole('menu')).toHaveClass('bg-surface', 'border-border');
  fireEvent.mouseDown(document.body);
  expect(screen.queryByRole('menu')).not.toBeInTheDocument();
});

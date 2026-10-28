// @vitest-environment jsdom

import { QueryClient, QueryClientProvider } from '@tanstack/react-query';
import { fireEvent, render, screen, within } from '@testing-library/react';
import type { ReactNode } from 'react';
import { beforeEach, describe, expect, it, vi } from 'vitest';
import { Sidebar } from './Sidebar';
import { SidebarProvider } from './SidebarContext';
import { getRecentSboms, getRuns } from '@/lib/api';

const navigationState = vi.hoisted(() => ({
  pathname: '/sboms',
  search: '',
  permissions: new Set<string>(['*']),
}));

vi.mock('next/navigation', () => ({
  useRouter: () => ({ replace: vi.fn() }),
  usePathname: () => navigationState.pathname,
  useSearchParams: () => new URLSearchParams(navigationState.search),
}));

vi.mock('@/hooks/useAuth', () => ({
  useAuth: () => ({
    user: { displayName: 'Dev User', email: 'dev@local' },
    tenants: [
      {
        id: 1,
        name: 'Default Tenant',
        slug: 'default',
        externalIamTenantId: 'default',
        status: 'ACTIVE',
        role: 'TENANT_ADMIN',
      },
    ],
    activeTenantId: '1',
    switchTenant: vi.fn(),
    hasPermission: (permission: string) => (
      navigationState.permissions.has('*')
      || navigationState.permissions.has(permission)
    ),
  }),
}));

vi.mock('@/lib/api', async () => {
  const actual = await vi.importActual<typeof import('@/lib/api')>('@/lib/api');
  return {
    ...actual,
    getRecentSboms: vi.fn().mockResolvedValue([]),
    getRuns: vi.fn().mockResolvedValue([]),
  };
});

function wrap(children: ReactNode) {
  const client = new QueryClient({
    defaultOptions: { queries: { retry: false, gcTime: 0, staleTime: Infinity } },
  });
  return (
    <QueryClientProvider client={client}>
      <SidebarProvider>{children}</SidebarProvider>
    </QueryClientProvider>
  );
}

function renderSidebar(pathname = '/sboms', search = '') {
  navigationState.pathname = pathname;
  navigationState.search = search;
  return render(wrap(<Sidebar />));
}

function collapseSidebar() {
  fireEvent.click(screen.getByRole('button', { name: 'Collapse sidebar' }));
}

describe('Sidebar analysis navigation', () => {
  it('groups only authorized tenant working areas and preserves the selected route', () => {
    navigationState.permissions = new Set(['dashboard:read', 'project:read', 'sbom:read', 'analysis:read', 'vex:read', 'schedule:read', 'tenant:user:read']);
    renderSidebar('/projects');
    for (const label of ['Overview', 'Inventory', 'Security Operations', 'Administration']) {
      expect(screen.getByRole('heading', { name: label })).toBeInTheDocument();
    }
    expect(screen.getByRole('link', { name: 'Projects' })).toHaveAttribute('aria-current', 'page');
    expect(screen.getByRole('link', { name: 'Projects' })).toHaveClass('active');
    expect(screen.getByRole('complementary')).toHaveClass('tenant-sidebar');
    expect(screen.getByText('System Status')).toBeInTheDocument();
    expect(screen.queryByRole('link', { name: 'Platform Dashboard' })).not.toBeInTheDocument();
  });
  it('omits sections whose items are unauthorized', () => {
    navigationState.permissions = new Set(['dashboard:read']); renderSidebar('/');
    expect(screen.getByRole('heading', { name: 'Overview' })).toBeInTheDocument();
    expect(screen.queryByRole('heading', { name: 'Inventory' })).not.toBeInTheDocument();
    expect(screen.queryByRole('heading', { name: 'Security Operations' })).not.toBeInTheDocument();
    expect(screen.queryByRole('heading', { name: 'Administration' })).not.toBeInTheDocument();
  });
  it('announces Settings expansion and retains authorized child routes', () => {
    navigationState.permissions = new Set(['tenant:user:read', 'tenant:ai:read']);
    renderSidebar('/projects');
    const settings = screen.getByRole('button', { name: 'Settings' });
    expect(settings).toHaveAttribute('aria-expanded', 'false');
    expect(settings).toHaveAttribute('aria-controls', 'sidebar-flyout-settings-children');
    fireEvent.click(settings);
    expect(settings).toHaveAttribute('aria-expanded', 'true');
    expect(screen.getByRole('link', { name: 'Users & Access' })).toHaveAttribute('href', '/settings/users');
    expect(screen.queryByRole('link', { name: 'Lifecycle Providers' })).not.toBeInTheDocument();
    fireEvent.click(settings); expect(settings).toHaveAttribute('aria-expanded', 'false');
  });
  it('keeps labeled navigation and workspace controls in the collapsed rail', () => {
    renderSidebar('/projects'); collapseSidebar();
    expect(screen.getByRole('link', { name: 'Projects' })).toHaveAttribute('title', 'Projects');
    expect(screen.getByRole('button', { name: 'Switch tenant' })).toBeInTheDocument();
    expect(screen.getByRole('button', { name: 'Expand sidebar' })).toHaveAttribute('aria-expanded', 'false');
  });
  it('shows only the control plane for a pure Platform Admin', () => {
    navigationState.permissions = new Set(['platform:tenant:read', 'platform:administrator:read', 'platform:health:read', 'platform:admin', 'platform:ai:read', 'platform:lifecycle-provider:read']);
    renderSidebar('/platform');
    expect(screen.getByRole('link', { name: 'Platform Dashboard' })).toBeInTheDocument();
    expect(screen.getByRole('link', { name: 'Tenants' })).toBeInTheDocument();
    expect(screen.getByRole('region', { name: 'Configuration' })).toBeInTheDocument();
    expect(screen.getByRole('region', { name: 'Administration' })).toBeInTheDocument();
    expect(screen.queryByRole('button', { name: 'Settings' })).not.toBeInTheDocument();
    expect(screen.getByRole('link', { name: 'Platform Dashboard' })).toHaveAttribute('aria-current', 'page');
    for (const name of ['Dashboard', 'Projects', 'SBOMs', 'CISA KEV', 'VEX Investigation', 'Schedules', 'Users & Access']) {
      expect(screen.queryByRole('link', { name })).not.toBeInTheDocument();
    }
    expect(screen.queryByRole('button', { name: 'Analysis' })).not.toBeInTheDocument();
    expect(getRecentSboms).not.toHaveBeenCalled();
    expect(getRuns).not.toHaveBeenCalled();
  });
  it.each(['platform:user:read', 'tenant:user:read', 'neither'])('guards the single Users & Access entry with %s', permission => {
    navigationState.permissions = new Set([permission]);
    renderSidebar('/settings/users');
    expect(screen.queryAllByRole('link', { name: 'Users & Access' })).toHaveLength(permission === 'tenant:user:read' ? 1 : 0);
    expect(screen.queryByText('Administration · Users')).not.toBeInTheDocument();
    expect(screen.queryByText('Tenant users')).not.toBeInTheDocument();
  });
  beforeEach(() => {
    vi.clearAllMocks();
    navigationState.pathname = '/sboms';
    navigationState.search = '';
    navigationState.permissions = new Set(['*']);
  });

  it('shows Analysis children in expanded mode and exposes Runs navigation', () => {
    renderSidebar('/sboms');

    fireEvent.click(screen.getByRole('button', { name: 'Analysis' }));

    const nav = screen.getByRole('navigation', { name: 'Main' });
    const runs = within(nav).getByRole('link', { name: 'Runs' });
    expect(runs).toHaveAttribute('href', '/analysis?tab=runs');
    expect(within(nav).getByRole('link', { name: 'Consolidated' })).toHaveAttribute(
      'href',
      '/analysis?tab=consolidated',
    );
    expect(within(nav).getByRole('link', { name: 'Compare' })).toHaveAttribute(
      'href',
      '/analysis/compare',
    );
  });

  it('shows the CISA KEV catalog navigation item', () => {
    renderSidebar('/sboms');

    const nav = screen.getByRole('navigation', { name: 'Main' });
    expect(within(nav).getByRole('link', { name: 'CISA KEV' })).toHaveAttribute('href', '/kev');
  });

  it('opens a collapsed flyout with Analysis child links', () => {
    renderSidebar('/sboms');
    collapseSidebar();

    const analysisTrigger = screen.getByRole('button', { name: 'Analysis' });
    expect(analysisTrigger).toBeInTheDocument();

    fireEvent.click(analysisTrigger);

    const flyout = screen.getByRole('menu', { name: 'Analysis menu' });
    expect(flyout).toHaveClass('fixed');
    expect(flyout).toHaveClass('z-[80]');
    expect(flyout).toHaveClass('bg-surface');
    expect(flyout).toHaveClass('text-foreground');
    expect(within(flyout).getByRole('menuitem', { name: 'Runs' })).toHaveAttribute(
      'href',
      '/analysis?tab=runs',
    );
    expect(within(flyout).getByRole('menuitem', { name: 'Consolidated' })).toHaveAttribute(
      'href',
      '/analysis?tab=consolidated',
    );
    expect(within(flyout).getByRole('menuitem', { name: 'Compare' })).toHaveAttribute(
      'href',
      '/analysis/compare',
    );
  });

  it('closes the collapsed flyout after choosing an Analysis route', () => {
    renderSidebar('/sboms');
    collapseSidebar();
    fireEvent.click(screen.getByRole('button', { name: 'Analysis' }));

    const flyout = screen.getByRole('menu', { name: 'Analysis menu' });
    fireEvent.click(within(flyout).getByRole('menuitem', { name: 'Consolidated' }));

    expect(screen.queryByRole('menu', { name: 'Analysis menu' })).not.toBeInTheDocument();
  });

  it('keeps the Analysis icon active on analysis routes and marks active flyout child', () => {
    renderSidebar('/analysis/compare');
    collapseSidebar();

    const analysisTrigger = screen.getByRole('button', { name: 'Analysis' });
    expect(analysisTrigger).toHaveClass('active');
    fireEvent.click(analysisTrigger);

    const flyout = screen.getByRole('menu', { name: 'Analysis menu' });
    expect(within(flyout).getByRole('menuitem', { name: 'Compare' })).toHaveAttribute(
      'aria-current',
      'page',
    );
  });

  it('marks Consolidated active from the analysis tab query', () => {
    renderSidebar('/analysis', 'tab=consolidated');

    const nav = screen.getByRole('navigation', { name: 'Main' });
    expect(within(nav).getByRole('link', { name: 'Consolidated' })).toHaveAttribute(
      'aria-current',
      'page',
    );
  });

  it('uses dark-mode readable flyout classes', () => {
    render(wrap(
      <div className="dark">
        <Sidebar />
      </div>,
    ));
    collapseSidebar();
    fireEvent.click(screen.getByRole('button', { name: 'Analysis' }));

    const flyout = screen.getByRole('menu', { name: 'Analysis menu' });
    expect(flyout).toHaveClass('border-hcl-border');
    expect(flyout).toHaveClass('bg-surface');
    expect(flyout).toHaveClass('text-foreground');
    expect(within(flyout).getByRole('menuitem', { name: 'Runs' })).toHaveClass(
      'dark:hover:text-foreground',
    );
  });

  it('shows platform administration only with platform permissions', () => {
    renderSidebar('/settings');
    expect(screen.getByRole('link', { name: 'Tenants' })).toBeInTheDocument();
    expect(screen.getByRole('region', { name: 'Administration' })).toBeInTheDocument();
    expect(screen.getByRole('link', { name: 'Platform Administrators' })).toBeInTheDocument();
  });

  it('shows tenant administration without platform administration for a Tenant Administrator', () => {
    navigationState.permissions = new Set([
      'tenant:user:read',
      'tenant:settings:update',
    ]);
    renderSidebar('/settings/users');
    const nav = screen.getByRole('navigation', { name: 'Main' });
    expect(within(nav).getByRole('link', { name: 'Users & Access' })).toBeInTheDocument();
    expect(within(nav).queryByRole('link', { name: 'Platform tenants' })).not.toBeInTheDocument();
    expect(within(nav).queryByRole('link', { name: 'Platform Administrators' })).not.toBeInTheDocument();
  });

  it('does not show administration pages for Security Analyst or Viewer permissions', () => {
    navigationState.permissions = new Set(['analysis:run', 'sbom:read']);
    renderSidebar('/sboms');
    const nav = screen.getByRole('navigation', { name: 'Main' });
    expect(within(nav).queryByRole('link', { name: 'Tenant users' })).not.toBeInTheDocument();
    expect(within(nav).queryByRole('link', { name: 'Platform tenants' })).not.toBeInTheDocument();
    expect(within(nav).queryByRole('link', { name: 'Platform Administrators' })).not.toBeInTheDocument();
  });
});

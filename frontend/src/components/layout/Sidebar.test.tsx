// @vitest-environment jsdom

import { QueryClient, QueryClientProvider } from '@tanstack/react-query';
import { fireEvent, render, screen, within } from '@testing-library/react';
import type { ReactNode } from 'react';
import { beforeEach, describe, expect, it, vi } from 'vitest';
import { Sidebar } from './Sidebar';
import { SidebarProvider } from './SidebarContext';

const navigationState = vi.hoisted(() => ({
  pathname: '/sboms',
  search: '',
}));

vi.mock('next/navigation', () => ({
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
    hasPermission: () => true,
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
  beforeEach(() => {
    navigationState.pathname = '/sboms';
    navigationState.search = '';
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
});

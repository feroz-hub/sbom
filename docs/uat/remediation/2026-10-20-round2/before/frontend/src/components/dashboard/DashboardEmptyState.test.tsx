// @vitest-environment jsdom
import { fireEvent, render, screen } from '@testing-library/react';
import { beforeEach, describe, expect, it, vi } from 'vitest';
import { DashboardEmptyState } from './DashboardEmptyState';
import { LifetimeStats } from './LifetimeStats/LifetimeStats';
import { QuickActionsV2 } from './QuickActionsV2/QuickActionsV2';

let permissions: string[] = [];
vi.mock('@/hooks/useAuth', () => ({ useAuth: () => ({ user: { userId: 1, permissions: [] }, hasPermission: (p: string) => permissions.includes(p) }) }));
beforeEach(() => { permissions = []; });
describe('Tenant dashboard guidance', () => {
  it('offers an upload action only with active upload permission', () => {
    permissions = ['sbom:upload', 'project:create'];
    render(<DashboardEmptyState filtered={false} onClear={vi.fn()} />);
    expect(screen.getByText('No SBOMs uploaded yet')).toBeInTheDocument();
    expect(screen.getByRole('link', { name: 'Upload SBOM' })).toHaveAttribute('href', '/sboms?action=upload');
    expect(screen.getByRole('link', { name: /Create project/ })).toHaveAttribute('href', '/projects');
  });
  it('shows informational guidance to a Viewer without unauthorized actions anywhere', () => {
    render(<><DashboardEmptyState filtered={false} onClear={vi.fn()} /><QuickActionsV2 /></>);
    expect(screen.getByText(/Upload an SBOM to start/)).toBeInTheDocument();
    expect(screen.queryByRole('link')).not.toBeInTheDocument();
  });
  it('distinguishes filtered empty inventory and clears filters', () => {
    const clear = vi.fn();
    render(<DashboardEmptyState filtered onClear={clear} />);
    expect(screen.getByText('No data matches the current filters')).toBeInTheDocument();
    expect(screen.queryByText('No SBOMs uploaded yet')).not.toBeInTheDocument();
    fireEvent.click(screen.getByRole('button', { name: 'Clear filters' }));
    expect(clear).toHaveBeenCalledOnce();
  });
  it('renders meaningful zero metrics and authorized analysis navigation', () => {
    permissions = ['analysis:read'];
    render(<LifetimeStats data={undefined} findingsTotal={0} isLoading={false} />);
    expect(screen.getByText('Not started')).toBeInTheDocument();
    expect(screen.getByText('No completed analysis runs')).toBeInTheDocument();
    expect(screen.getByRole('link', { name: /View Analysis/ })).toHaveAttribute('href', '/analysis');
  });
});

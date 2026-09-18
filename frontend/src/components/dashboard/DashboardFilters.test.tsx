// @vitest-environment jsdom

import { describe, expect, it, vi } from 'vitest';
import { fireEvent, render, screen } from '@testing-library/react';
import { QueryClient, QueryClientProvider } from '@tanstack/react-query';
import { DashboardFilters } from './DashboardFilters';

vi.mock('@/hooks/useAuth', () => ({
  useAuth: () => ({
    activeTenant: { id: 1, name: 'Tenant One' },
    activeTenantId: '1',
  }),
}));
vi.mock('@/lib/api', () => ({
  getDashboardProjectOptions: async () => ({ items: [
    { id: 10, name: 'Project A' }, { id: 20, name: 'Project B' },
    { id: 30, name: 'Project C' }, { id: 40, name: 'Empty Project' },
  ] }),
  getDashboardApplicationOptions: async (projectId: number) => ({
    items: projectId === 40 ? [] : projectId === 10 ? [{ id: 100, name: 'Application A' }]
      : projectId === 30 ? [{ id: 300, name: 'Application C' }] : [{ id: 200, name: 'Application B' }],
  }),
  getDashboardSbomOptions: async (scope: { applicationId: number }) => ({
    items: scope.applicationId === 300 ? [] : [{ id: 1000, name: 'SBOM A', version: '1.0', display_name: 'SBOM A — v1.0' }],
  }),
}));

function renderFilters(scope = { projectId: null as number | null, applicationId: null as number | null, sbomId: null as number | null }) {
  const onChange = vi.fn();
  const queryClient = new QueryClient({ defaultOptions: { queries: { retry: false } } });
  const view = render(
    <QueryClientProvider client={queryClient}>
      <DashboardFilters scope={scope} onChange={onChange} isUpdating={false} />
    </QueryClientProvider>,
  );
  return { onChange, ...view };
}

describe('DashboardFilters', () => {
  it('starts at tenant scope and disables children until their parent is selected', async () => {
    renderFilters();
    expect(screen.queryByLabelText('Tenant')).not.toBeInTheDocument();
    expect(screen.getAllByRole('combobox')).toHaveLength(3);
    expect(screen.getByText('Viewing: Tenant One')).toBeInTheDocument();
    expect(screen.getByLabelText('Application')).toBeDisabled();
    expect(screen.getByLabelText('SBOM')).toBeDisabled();
    await screen.findByRole('option', { name: 'Project A' });
    expect(screen.getAllByRole('option', { name: 'ALL' })).toHaveLength(3);
    expect(screen.getByRole('button', { name: 'Clear all filters' })).toBeDisabled();
  });

  it('clears project, application, and SBOM while keeping the current tenant', () => {
    const { onChange } = renderFilters({ projectId: 10, applicationId: 100, sbomId: 1000 });
    const clear = screen.getByRole('button', { name: 'Clear all filters' });
    expect(clear).toBeEnabled();
    fireEvent.click(clear);
    expect(onChange).toHaveBeenCalledWith({ projectId: null, applicationId: null, sbomId: null });
    expect(screen.getByText('Viewing: Tenant One')).toBeInTheDocument();
  });

  it('resets descendants when a parent changes', async () => {
    const scope = { projectId: 10, applicationId: 100, sbomId: 1000 };
    const { onChange } = renderFilters(scope);
    await screen.findByRole('option', { name: 'Project B' });
    await screen.findByRole('option', { name: 'Application A' });
    await screen.findByRole('option', { name: 'SBOM A — v1.0' });
    fireEvent.change(screen.getByLabelText('Project'), { target: { value: '20' } });
    expect(onChange).toHaveBeenLastCalledWith({ projectId: 20, applicationId: null, sbomId: null });
    fireEvent.change(screen.getByLabelText('Application'), { target: { value: '' } });
    expect(onChange).toHaveBeenLastCalledWith({ projectId: 10, applicationId: null, sbomId: null });
  });

  it('shows empty states for projects without applications and applications without SBOMs', async () => {
    const first = renderFilters({ projectId: 40, applicationId: null, sbomId: null });
    expect(await screen.findByText('No applications are available in this project.')).toBeInTheDocument();
    first.unmount();
    renderFilters({ projectId: 30, applicationId: 300, sbomId: null });
    expect(await screen.findByText('No SBOMs have been uploaded for this application.')).toBeInTheDocument();
  });
});

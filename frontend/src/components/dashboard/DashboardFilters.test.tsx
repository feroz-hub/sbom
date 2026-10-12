// @vitest-environment jsdom

import { beforeEach, describe, expect, it, vi } from 'vitest';
import userEvent from '@testing-library/user-event';
import { fireEvent, render, screen } from '@testing-library/react';
import { QueryClient, QueryClientProvider } from '@tanstack/react-query';
import { DashboardFilters } from './DashboardFilters';

const postureNotice = vi.hoisted(() => vi.fn(() => null));
vi.mock('@/components/sboms/SbomPostureNotice', () => ({SbomPostureNotice: postureNotice}));

const auth = vi.hoisted(() => ({tenantId:'1'}));
beforeEach(() => {auth.tenantId='1';});
vi.mock('@/hooks/useAuth', () => ({
  useAuth: () => ({
    activeTenant: { id: 1, name: 'Tenant One' },
    activeTenantId: auth.tenantId,
  }),
}));
vi.mock('@/lib/api', () => ({
  getVexInvestigationVersions: async () => ({items: []}),
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
    expect(screen.queryByText(/Viewing:|Tenant One/)).not.toBeInTheDocument();
    expect(screen.queryByText('Scope')).not.toBeInTheDocument();
    expect(screen.queryByText('Tenant One')).not.toBeInTheDocument();
    expect(screen.getByLabelText('Application')).toBeDisabled();
    expect(screen.getByLabelText('SBOM')).toBeDisabled();
    await screen.findByRole('option', { name: 'Project A' });
    expect(screen.getByRole('option', {name:'All projects'})).toBeInTheDocument();
    expect(screen.getByRole('option', {name:'All applications'})).toBeInTheDocument();
    expect(screen.getByRole('option', {name:'All SBOMs'})).toBeInTheDocument();
    expect(screen.queryByRole('button', {name:'Reset filters'})).not.toBeInTheDocument();
  });

  it('clears project, application, and SBOM while keeping the current tenant', () => {
    const { onChange } = renderFilters({ projectId: 10, applicationId: 100, sbomId: 1000 });
    const clear = screen.getByRole('button', { name: 'Reset filters' });
    expect(clear).toBeEnabled();
    fireEvent.click(clear);
    expect(onChange).toHaveBeenCalledWith({ projectId: null, applicationId: null, sbomId: null });
    expect(screen.queryByText(/Viewing:|Tenant One/)).not.toBeInTheDocument();
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


it.each([
  {projectId:null,applicationId:null,sbomId:null},
  {projectId:10,applicationId:null,sbomId:null},
  {projectId:10,applicationId:100,sbomId:null},
  {projectId:10,applicationId:100,sbomId:1000},
])('does not mount version posture or its query at scope %j', async scope => {
  renderFilters(scope);
  await screen.findByRole('option', {name:'Project A'});
  expect(postureNotice).not.toHaveBeenCalled();
  expect(screen.queryByLabelText('SBOM version posture')).not.toBeInTheDocument();
  expect(screen.queryByText(/Current SBOM:|Latest uploaded:|Latest analyzed:|Security posture:|Analysis run \d|Last successful analysis|Analysis coverage incomplete|Version posture/)).not.toBeInTheDocument();
  expect(screen.getByLabelText('Project')).toBeInTheDocument();
  expect(screen.getByLabelText('Application')).toBeInTheDocument();
  expect(screen.getByLabelText('SBOM')).toBeInTheDocument();
});


it('exposes dependent-filter instructions to assistive technology', () => {
 renderFilters();
 expect(screen.getByRole('button',{name:'Application: All applications'})).toBeDisabled();
 expect(screen.getByRole('button',{name:'Application: All applications'})).toHaveAccessibleDescription('Select a project first.');
 expect(screen.getByRole('button',{name:'SBOM: All SBOMs'})).toHaveAccessibleDescription('Select an application first.');
});

it('partitions project-option caches by active tenant', async () => {
 const queryClient=new QueryClient({defaultOptions:{queries:{retry:false}}});
 queryClient.setQueryData(['dashboard-projects','1'],{items:[{id:11,name:'Tenant One Project'}]});
 queryClient.setQueryData(['dashboard-projects','2'],{items:[{id:22,name:'Tenant Two Project'}]});
 const element=()=> <QueryClientProvider client={queryClient}><DashboardFilters scope={{projectId:null,applicationId:null,sbomId:null}} onChange={vi.fn()} isUpdating={false}/></QueryClientProvider>;
 const view=render(element());
 expect(screen.getByRole('option',{name:'Tenant One Project'})).toBeInTheDocument();
 auth.tenantId='2';view.rerender(element());
 expect(screen.getByRole('option',{name:'Tenant Two Project'})).toBeInTheDocument();
 expect(screen.queryByRole('option',{name:'Tenant One Project'})).not.toBeInTheDocument();
});


it('supports keyboard reset without changing tenant selection', async () => {
 const user=userEvent.setup();const {onChange}=renderFilters({projectId:10,applicationId:null,sbomId:null});
 const reset=screen.getByRole('button',{name:'Reset filters'});reset.focus();await user.keyboard('{Enter}');
 expect(onChange).toHaveBeenCalledWith({projectId:null,applicationId:null,sbomId:null});expect(auth.tenantId).toBe('1');
});

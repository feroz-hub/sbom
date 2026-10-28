// @vitest-environment jsdom
import { QueryClient, QueryClientProvider, useMutation, useQuery } from '@tanstack/react-query';
import { fireEvent, render, screen, waitFor } from '@testing-library/react';
import { afterEach, beforeEach, expect, it, vi } from 'vitest';
import type { Project, SBOMSource } from '@/types';
import { ProjectModal } from '@/components/projects/ProjectModal';
import { ReportPreferencesEditor, defaultReportPreferences } from '@/components/reports/ReportNotificationsPage';
import { updateSbom, restoreSbomVersion, overrideComponentLifecycle, refreshComponentLifecycle } from '@/lib/api';
import { invalidateProjectAssignmentSurfaces, invalidateSbomRevisionCreated, invalidateLifecycleOverrideSurfaces, invalidateProjectMetadata } from '@/lib/queryInvalidation';

const api = vi.hoisted(() => ({ create: vi.fn(), update: vi.fn(), sbom: vi.fn(), restore: vi.fn(), override: vi.fn(), refresh: vi.fn(), targets: vi.fn(), success: vi.fn(), error: vi.fn() }));
vi.mock('@/lib/api', async original => ({ ...(await original<typeof import('@/lib/api')>()), createProject: (...args: unknown[]) => api.create(...args), updateProject: (...args: unknown[]) => api.update(...args),
  updateSbom: (...args: unknown[]) => api.sbom(...args), restoreSbomVersion: (...args: unknown[]) => api.restore(...args), overrideComponentLifecycle: (...args: unknown[]) => api.override(...args), refreshComponentLifecycle: (...args: unknown[]) => api.refresh(...args),
}));
vi.mock('@/lib/reportApi', async original => ({ ...(await original<typeof import('@/lib/reportApi')>()), getReportTargets: (...args: unknown[]) => api.targets(...args) }));
vi.mock('@/hooks/useAuth', async () => { const { authorizedAuth } = await import('@/test/authorizedAuth'); return { useAuth: () => authorizedAuth() }; });
vi.mock('@/hooks/useToast', () => ({ useToast: () => ({ showToast: vi.fn() }) }));
vi.mock('@/hooks/useNotifications', () => ({ useNotifications: () => ({ showSuccess: api.success, showApiError: api.error }) }));
const project: Project = { id: 1, project_name: 'Project A', project_details: null, project_status: 1, created_by: null, created_on: null, modified_by: null, modified_on: null };
const initial: SBOMSource = { id: 5, sbom_name: 'Original', sbom_version: '1.0', sbom_type: null, projectid: 1, product_id: 10, created_by: null, created_on: null, modified_by: null, modified_on: null, productver: null };
let qc: QueryClient, server: SBOMSource[], projectLabel: string, lifecycle: string;
const wrap = (node: React.ReactNode) => <QueryClientProvider client={qc}>{node}</QueryClientProvider>;
function Inventory({ owner }: { owner: number }) {
  const data = useQuery({ queryKey: ['product-sboms', owner], queryFn: async () => server.filter(row => row.product_id === owner) });
  return <output>Product {owner}: {data.data?.map(row => row.sbom_name).join(',') || 'empty'}</output>;
}
function ProjectProjection() {
  const data = useQuery({ queryKey: ['project-detail', 1], queryFn: async () => ({ project_name: projectLabel }) });
  return <output>Detail: {data.data?.project_name}</output>;
}
function Evidence({ canonical }: { canonical: boolean }) {
  const data = useQuery({ queryKey: canonical ? ['sbom-components-canonical', 5] : ['sbom-components', 5, false, 2, 25, 'openssl'], queryFn: async () => lifecycle });
  return <output>{canonical ? 'Canonical' : 'Page 2'}: {data.data}</output>;
}
// API mutations use the same authoritative response and helper contracts as SbomDetail.
function InventoryAction({ action }: { action: 'move' | 'rename' | 'restore' | 'override' | 'refresh' }) {
  const mutation = useMutation({ mutationFn: async () => {
    if (action === 'restore') {
      const revision = await restoreSbomVersion(5, 4); await invalidateSbomRevisionCreated(qc, initial, revision);
    } else if (action === 'override' || action === 'refresh') {
      if (action === 'override') await overrideComponentLifecycle(11, { reason: 'Verified vendor evidence', lifecycle_status: 'SUPPORTED' });
      else await refreshComponentLifecycle(11, true);
      await invalidateLifecycleOverrideSurfaces(qc, 5);
    } else {
      const updated = await updateSbom(5, action === 'move' ? { project_id: 2, product_id: 20 } : { name: 'Renamed' });
      await invalidateProjectAssignmentSurfaces(qc, { sbomId: 5, previousProjectId: initial.projectid, nextProjectId: updated.projectid, previousProductId: initial.product_id, nextProductId: updated.product_id });
    }
  } });
  return <><button onClick={() => mutation.mutate()}>Mutate inventory</button>{mutation.isError ? <p role="alert">Mutation failed</p> : mutation.isSuccess ? <p>Mutation complete</p> : null}</>;
}
beforeEach(() => {
  vi.clearAllMocks(); qc = new QueryClient({ defaultOptions: { queries: { staleTime: 300_000, refetchOnWindowFocus: false, retry: false }, mutations: { retry: false } } });
  server = [initial]; projectLabel = 'Project A'; lifecycle = 'UNKNOWN';
  qc.setQueryData(['product-sboms', 10], [initial]); qc.setQueryData(['product-sboms', 20], []);
  qc.setQueryData(['project-detail', 1], project); qc.setQueryData(['projects'], [project]);
  qc.setQueryData(['reports', 'targets', 'PROJECT', ''], [{ id: 1, label: 'Project A' }]);
  qc.setQueryData(['reports', 'deliveries', false, '', 52], 'immutable');
  api.targets.mockResolvedValue([{ id: 1, label: 'Project A' }, { id: 2, label: 'New Project' }]);
  api.create.mockResolvedValue({ ...project, id: 2, project_name: 'New Project' });
  api.update.mockImplementation(async () => { projectLabel = 'Renamed'; return { ...project, project_name: 'Renamed' }; });
  api.sbom.mockImplementation(async (_id, payload) => { const updated = { ...initial, ...(payload.name ? { sbom_name: payload.name } : { projectid: 2, product_id: 20 }) }; server = [updated]; return updated; });
  api.restore.mockImplementation(async () => { const revision = { ...initial, id: 6, parent_id: 5, sbom_name: 'Restored revision' }; server = [initial, revision]; return revision; });
  for (const fn of [api.override, api.refresh]) fn.mockImplementation(async () => { lifecycle = 'SUPPORTED'; return { id: 11, lifecycle_status: lifecycle }; });
});
afterEach(() => qc.clear());
it('actual project creation refreshes report options on reopen without resetting selected scope/search', async () => {
  const closed = vi.fn(); const mounted = render(wrap(<ProjectModal open onClose={closed} />));
  fireEvent.change(screen.getByRole('textbox', { name: 'Project Name' }), { target: { value: 'New Project' } });
  fireEvent.click(screen.getByRole('button', { name: 'Create Project' })); await waitFor(() => expect(closed).toHaveBeenCalled());
  mounted.rerender(wrap(<ReportPreferencesEditor initial={defaultReportPreferences('PROJECT', 1)} tenantScopeAllowed={false} onClose={vi.fn()} />));
  expect(await screen.findByRole('option', { name: 'New Project · #2' })).toBeInTheDocument();
  expect(screen.getByLabelText('Scope')).toHaveValue('PROJECT'); expect(screen.getByLabelText('Target')).toHaveValue('1');
  expect(screen.getByLabelText('Search scope')).toHaveValue(''); expect(api.targets).toHaveBeenCalledTimes(1);
  expect(qc.getQueryState(['reports', 'deliveries', false, '', 52])?.isInvalidated).toBe(false);
});
it('actual project rename refreshes cached detail from backend values', async () => {
  render(wrap(<><ProjectProjection /><ProjectModal open project={project} onClose={vi.fn()} /></>));
  fireEvent.change(screen.getByRole('textbox', { name: 'Project Name' }), { target: { value: 'Renamed' } });
  fireEvent.click(screen.getByRole('button', { name: 'Save Changes' })); await screen.findByText('Detail: Renamed');
  expect(api.update).toHaveBeenCalledWith(1, expect.objectContaining({ project_name: 'Renamed' }));
});
it('project failure preserves the form, cached detail and success state', async () => {
  api.update.mockRejectedValue(new Error('Failed')); const closed = vi.fn();
  render(wrap(<><ProjectProjection /><ProjectModal open project={project} onClose={closed} /></>));
  fireEvent.change(screen.getByRole('textbox', { name: 'Project Name' }), { target: { value: 'Draft name' } });
  fireEvent.click(screen.getByRole('button', { name: 'Save Changes' })); await waitFor(() => expect(api.error).toHaveBeenCalled());
  expect(screen.getByRole('textbox', { name: 'Project Name' })).toHaveValue('Draft name'); expect(screen.getByText('Detail: Project A')).toBeInTheDocument();
  expect(api.success).not.toHaveBeenCalled(); expect(closed).not.toHaveBeenCalled(); expect(qc.getQueryState(['project-detail', 1])?.isInvalidated).toBe(false);
});
it.each(['move', 'rename', 'restore'] as const)('%s refreshes actual old/new owner rows from backend', async action => {
  render(wrap(<><Inventory owner={10} /><Inventory owner={20} /><InventoryAction action={action} /></>));
  fireEvent.click(screen.getByRole('button', { name: 'Mutate inventory' })); await screen.findByText('Mutation complete');
  expect(screen.getByText(action === 'move' ? 'Product 10: empty' : action === 'rename' ? 'Product 10: Renamed' : 'Product 10: Original,Restored revision')).toBeInTheDocument();
  expect(screen.getByText(action === 'move' ? 'Product 20: Original' : 'Product 20: empty')).toBeInTheDocument();
});
it.each(['override', 'refresh'] as const)('%s refreshes canonical and paginated evidence', async action => {
  qc.setQueryData(['sbom-components-canonical', 5], 'UNKNOWN'); qc.setQueryData(['sbom-components', 5, false, 2, 25, 'openssl'], 'UNKNOWN');
  render(wrap(<><Evidence canonical /><Evidence canonical={false} /><InventoryAction action={action} /></>));
  fireEvent.click(screen.getByRole('button', { name: 'Mutate inventory' })); await screen.findByText('Mutation complete');
  expect(screen.getByText('Canonical: SUPPORTED')).toBeInTheDocument(); expect(screen.getByText('Page 2: SUPPORTED')).toBeInTheDocument();
});
it.each(['move', 'restore', 'override'] as const)('failed %s does not update inventory caches', async action => {
  (action === 'move' ? api.sbom : action === 'restore' ? api.restore : api.override).mockRejectedValue(new Error('Failed'));
  render(wrap(<><Inventory owner={10} /><InventoryAction action={action} /></>));
  fireEvent.click(screen.getByRole('button', { name: 'Mutate inventory' })); await screen.findByRole('alert');
  expect(screen.getByText('Product 10: Original')).toBeInTheDocument(); expect(qc.getQueryState(['product-sboms', 10])?.isInvalidated).toBe(false);
});
it('status changes refresh an inactive dashboard before revisiting it', async () => {
  qc.setQueryData(['dashboard-summary', 'tenant', 1], 'cached');
  await invalidateProjectMetadata(qc, { ...project, project_status: 0 }, project);
  expect(qc.getQueryState(['dashboard-summary', 'tenant', 1])?.isInvalidated).toBe(true);
  await qc.fetchQuery({ queryKey: ['dashboard-summary', 'tenant', 1], queryFn: async () => 'authoritative status counts' });
  expect(qc.getQueryData(['dashboard-summary', 'tenant', 1])).toBe('authoritative status counts');
});
it('active report refresh preserves search, scope and selected target', async () => {
  api.targets.mockResolvedValue([{ id: 1, label: 'Project A' }]);
  render(wrap(<ReportPreferencesEditor initial={defaultReportPreferences('PROJECT', 1)} tenantScopeAllowed={false} onClose={vi.fn()} />));
  fireEvent.change(screen.getByLabelText('Search scope'), { target: { value: 'Production' } });
  await waitFor(() => expect(api.targets).toHaveBeenCalledTimes(1));
  api.targets.mockResolvedValue([{ id: 1, label: 'Project A' }, { id: 2, label: 'New target' }]);
  await invalidateProjectMetadata(qc, { ...project, id: 2 });
  expect(await screen.findByRole('option', { name: 'New target · #2' })).toBeInTheDocument();
  expect(screen.getByLabelText('Search scope')).toHaveValue('Production'); expect(screen.getByLabelText('Scope')).toHaveValue('PROJECT');
  expect(screen.getByLabelText('Target')).toHaveValue('1'); expect(api.targets).toHaveBeenCalledTimes(2);
});

// @vitest-environment jsdom
import { QueryClient, QueryClientProvider } from '@tanstack/react-query';
import { fireEvent, render, screen, waitFor, within } from '@testing-library/react';
import { beforeEach, describe, expect, it, vi } from 'vitest';
import { ToastProvider } from '@/hooks/useToast';
import ProjectsPage from './page';
import type { Product, Project } from '@/types';

const access = vi.hoisted(() => ({ readOnly: false }));
const mocks = vi.hoisted(() => ({ url: '', push: vi.fn(), getProjects: vi.fn(), getProducts: vi.fn(), deleteProduct: vi.fn(), deleteProject: vi.fn(), impact: vi.fn(), scanned: vi.fn(), schedule: vi.fn() }));
vi.mock('@/components/layout/TopBar', () => ({ TopBar: ({ title, action }: { title: string; action: React.ReactNode }) => <header><h1>{title}</h1>{action}</header> }));
vi.mock('next/navigation', () => ({ useSearchParams: () => new URLSearchParams(mocks.url), useRouter: () => ({ push: mocks.push }) }));
vi.mock('@/lib/api', async original => ({ ...await original<typeof import('@/lib/api')>(), getProjects: mocks.getProjects, getProducts: mocks.getProducts, deleteProduct: mocks.deleteProduct, deleteProject: mocks.deleteProject, getProjectDeleteImpact: mocks.impact, getDashboardScannedProjectIds: mocks.scanned, getEffectiveProductSchedule: mocks.schedule }));
vi.mock('@/components/projects/ProjectModal', () => ({ ProjectModal: ({ open, project }: { open: boolean; project?: Project }) => open ? <div role="dialog" aria-label={project ? `Edit project ${project.project_name}` : 'New project'} /> : null }));
vi.mock('@/components/products/ProductFormDialog', () => ({ ProductFormDialog: ({ open, project, product }: { open: boolean; project: Project; product?: Product }) => open ? <div role="dialog" aria-label={`${product ? 'Edit' : 'Create'} application in ${project.project_name}`} /> : null }));
vi.mock('@/components/sboms/SbomUploadModal', () => ({ SbomUploadModal: ({ open, initialProjectId, initialProductId }: { open: boolean; initialProjectId: number; initialProductId: number }) => open ? <div role="dialog" aria-label={`Upload to project ${initialProjectId} application ${initialProductId}`} /> : null }));
vi.mock('@/components/schedules/ProjectScheduleDialog', () => ({ ProjectScheduleDialog: ({ open, project }: { open: boolean; project: Project }) => open ? <div role="dialog" aria-label={`Schedule ${project.project_name}`} /> : null }));
const projects: Project[] = [
  { id: "00000000-0000-4000-8000-000000000002", display_id: 2, project_name: 'Pump Security', project_details: 'Governance and monitoring', project_status: 1, created_by: 'owner@example.test', created_on: null, modified_by: null, modified_on: null },
  { id: "00000000-0000-4000-8000-000000000001", display_id: 1, project_name: 'TestProject', project_details: null, project_status: 0, created_by: null, created_on: null, modified_by: null, modified_on: null },
];
const pump: Product = { id: "00000000-0000-4000-8000-000000000014", display_id: 20, project_id: "00000000-0000-4000-8000-000000000002", name: 'Pump Controller', description: 'Controller software', status: 'active', sbom_count: 1, latest_sbom_id: "00000000-0000-4000-8000-000000000008", latest_sbom_display_id: 8, latest_sbom_version: '1.0.0', current_sbom_id: "00000000-0000-4000-8000-000000000008", current_sbom_display_id: 8, current_sbom_version: '1.0.0' };
const other: Product = { id: "00000000-0000-4000-8000-00000000000a", display_id: 10, project_id: "00000000-0000-4000-8000-000000000001", name: 'Other application', status: 'inactive', sbom_count: 2 };
function setup() {
  const client = new QueryClient({ defaultOptions: { queries: { retry: false }, mutations: { retry: false } } });
  const tree = () => <QueryClientProvider client={client}><ToastProvider><ProjectsPage /></ToastProvider></QueryClientProvider>;
  const result = render(tree());
  return { client, refresh: () => result.rerender(tree()) };
}
function appTable() { return screen.getByRole('region', { name: / applications$/ }); }
function projectMenu(name = 'Pump Security') { fireEvent.click(screen.getByRole('button', { name: `Actions for project ${name}` })); return screen.getByRole('menu'); }
beforeEach(() => {
  access.readOnly = false;
  window.localStorage.clear(); mocks.url = ''; vi.clearAllMocks();
  mocks.push.mockImplementation((url: string) => { mocks.url = url.split('?')[1] || ''; });
  mocks.getProjects.mockResolvedValue(projects);
  mocks.getProducts.mockImplementation((id: (string | number)) => Promise.resolve({ items: id === "00000000-0000-4000-8000-000000000002" ? [pump] : [other], total: 1 }));
  mocks.schedule.mockResolvedValue({ schedule: null });
  mocks.impact.mockResolvedValue({ sboms: 1, runs: 2, findings: 3, schedules: 0 });
  mocks.deleteProject.mockResolvedValue({}); mocks.deleteProduct.mockResolvedValue({});
});

describe('Projects selection and contextual applications', () => {
  it('shows the persisted project label while selection and links retain UUIDs', async () => {
    mocks.getProjects.mockResolvedValue([{ ...projects[0], display_id: 873 }]);
    setup();
    await screen.findByLabelText('Project ID 873');
    expect(screen.queryByText(`#${projects[0].id}`)).not.toBeInTheDocument();
    expect(mocks.getProducts).toHaveBeenCalledWith(projects[0].id, expect.any(AbortSignal));
  });
  it('loads only the initial project applications and switches the same table with URL selection', async () => {
    const { refresh } = setup();
    await screen.findByRole('button', { name: 'Select project Pump Security' });
    await waitFor(() => expect(within(appTable()).getByText('Pump Controller')).toBeInTheDocument());
    expect(mocks.getProducts).toHaveBeenCalledTimes(1);
    expect(mocks.getProducts).toHaveBeenCalledWith("00000000-0000-4000-8000-000000000002", expect.any(AbortSignal));
    expect(screen.getByRole('button', { name: 'Select project Pump Security' })).toHaveAttribute('aria-pressed', 'true');
    fireEvent.click(screen.getByRole('button', { name: 'Select project TestProject' })); refresh();
    await waitFor(() => expect(within(appTable()).getByText('Other application')).toBeInTheDocument());
    expect(screen.queryByRole('region', { name: 'Pump Security applications' })).not.toBeInTheDocument();
    expect(screen.getAllByRole('region', { name: / applications$/ })).toHaveLength(1);
    expect(mocks.push).toHaveBeenCalledWith("/projects?selectedProject=00000000-0000-4000-8000-000000000001", { scroll: false });
    expect(screen.getByRole('button', { name: 'Select project TestProject' })).toHaveAttribute('aria-pressed', 'true');
    mocks.url = "selectedProject=00000000-0000-4000-8000-000000000002"; refresh();
    await waitFor(() => expect(within(appTable()).getByText('Pump Controller')).toBeInTheDocument());
  });
  it('honors a bookmarked selection and passes it to creation and upload', async () => {
    mocks.url = "selectedProject=00000000-0000-4000-8000-000000000001"; setup();
    await waitFor(() => expect(within(appTable()).getByText('Other application')).toBeInTheDocument());
    expect(mocks.getProducts).toHaveBeenCalledWith("00000000-0000-4000-8000-000000000001", expect.any(AbortSignal));
    expect(mocks.getProducts).not.toHaveBeenCalledWith("00000000-0000-4000-8000-000000000002", expect.anything());
    fireEvent.click(screen.getByRole('button', { name: 'Create Application' }));
    expect(screen.getByRole('dialog', { name: 'Create application in TestProject' })).toBeInTheDocument();
  });
  it('keeps application edit, upload, soft-delete confirmation and SBOM links', async () => {
    setup(); await waitFor(() => expect(within(appTable()).getByText('Pump Controller')).toBeInTheDocument());
    expect(within(appTable()).getByRole('link', { name: "SBOM #8" })).toHaveAttribute('href', "/sboms/00000000-0000-4000-8000-000000000008");
    expect(within(appTable()).getByRole('link', { name: 'SBOM #8 · 1.0.0' })).toHaveAttribute('href', "/sboms/00000000-0000-4000-8000-000000000008");
    const actions = () => { fireEvent.click(within(appTable()).getByRole('button', { name: 'Actions for application Pump Controller' })); return screen.getByRole('menu'); };
    fireEvent.click(within(actions()).getByRole('menuitem', { name: 'Edit application' }));
    expect(screen.getByRole('dialog', { name: 'Edit application in Pump Security' })).toBeInTheDocument();
    fireEvent.click(within(actions()).getByRole('menuitem', { name: 'Upload SBOM' }));
    expect(screen.getByRole('dialog', { name: 'Upload to project 00000000-0000-4000-8000-000000000002 application 00000000-0000-4000-8000-000000000014' })).toBeInTheDocument();
    fireEvent.click(within(actions()).getByRole('menuitem', { name: 'Delete application' }));
    expect(screen.getByRole('dialog', { name: /Delete application/ })).toBeInTheDocument();
    expect(mocks.deleteProduct).not.toHaveBeenCalled();
    expect(screen.queryByLabelText('Delete permanently')).not.toBeInTheDocument();
  });
  it('retains project notification, schedule, edit and deletion impact confirmation', async () => {
    setup(); await screen.findByRole('button', { name: 'Select project Pump Security' });
    expect(within(projectMenu()).getByRole('menuitem', { name: 'Notification settings' })).toHaveAttribute('href', '/settings/notifications?scope=PROJECT&target=00000000-0000-4000-8000-000000000002');
    fireEvent.keyDown(screen.getByRole('menu'), { key: 'Escape' });
    expect(screen.getByRole('button', { name: 'Actions for project Pump Security' })).toHaveFocus();
    fireEvent.click(within(projectMenu()).getByRole('menuitem', { name: /^Configure periodic/ }));
    expect(screen.getByRole('dialog', { name: 'Schedule Pump Security' })).toBeInTheDocument();
    fireEvent.click(within(projectMenu()).getByRole('menuitem', { name: 'Edit Pump Security' }));
    expect(screen.getByRole('dialog', { name: 'Edit project Pump Security' })).toBeInTheDocument();
    fireEvent.click(within(projectMenu()).getByRole('menuitem', { name: 'Delete Pump Security' }));
    await screen.findByRole('dialog', { name: /Delete project/ });
    await waitFor(() => expect(mocks.impact).toHaveBeenCalledWith("00000000-0000-4000-8000-000000000002", expect.any(AbortSignal)));
    expect(mocks.deleteProject).not.toHaveBeenCalled();
  });
  it('filters projects and applications without fetching every project for counts', async () => {
    setup(); await waitFor(() => expect(within(appTable()).getByText('Pump Controller')).toBeInTheDocument());
    fireEvent.change(screen.getByLabelText('Search applications'), { target: { value: 'no-match' } });
    expect(within(appTable()).queryByText('Pump Controller')).not.toBeInTheDocument();
    fireEvent.click(screen.getByRole('button', { name: 'Clear application filters' }));
    fireEvent.change(screen.getByLabelText('Search'), { target: { value: 'TestProject' } });
    await waitFor(() => expect(within(appTable()).getByText('Other application')).toBeInTheDocument());
    expect(screen.queryByRole('button', { name: 'Select project Pump Security' })).not.toBeInTheDocument();
    expect(mocks.getProducts).toHaveBeenCalledTimes(2);
  });
  it('renders project and application empty states', async () => {
    mocks.getProducts.mockResolvedValue({ items: [], total: 0 }); setup();
    expect(await screen.findByText('No applications in this project')).toBeInTheDocument();
    expect(screen.getAllByRole('button', { name: 'Create Application' })).toHaveLength(2);
  });
  it('provides a new-project empty state', async () => {
    mocks.getProjects.mockResolvedValue([]); setup();
    expect(await screen.findByText(/No projects yet/)).toBeInTheDocument();
    fireEvent.click(screen.getByRole('button', { name: 'Create Project' }));
    expect(screen.getByRole('dialog', { name: 'New project' })).toBeInTheDocument();
    expect(mocks.getProducts).not.toHaveBeenCalled();
  });
  it('preserves dashboard scope filters and rejects URL IDs absent from the permitted result', async () => {
    mocks.url = "project=00000000-0000-4000-8000-000000000002&product=00000000-0000-4000-8000-000000000014&sbom=00000000-0000-4000-8000-000000000008&scanned=1&selectedProject=00000000-0000-4000-8000-0000000003e7";
    mocks.scanned.mockResolvedValue({ ids: ['00000000-0000-4000-8000-000000000002'] }); setup();
    await waitFor(() => expect(within(appTable()).getByText('Pump Controller')).toBeInTheDocument());
    expect(screen.queryByRole('button', { name: 'Select project TestProject' })).not.toBeInTheDocument();
    expect(mocks.scanned).toHaveBeenCalledWith({ projectId: "00000000-0000-4000-8000-000000000002", applicationId: "00000000-0000-4000-8000-000000000014", sbomId: "00000000-0000-4000-8000-000000000008" }, expect.any(AbortSignal));
    expect(mocks.getProducts).not.toHaveBeenCalledWith("00000000-0000-4000-8000-0000000003e7", expect.anything());
  });
});


it('honors bookmarked projects on later pages and retains project pagination', async () => {
  const many = Array.from({ length: 30 }, (_, index) => ({ ...projects[0], id: fixturePublicId(30 - index), project_name: `Project ${30 - index}` }));
  mocks.getProjects.mockResolvedValue(many); mocks.url = "selectedProject=00000000-0000-4000-8000-000000000001";
  const { refresh } = setup();
  await screen.findByRole('button', { name: 'Select project Project 1' });
  await waitFor(() => expect(screen.getByRole('button', { name: 'Select project Project 1' })).toHaveAttribute('aria-pressed', 'true'));
  expect(screen.getByRole('region', { name: 'Project 1 applications' })).toBeInTheDocument();
  mocks.url = ''; refresh();
  fireEvent.click(screen.getByRole('button', { name: 'Previous page' }));
  await screen.findByRole('button', { name: 'Select project Project 30' });
  expect(await screen.findByRole('region', { name: 'Project 30 applications' })).toBeInTheDocument();
});
it('keeps card selection keyboard accessible and status filtering contextual', async () => {
  setup(); await screen.findByRole('button', { name: 'Select project Pump Security' });
  fireEvent.change(screen.getByLabelText('Status'), { target: { value: 'inactive' } });
  await waitFor(() => expect(screen.getByRole('button', { name: 'Select project TestProject' })).toHaveAttribute('aria-pressed', 'true'));
  expect(screen.queryByRole('button', { name: 'Select project Pump Security' })).not.toBeInTheDocument();
});
it('updates application status filters and keeps mobile inventory cards available', async () => {
  mocks.getProducts.mockResolvedValue({ items: [pump, { ...other, project_id: "00000000-0000-4000-8000-000000000002" }], total: 2 });
  setup(); await waitFor(() => expect(within(appTable()).getByText('Pump Controller')).toBeInTheDocument());
  fireEvent.change(screen.getByLabelText('Application status'), { target: { value: 'inactive' } });
  expect(within(appTable()).queryByText('Pump Controller')).not.toBeInTheDocument();
  expect(within(appTable()).getByText('Other application')).toBeInTheDocument();
  expect(screen.getByRole('article', { name: 'Other application' })).toBeInTheDocument();
});

vi.mock('@/hooks/useAuth', async () => { const { authorizedAuth } = await import('@/test/authorizedAuth'); return { useAuth: () => ({ ...authorizedAuth(), hasPermission: (p: string) => access.readOnly ? p.endsWith(':read') : authorizedAuth().hasPermission(p) }) }; });

it('Viewer can select and view projects but cannot open creation or mutation dialogs', async () => {
  access.readOnly = true; setup();
  await screen.findByRole('button', { name: 'Select project Pump Security' });
  expect(screen.getByRole('button', { name: 'New Project' })).toBeDisabled();
  fireEvent.click(screen.getByRole('button', { name: 'New Project' }));
  expect(screen.queryByRole('dialog', { name: 'New project' })).not.toBeInTheDocument();
  await screen.findByRole('button', { name: 'Create Application' });
  expect(screen.getByRole('button', { name: 'Create Application' })).toBeDisabled();
  fireEvent.click(screen.getByRole('button', { name: 'Create Application' }));
  expect(screen.queryByRole('dialog')).not.toBeInTheDocument();
  projectMenu();
  const edit = screen.getByRole('menuitem', { name: 'Edit Pump Security' });
  expect(edit).toHaveAttribute('aria-disabled', 'true'); fireEvent.click(edit);
  expect(screen.queryByRole('dialog')).not.toBeInTheDocument(); expect(mocks.deleteProject).not.toHaveBeenCalled();
  expect(screen.getByRole('menuitem', { name: 'View project' })).not.toHaveAttribute('aria-disabled', 'true');
});
it('Viewer empty applications retain read-only guidance without an actionable empty-state CTA', async () => {
  access.readOnly = true; mocks.getProducts.mockResolvedValue({ items: [], total: 0 }); setup();
  await screen.findByText('No applications in this project');
  expect(screen.getAllByRole('button', { name: 'Create Application' })).toHaveLength(1);
  expect(screen.getByRole('button', { name: 'Create Application' })).toBeDisabled();
});

function fixturePublicId(value: number): string { return `00000000-0000-4000-8000-${value.toString(16).padStart(12, "0")}`; }

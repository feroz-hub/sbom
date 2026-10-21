// @vitest-environment jsdom
import { Suspense, type ReactNode } from 'react';
import { QueryClient, QueryClientProvider } from '@tanstack/react-query';
import { act, render, screen, waitFor, within } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { beforeEach, afterEach, describe, expect, it, vi } from 'vitest';
import type { PlatformAdministrator, TenantSummary } from '@/lib/api';

const state = vi.hoisted(() => ({
  allowed: true,
  summary: vi.fn(), tenants: vi.fn(), detail: vi.fn(), create: vi.fn(), status: vi.fn(),
  admins: vi.fn(), grant: vi.fn(), revoke: vi.fn(), recover: vi.fn(),
  success: vi.fn(), error: vi.fn(), push: vi.fn(),
}));
vi.mock('next/navigation', () => ({ usePathname: () => '/platform', useRouter: () => ({ push: state.push }) }));
vi.mock('@/hooks/useAuth', () => ({ useAuth: () => ({
  user: { userId: '00000000-0000-4000-8000-000000000001', isPlatformAdmin: true }, isLoading: false,
  hasPermission: () => state.allowed,
}) }));
vi.mock('@/hooks/useNotifications', () => ({ useNotifications: () => ({
  showSuccess: state.success, showError: state.error, showInfo: vi.fn(), showWarning: vi.fn(),
}) }));
vi.mock('@/components/layout/TopBar', () => ({ TopBar: ({ title, action }: { title: string; action?: ReactNode }) => <header><h1>{title}</h1>{action}</header> }));
// Candidate discovery is independent of cache synchronization. Exercise the actual forms and mutations.
vi.mock('@/components/admin/UserSearchCombobox', () => ({ UserSearchCombobox: ({ onSelect }: { onSelect: (user: unknown) => void }) =>
  <button type="button" onClick={() => onSelect({ id: '00000000-0000-4000-8000-000000000003', display_name: 'Candidate', email: 'candidate@example.test', status: 'ACTIVE', email_verified: true })}>Select candidate</button>,
}));
vi.mock('@/lib/api', async original => ({
  ...(await original<typeof import('@/lib/api')>()),
  getPlatformSummary: () => state.summary(), listPlatformTenants: (...args: unknown[]) => state.tenants(...args),
  getPlatformTenant: (...args: unknown[]) => state.detail(...args), createPlatformTenant: (...args: unknown[]) => state.create(...args),
  updatePlatformTenantStatus: (...args: unknown[]) => state.status(...args), getPlatformAdministrators: () => state.admins(),
  grantPlatformAdministrator: (...args: unknown[]) => state.grant(...args), revokePlatformAdministrator: (...args: unknown[]) => state.revoke(...args),
  recoverPlatformTenantAdmin: (...args: unknown[]) => state.recover(...args),
}));
import Dashboard from './page';
import TenantList from '../settings/platform/tenants/page';
import TenantDetail from '../settings/platform/tenants/[tenantId]/page';
import Administrators from '../settings/platform/page';

const initialSummary = { total_tenants: 4, active_tenants: 2, pending_tenants: 1, disabled_tenants: 1,
  total_memberships: 7, tenants_without_admin: 0, platform_admins: 1 };
const tenant: TenantSummary = { id: "00000000-0000-4000-8000-000000000007", name: 'Test Tenant', slug: 'test-tenant', external_iam_tenant_id: null, status: 'PENDING', created_at: '2026-10-01T00:00:00Z', member_count: 2, current_administrators: [] };
const admin: PlatformAdministrator = { grant_id: 3, user_id: '00000000-0000-4000-8000-000000000003', email: 'candidate@example.test', display_name: 'Candidate',
  role: 'PLATFORM_ADMIN', grant_status: 'ACTIVE', local_status: 'ACTIVE', email_verified: true,
  verification_required: false, is_effective: true, created_at: '2026-10-01T00:00:00Z' };
let client: QueryClient;
let detailParams: Promise<{ tenantId: string }>;
function view(node: ReactNode) { return <QueryClientProvider client={client}><Suspense fallback={<p>Loading</p>}>{node}</Suspense></QueryClientProvider>; }
async function renderView(node: ReactNode) {
  let result!: ReturnType<typeof render>;
  await act(async () => { result = render(view(node)); });
  return result;
}
function detailPage() { return <TenantDetail params={detailParams} />; }
function seed() {
  client.setQueryData(['platform-summary'], initialSummary);
  client.setQueryData(['platform-tenants', 'overview'], [tenant]);
  client.setQueryData(['platform-tenants', '', 1], [tenant]);
  client.setQueryData(['platform-tenants', 'filtered', 2], [tenant]);
  client.setQueryData(['platform-tenant', "00000000-0000-4000-8000-000000000007"], tenant);
  client.setQueryData(['platform-tenant', "00000000-0000-4000-8000-000000000063"], { ...tenant, id: "00000000-0000-4000-8000-000000000063" });
  client.setQueryData(['platform-administrators'], []);
  client.setQueryData(['sboms', 'tenant-7'], ['business data']);
}
function expectMetric(title: string, value: number) { expect(screen.getByLabelText(`${title}: ${value}`)).toBeInTheDocument(); }
async function createTenant() {
  const user = userEvent.setup();
  await user.click(screen.getByRole('button', { name: 'Create Tenant' }));
  const form = screen.getByRole('dialog', { name: 'Create tenant' });
  await user.type(within(form).getByLabelText('Name'), 'New Tenant');
  await user.click(within(form).getByRole('button', { name: 'Select candidate' }));
  await user.click(within(form).getByRole('button', { name: 'Create Tenant' }));
  return form;
}
async function statusChange(from: 'PENDING' | 'ACTIVE', entry: 'list' | 'detail') {
  const user = userEvent.setup();
  if (entry === 'detail') {
    await user.click(await screen.findByRole('button', { name: from === 'ACTIVE' ? 'Disable tenant' : 'Enable tenant' }));
    await user.click(screen.getByRole('button', { name: 'Confirm' }));
  } else {
    await user.click(screen.getByRole('button', { name: from === 'ACTIVE' ? 'Disable Test Tenant' : 'Enable Test Tenant' }));
    if (from === 'ACTIVE') await user.click(screen.getByRole('button', { name: 'Disable tenant' }));
  }
}
beforeEach(() => {
  vi.clearAllMocks(); state.allowed = true;
  client = new QueryClient({ defaultOptions: { queries: { staleTime: 5 * 60_000, refetchOnWindowFocus: false, retry: false }, mutations: { retry: false } } });
  detailParams = Promise.resolve({ tenantId: "00000000-0000-4000-8000-000000000007" });
  state.summary.mockResolvedValue(initialSummary); state.tenants.mockResolvedValue([tenant]); state.detail.mockResolvedValue(tenant);
  state.admins.mockResolvedValue([]); state.recover.mockResolvedValue({}); seed();
});
afterEach(() => client.clear());

describe('platform control-plane cache integration', () => {
  it.each(['PENDING', 'ACTIVE'] as const)('creation of %s invalidates fresh inactive summary and refetches on dashboard return', async status => {
    const created = { ...tenant, id: "00000000-0000-4000-8000-000000000008", name: 'New Tenant', status };
    const authoritative = { ...initialSummary, total_tenants: 5,
      pending_tenants: status === 'PENDING' ? 2 : 1, active_tenants: status === 'ACTIVE' ? 3 : 2 };
    state.create.mockImplementation(async () => {
      state.summary.mockResolvedValue(authoritative); state.tenants.mockResolvedValue([tenant, created]); return created;
    });
    const mounted = await renderView(<Dashboard />);
    expectMetric('Total Tenants', 4); expect(state.summary).not.toHaveBeenCalled();
    await act(async () => { mounted.rerender(view(<TenantList />)); });
    await createTenant();
    await waitFor(() => expect(state.push).toHaveBeenCalledWith("/settings/platform/tenants/00000000-0000-4000-8000-000000000008"));
    expect(await screen.findByText('New Tenant')).toBeInTheDocument();
    expect(client.getQueryState(['platform-summary'])?.isInvalidated).toBe(true);
    expect(client.getQueryState(['platform-tenants', 'overview'])?.isInvalidated).toBe(true);
    expect(client.getQueryState(['platform-tenants', 'filtered', 2])?.isInvalidated).toBe(true);
    expect(state.summary).not.toHaveBeenCalled(); // invalidating an inactive cache must not execute its query
    await act(async () => { mounted.rerender(view(<Dashboard />)); });
    await screen.findByLabelText('Total Tenants: 5');
    expectMetric('Pending Setup', authoritative.pending_tenants); expectMetric('Active Tenants', authoritative.active_tenants);
    expect(state.summary).toHaveBeenCalledTimes(1);
    expect(client.getQueryData(['platform-summary'])).toEqual(authoritative);
  });

  it.each(['list', 'detail'] as const)('activation and disabling from %s refresh detail, overview and backend metrics', async entry => {
    state.status.mockImplementation(async (_id, status) => {
      const updated = { ...tenant, status };
      state.detail.mockResolvedValue(updated); state.tenants.mockResolvedValue([updated]);
      state.summary.mockResolvedValue({ ...initialSummary, pending_tenants: 0,
        active_tenants: status === 'ACTIVE' ? 3 : 2, disabled_tenants: status === 'DISABLED' ? 2 : 1 });
      return { tenant_id: "00000000-0000-4000-8000-000000000007", status };
    });
    const mounted = await renderView(entry === 'list' ? <TenantList /> : detailPage());
    await statusChange('PENDING', entry);
    await waitFor(() => expect(client.getQueryState(['platform-summary'])?.isInvalidated).toBe(true));
    if (entry === 'list') {
      await screen.findByText('Active');
      expect(client.getQueryState(['platform-tenant', "00000000-0000-4000-8000-000000000007"])?.isInvalidated).toBe(true);
      await act(async () => { mounted.rerender(view(detailPage())); });
    }
    await screen.findByRole('button', { name: 'Disable tenant' });
    expect(client.getQueryData<TenantSummary>(['platform-tenant', "00000000-0000-4000-8000-000000000007"])?.status).toBe('ACTIVE');
    await act(async () => { mounted.rerender(view(<Dashboard />)); });
    await screen.findByLabelText('Active Tenants: 3'); expectMetric('Pending Setup', 0);
    expect(screen.getByRole('row', { name: /Test Tenant/ })).toHaveTextContent('Active');
    await act(async () => { mounted.rerender(view(entry === 'list' ? <TenantList /> : detailPage())); });
    await statusChange('ACTIVE', entry);
    await waitFor(() => expect(client.getQueryState(['platform-summary'])?.isInvalidated).toBe(true));
    if (entry === 'list') { await screen.findByText('Disabled'); await act(async () => { mounted.rerender(view(detailPage())); }); }
    await screen.findByRole('button', { name: 'Enable tenant' });
    expect(client.getQueryData<TenantSummary>(['platform-tenant', "00000000-0000-4000-8000-000000000007"])?.status).toBe('DISABLED');
    await act(async () => { mounted.rerender(view(<Dashboard />)); });
    await screen.findByLabelText('Disabled Tenants: 2'); expectMetric('Active Tenants', 2); expectMetric('Pending Setup', 0);
    expect(screen.getByRole('row', { name: /Test Tenant/ })).toHaveTextContent('Disabled');
    expect(state.status.mock.calls).toEqual([['00000000-0000-4000-8000-000000000007', 'ACTIVE'], ['00000000-0000-4000-8000-000000000007', 'DISABLED']]);
    expect(client.getQueryState(['platform-tenant', "00000000-0000-4000-8000-000000000063"])?.isInvalidated).toBe(false);
    expect(client.getQueryState(['sboms', 'tenant-7'])?.isInvalidated).toBe(false);
  });

  it('grant and revoke refresh active administrator list and summary without touching tenant business data', async () => {
    state.grant.mockImplementation(async () => { state.admins.mockResolvedValue([admin]); state.summary.mockResolvedValue({ ...initialSummary, platform_admins: 2 }); return admin; });
    state.revoke.mockImplementation(async () => { state.admins.mockResolvedValue([]); state.summary.mockResolvedValue(initialSummary); });
    await renderView(<><Dashboard /><Administrators /></>);
    expectMetric('Platform Administrators', 1);
    const user = userEvent.setup();
    await user.click(screen.getByRole('button', { name: 'Select candidate' }));
    await user.click(screen.getByRole('button', { name: 'Grant Platform Administrator' }));
    await screen.findByLabelText('Platform Administrators: 2');
    expect(await screen.findByText('candidate@example.test')).toBeInTheDocument();
    expect(client.getQueryData(['platform-administrators'])).toEqual([admin]);
    await user.click(screen.getByRole('button', { name: 'Revoke' }));
    await user.click(screen.getByRole('button', { name: 'Revoke authority' }));
    await screen.findByLabelText('Platform Administrators: 1');
    expect(await screen.findByText('No platform administrators found.')).toBeInTheDocument();
    expect(state.summary).toHaveBeenCalledTimes(2); expect(state.admins).toHaveBeenCalledTimes(2);
    expect(state.grant).toHaveBeenCalledWith('00000000-0000-4000-8000-000000000003'); expect(state.revoke).toHaveBeenCalledWith(3);
    expect(state.tenants).not.toHaveBeenCalled();
    expect(client.getQueryState(['sboms', 'tenant-7'])?.isInvalidated).toBe(false);
  });

  it('administrator recovery retains summary/list/detail refresh and success notification', async () => {
    state.recover.mockImplementation(async () => {
      state.detail.mockResolvedValue({ ...tenant, member_count: 3, current_administrators: [{ user_id: '00000000-0000-4000-8000-000000000003', display_name: 'Candidate', email: 'candidate@example.test' }] });
      return {};
    });
    await renderView(detailPage());
    const user = userEvent.setup(); await user.click(screen.getByRole('button', { name: 'Select candidate' }));
    await user.click(screen.getByRole('button', { name: 'Assign Tenant Administrator' }));
    expect(await screen.findByText('3 memberships · 1 active Tenant Administrators')).toBeInTheDocument();
    expect(state.success).toHaveBeenCalledWith('Tenant Administrator recovery completed.');
    expect(client.getQueryState(['platform-summary'])?.isInvalidated).toBe(true);
    expect(client.getQueryState(['platform-tenants', 'overview'])?.isInvalidated).toBe(true);
  });

  it.each(['create', 'status', 'grant', 'revoke'] as const)('failed %s preserves metrics and form/confirmation state without success or invalidation', async operation => {
    state[operation].mockRejectedValue(new Error('Mutation rejected'));
    if (operation === 'revoke') client.setQueryData(['platform-administrators'], [admin]);
    await renderView(operation === 'create' || operation === 'status' ? <TenantList /> : <Administrators />);
    const user = userEvent.setup(); let form: HTMLElement | undefined;
    if (operation === 'create') form = await createTenant();
    else if (operation === 'status') await statusChange('PENDING', 'list');
    else if (operation === 'grant') { await user.click(screen.getByRole('button', { name: 'Select candidate' })); await user.click(screen.getByRole('button', { name: 'Grant Platform Administrator' })); }
    else { await user.click(screen.getByRole('button', { name: 'Revoke' })); await user.click(screen.getByRole('button', { name: 'Revoke authority' })); }
    await waitFor(() => expect(state.error).toHaveBeenCalled());
    expect(state.success).not.toHaveBeenCalled(); expect(state.push).not.toHaveBeenCalled();
    expect(client.getQueryData(['platform-summary'])).toEqual(initialSummary);
    for (const query of client.getQueryCache().getAll()) expect(query.state.isInvalidated).toBe(false);
    expect(state.summary).not.toHaveBeenCalled(); expect(state.tenants).not.toHaveBeenCalled(); expect(state.admins).not.toHaveBeenCalled();
    if (form) expect(within(form).getByLabelText('Name')).toHaveValue('New Tenant');
    if (operation === 'grant') expect(screen.getByRole('button', { name: 'Grant Platform Administrator' })).toBeInTheDocument();
    if (operation === 'revoke') expect(screen.getByRole('dialog')).toBeInTheDocument();
  });

  it.each(['dashboard', 'tenants', 'detail', 'administrators'] as const)('unauthorized %s executes no platform query', async page => {
    state.allowed = false;
    await renderView(page === 'dashboard' ? <Dashboard /> : page === 'tenants' ? <TenantList /> : page === 'detail' ? detailPage() : <Administrators />);
    await screen.findByRole('alert');
    for (const fn of [state.summary, state.tenants, state.detail, state.admins]) expect(fn).not.toHaveBeenCalled();
  });
});

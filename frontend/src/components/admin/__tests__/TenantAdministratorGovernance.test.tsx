// @vitest-environment jsdom
import { QueryClient, QueryClientProvider } from '@tanstack/react-query';
import { act, render, screen, waitFor, within } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { beforeEach, expect, it, vi } from 'vitest';
import { TenantAdministratorGovernance } from '../TenantAdministratorGovernance';
import { ApiError, type TenantAdministratorDirectory } from '@/lib/api';

const tenant = '00000000-0000-4000-8000-000000000007';
const membership = '00000000-0000-4000-8000-000000000008';
const state = vi.hoisted(() => ({
  allowed: true, platform: true, loading: false, userId: '00000000-0000-4000-8000-000000000001',
  get: vi.fn(), revoke: vi.fn(), deactivate: vi.fn(), remove: vi.fn(), success: vi.fn(), error: vi.fn(), refresh: vi.fn(),
}));
vi.mock('@/hooks/useAuth', () => ({ useAuth: () => ({
  user: { userId: state.userId }, isPlatformContext: state.platform, isLoading: state.loading,
  isTenantContextLoading: false, activeTenantId: null, bootstrapState: 'ready',
  hasPermission: () => state.allowed, refreshSession: state.refresh,
}) }));
vi.mock('@/hooks/useNotifications', () => ({ useNotifications: () => ({ showSuccess: state.success, showError: state.error }) }));
vi.mock('@/lib/api', async original => ({
  ...await original<typeof import('@/lib/api')>(),
  getPlatformTenantAdministrators: (...args: unknown[]) => state.get(...args),
  revokePlatformTenantAdministrator: (...args: unknown[]) => state.revoke(...args),
  deactivatePlatformTenantAdministrator: (...args: unknown[]) => state.deactivate(...args),
  removePlatformTenantAdministrator: (...args: unknown[]) => state.remove(...args),
}));

let data: TenantAdministratorDirectory;
beforeEach(() => {
  vi.clearAllMocks(); state.allowed = true; state.platform = true; state.loading = false;
  state.userId = '00000000-0000-4000-8000-000000000001';
  data = {
    tenant_id: tenant,
    administrators: [{ tenant_id: tenant, membership_id: membership, user_id: '00000000-0000-4000-8000-000000000009',
      display_name: 'Alex Admin', email: 'alex@example.test', status: 'ACTIVE', account_status: 'ACTIVE', is_effective: true,
      roles: ['TENANT_ADMIN', 'SECURITY_ANALYST'], primary_role: 'TENANT_ADMIN', role_assignment_version: 3 }],
    replacement_roles: [{ code: 'VIEWER', name: 'Viewer', scope: 'TENANT' }, { code: 'SECURITY_ANALYST', name: 'Security Analyst', scope: 'TENANT' },
      { code: 'CUSTOM_REVIEWER', name: 'Custom Reviewer', scope: 'TENANT' }],
  };
  state.get.mockImplementation(() => Promise.resolve(structuredClone(data)));
  state.revoke.mockReset().mockResolvedValue({}); state.deactivate.mockReset().mockResolvedValue({}); state.remove.mockReset().mockResolvedValue(undefined);
});
function setup(id = tenant) {
  const qc = new QueryClient({ defaultOptions: { queries: { retry: false, gcTime: Infinity }, mutations: { retry: 2 } } });
  const view = (currentId: string) => <QueryClientProvider client={qc}><TenantAdministratorGovernance tenantId={currentId} tenantName={currentId === tenant ? 'Olympus' : 'MedTech'} /></QueryClientProvider>;
  return { ...render(view(id)), user: userEvent.setup(), qc, view };
}
async function open(operation = 'Revoke Admin Role') {
  await screen.findByRole('heading', { name: 'Alex Admin' });
  await userEvent.click(screen.getByRole('button', { name: operation }));
  return within(screen.getByRole('dialog'));
}

it('shows effective administrator identity, membership and additional active roles', async () => {
  setup(); await screen.findByText('Effective administrator');
  expect(screen.getByText('alex@example.test')).toBeInTheDocument();
  expect(screen.getByText('ACTIVE')).toBeInTheDocument();
  expect(screen.getByText('Security Analyst')).toBeInTheDocument();
  expect(screen.getByRole('heading', { name: 'Tenant Administrators' })).toBeInTheDocument();
  expect(state.get).toHaveBeenCalledWith(tenant, expect.any(AbortSignal));
});
it.each(['Tenant Admin', 'Security Analyst', 'Developer', 'Viewer'])('does not expose governance to %s without platform permission', () => {
  state.allowed = false; setup();
  expect(screen.queryByRole('button')).not.toBeInTheDocument(); expect(state.get).not.toHaveBeenCalled();
});
it('requires platform context even with stale platform permissions', () => {
  state.platform = false; setup(); expect(state.get).not.toHaveBeenCalled(); expect(screen.queryByText('Tenant Administrators')).not.toBeInTheDocument();
});
it('waits for resolved permissions', () => {
  state.loading = true; setup(); expect(state.get).not.toHaveBeenCalled();
});
it('requires an explicit replacement for primary admin, includes custom roles and excludes platform/admin roles', async () => {
  data.replacement_roles.push({ code: 'PLATFORM_ADMIN', name: 'Platform Admin', scope: 'TENANT' }, { code: 'TENANT_ADMIN', name: 'Tenant Admin', scope: 'TENANT' });
  const { user } = setup(); const dialog = await open();
  const select = dialog.getByRole('combobox', { name: 'Replacement primary role (required)' });
  expect(select).toHaveValue(''); expect(dialog.getByRole('button', { name: 'Revoke Admin Role' })).toBeDisabled();
  expect(dialog.getByRole('option', { name: 'Custom Reviewer' })).toBeInTheDocument();
  expect(dialog.getByRole('option', { name: 'Security Analyst (already assigned)' })).toBeInTheDocument();
  expect(dialog.queryByRole('option', { name: 'Platform Admin' })).not.toBeInTheDocument();
  expect(dialog.queryByRole('option', { name: 'Tenant Admin' })).not.toBeInTheDocument();
  await user.selectOptions(select, 'CUSTOM_REVIEWER');
  await user.type(dialog.getByRole('textbox', { name: 'Administrative reason (optional)' }), 'Approved reassignment');
  await user.click(dialog.getByRole('button', { name: 'Revoke Admin Role' }));
  await waitFor(() => expect(state.revoke).toHaveBeenCalledWith(tenant, membership, { expected_version: 3, replacement_primary_role_code: 'CUSTOM_REVIEWER', reason: 'Approved reassignment' }));
  await waitFor(() => expect(screen.queryByRole('dialog')).not.toBeInTheDocument());
  expect(state.success).toHaveBeenCalledWith('Tenant Administrator role revoked.');
  await waitFor(() => expect(state.get.mock.calls.length).toBeGreaterThan(1));
});
it('revokes secondary administrator authority without a replacement or implicit Viewer grant', async () => {
  data.administrators[0].primary_role = 'SECURITY_ANALYST'; setup(); const dialog = await open();
  expect(dialog.queryByRole('combobox')).not.toBeInTheDocument();
  await userEvent.click(dialog.getByRole('button', { name: 'Revoke Admin Role' }));
  await waitFor(() => expect(state.revoke).toHaveBeenCalledWith(tenant, membership, { expected_version: 3 }));
});
it('blocks primary revocation when the catalogue has no ordinary assignable roles', async () => {
  data.replacement_roles = []; setup(); const dialog = await open();
  expect(dialog.getByText(/No assignable ordinary tenant roles/)).toBeInTheDocument();
  expect(dialog.getByRole('button', { name: 'Revoke Admin Role' })).toBeDisabled();
});
it('requires review of a stale conflict and never retries with a new version automatically', async () => {
  state.revoke.mockRejectedValueOnce(new ApiError('Stale version', 409, 'TENANT_ROLE_VERSION_CONFLICT', { current_version: 4 }));
  const { user } = setup(); const dialog = await open();
  await user.selectOptions(dialog.getByRole('combobox'), 'VIEWER');
  data.administrators[0].role_assignment_version = 4;
  await user.click(dialog.getByRole('button', { name: 'Revoke Admin Role' }));
  await screen.findByRole('alert');
  expect(screen.getByRole('alert')).toHaveTextContent('Administrator information has changed');
  await dialog.findByRole('button', { name: 'Review updated administrator' });
  expect(state.revoke).toHaveBeenCalledTimes(1);
  expect(dialog.getByRole('button', { name: 'Revoke Admin Role' })).toBeDisabled();
  await user.click(dialog.getByRole('button', { name: 'Review updated administrator' }));
  expect(dialog.getByRole('combobox')).toHaveValue('');
  await user.selectOptions(dialog.getByRole('combobox'), 'VIEWER');
  await user.click(dialog.getByRole('button', { name: 'Revoke Admin Role' }));
  await waitFor(() => expect(state.revoke).toHaveBeenLastCalledWith(tenant, membership, { expected_version: 4, replacement_primary_role_code: 'VIEWER' }));
});
it('blocks an open dialog when a background refresh changes the administrator state', async () => {
  const { qc, user } = setup(); const dialog = await open();
  await user.selectOptions(dialog.getByRole('combobox'), 'VIEWER');
  data.administrators[0].role_assignment_version = 4;
  await act(async () => { qc.setQueryData(['platform-tenant-administrators', tenant, state.userId], structuredClone(data)); });
  await waitFor(() => expect(dialog.getByRole('button', { name: 'Revoke Admin Role' })).toBeDisabled());
  expect(dialog.getByRole('button', { name: 'Review updated administrator' })).toBeInTheDocument();
  expect(state.revoke).not.toHaveBeenCalled();
});
it('shows last-effective-admin protection without removing administrator records', async () => {
  state.remove.mockRejectedValueOnce(new ApiError('Last admin', 409, 'IAM_LAST_TENANT_ADMIN_PROTECTED'));
  setup(); const dialog = await open('Remove From Tenant'); await userEvent.click(dialog.getByRole('button', { name: 'Remove From Tenant' }));
  await waitFor(() => expect(screen.getByRole('alert')).toHaveTextContent('must retain an effective Tenant Administrator'));
  expect(screen.getByRole('heading', { name: 'Alex Admin' })).toBeInTheDocument(); expect(state.success).not.toHaveBeenCalled();
});
it.each([
  [401, 'Your session has expired'], [403, 'You do not have permission'],
  [404, 'no longer available'], [422, 'Select a valid ordinary replacement role'],
] as const)('shows actionable HTTP %i feedback without a success state', async (status, message) => {
  state.deactivate.mockRejectedValue(new ApiError('Select a valid ordinary replacement role', status));
  setup(); const dialog = await open('Deactivate Membership'); await userEvent.click(dialog.getByRole('button', { name: 'Deactivate Membership' }));
  await waitFor(() => expect(screen.getByRole('alert')).toHaveTextContent(message));
  expect(state.success).not.toHaveBeenCalled();
  if (status === 401 || status === 403) expect(dialog.getByRole('button', { name: 'Deactivate Membership' })).toBeDisabled();
});
it('deactivates only the selected membership, preserving and displaying its roles', async () => {
  const { user } = setup(); const dialog = await open('Deactivate Membership');
  expect(dialog.getByText(/Assigned tenant roles are preserved/)).toBeInTheDocument();
  await user.type(dialog.getByRole('textbox'), ' Temporary suspension ');
  data.administrators[0].status = 'DISABLED'; data.administrators[0].is_effective = false;
  await user.click(dialog.getByRole('button', { name: 'Deactivate Membership' }));
  await waitFor(() => expect(state.deactivate).toHaveBeenCalledWith(tenant, membership, 'Temporary suspension'));
  await screen.findByText('Administrator assignment preserved · not effective');
  expect(screen.getByText('DISABLED')).toBeInTheDocument();
  expect(screen.queryByRole('button', { name: 'Deactivate Membership' })).not.toBeInTheDocument();
  expect(screen.getByRole('button', { name: 'Remove From Tenant' })).toBeInTheDocument();
});
it('removes a tenant membership after server success and refreshes all control-plane summaries', async () => {
  const { qc, user } = setup();
  qc.setQueryData(['platform-summary'], { total_memberships: 2 }); qc.setQueryData(['platform-tenants', 'all'], []); qc.setQueryData(['platform-tenant', tenant], {});
  const dialog = await open('Remove From Tenant');
  expect(dialog.getByText(membership)).toBeInTheDocument();
  expect(dialog.getByText(/global account and memberships in other tenants are not deleted/)).toBeInTheDocument();
  await user.type(dialog.getByRole('textbox'), 'Approved removal');
  data.administrators = [];
  await user.click(dialog.getByRole('button', { name: 'Remove From Tenant' }));
  await waitFor(() => expect(state.remove).toHaveBeenCalledWith(tenant, membership, 'Approved removal'));
  await screen.findByText(/No administrator memberships/);
  expect(qc.getQueryState(['platform-summary'])?.isInvalidated).toBe(true);
  expect(qc.getQueryState(['platform-tenants', 'all'])?.isInvalidated).toBe(true);
  expect(qc.getQueryState(['platform-tenant', tenant])?.isInvalidated).toBe(true);
});
it('prevents double submissions and keeps the record until the server confirms removal', async () => {
  let resolve!: () => void; state.remove.mockImplementation(() => new Promise<void>(done => { resolve = done; }));
  const { user } = setup(); const dialog = await open('Remove From Tenant');
  const button = dialog.getByRole('button', { name: 'Remove From Tenant' });
  await user.dblClick(button);
  expect(state.remove).toHaveBeenCalledTimes(1); expect(button).toBeDisabled();
  expect(screen.getByRole('heading', { name: 'Alex Admin' })).toBeInTheDocument();
  await user.keyboard('{Escape}'); expect(screen.getByRole('dialog')).toBeInTheDocument();
  await act(async () => resolve());
  await waitFor(() => expect(screen.queryByRole('dialog')).not.toBeInTheDocument());
});
it('cancels with Escape, restores trigger focus and performs no mutation', async () => {
  const { user } = setup(); await open('Remove From Tenant');
  await user.keyboard('{Escape}');
  expect(screen.queryByRole('dialog')).not.toBeInTheDocument();
  expect(screen.getByRole('button', { name: 'Remove From Tenant' })).toHaveFocus();
  expect(state.remove).not.toHaveBeenCalled();
});
it('supports keyboard navigation and labelled reason and replacement fields', async () => {
  const { user } = setup(); await screen.findByRole('heading', { name: 'Alex Admin' });
  screen.getByRole('button', { name: 'Revoke Admin Role' }).focus(); await user.keyboard('{Enter}');
  const dialog = within(screen.getByRole('dialog'));
  expect(dialog.getByRole('combobox')).toHaveAccessibleName('Replacement primary role (required)');
  expect(dialog.getByRole('textbox')).toHaveAttribute('maxLength', '512');
  await user.click(dialog.getByRole('button', { name: 'Cancel' })); expect(state.revoke).not.toHaveBeenCalled();
});
it('loads disabled administrators separately from effective authority', async () => {
  data.administrators[0].status = 'DISABLED'; data.administrators[0].is_effective = false;
  setup(); await screen.findByText('DISABLED');
  expect(screen.queryByText('Effective administrator')).not.toBeInTheDocument();
  expect(screen.getByText(/does not currently provide effective administrator access/)).toBeInTheDocument();
});
it('resets dialogs on tenant navigation and rejects a late response from the previous tenant', async () => {
  let resolve!: () => void; state.remove.mockImplementation(() => new Promise<void>(done => { resolve = done; }));
  const { rerender, view, user } = setup(); const dialog = await open('Remove From Tenant');
  await user.click(dialog.getByRole('button', { name: 'Remove From Tenant' }));
  data = { tenant_id: '00000000-0000-4000-8000-000000000099', administrators: [], replacement_roles: [] };
  rerender(view(data.tenant_id));
  expect(screen.queryByRole('dialog')).not.toBeInTheDocument();
  expect(screen.queryByRole('heading', { name: 'Alex Admin' })).not.toBeInTheDocument();
  await act(async () => resolve());
  expect(state.success).not.toHaveBeenCalled(); await screen.findByText(/No administrator memberships/);
});
it('drops privileged controls when authorization changes', async () => {
  const { rerender, view } = setup(); await open(); state.allowed = false; rerender(view(tenant));
  expect(screen.queryByRole('dialog')).not.toBeInTheDocument(); expect(screen.queryByRole('button')).not.toBeInTheDocument();
});
it('refreshes the current account authorization presentation when it is affected', async () => {
  data.administrators[0].user_id = state.userId;
  setup(); const dialog = await open('Deactivate Membership'); await userEvent.click(dialog.getByRole('button', { name: 'Deactivate Membership' }));
  await waitFor(() => expect(state.refresh).toHaveBeenCalledWith({ authorizationChanged: true }));
});
it('shows loading, empty and fetch failure states without controls for stale cached data', async () => {
  let reject!: (error: Error) => void; state.get.mockImplementation(() => new Promise((_resolve, fail) => { reject = fail; }));
  setup(); expect(screen.getByRole('status')).toHaveTextContent('Loading administrator memberships');
  await act(async () => reject(new ApiError('Permission denied', 403)));
  expect(await screen.findByRole('alert')).toHaveTextContent('You do not have permission');
  expect(screen.queryByRole('button', { name: 'Remove From Tenant' })).not.toBeInTheDocument();
});

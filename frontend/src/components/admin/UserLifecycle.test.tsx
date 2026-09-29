// @vitest-environment jsdom
import { ToastProvider } from '@/hooks/useToast';
import type { ReactElement } from 'react';
import { cleanup, fireEvent, render as rtlRender, screen, waitFor } from '@testing-library/react';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import UserLifecycle from './UserLifecycle';
import { axe } from 'vitest-axe';
let platform = true;
let tenant = '1';
const permission = (p: string) => platform || p.startsWith('tenant:');
vi.mock('@/hooks/useAuth', () => ({ useAuth: () => ({ user: { isPlatformAdmin: platform, tenantId: Number(tenant) }, activeTenantId: tenant, hasPermission: permission }) }));
const listTenants = vi.hoisted(() => vi.fn());
vi.mock('@/lib/api', () => ({ listPlatformTenants: listTenants }));
const member = { membership_id: 12, tenant_id: 1, tenant_name: 'Olympus', membership_status: 'ACTIVE', roles: ['DEVELOPER', 'VIEWER'], primary_role: 'VIEWER', role_assignment_version: 4 };
const second = { ...member, membership_id: 15, tenant_id: 2, tenant_name: 'Hospital B' };
const user = { id: 42, user_id: 42, display_name: 'John Smith', first_name: 'John', last_name: 'Smith', email: 'john@example.test', phone: '+1234567', account_status: 'ACTIVE', providers: ['NATIVE'], email_verified: true, created_at: '2026-09-01', updated_at: '2026-09-01', last_login_at: null, activity: { items: [{ id: 1, action: 'USER_UPDATED', outcome: 'SUCCESS', timestamp: 'today' }], total: 1 } };
let providers = ['NATIVE'];
let account = 'ACTIVE';
let failed = false;
let pending = false;
let fetchMock: ReturnType<typeof vi.fn>;
beforeEach(() => {
  listTenants.mockReset().mockResolvedValue([{ id: 2, name: 'Hospital B', slug: 'hospital-b', status: 'ACTIVE' }]);
  platform = true; providers = ['NATIVE']; tenant = '1'; account = 'ACTIVE'; failed = false; pending = false;
  fetchMock = vi.fn(async (url: string, options: RequestInit) => {
    if (pending) return new Promise(() => {});
    if (failed) return Response.json({ detail: 'Access denied' }, { status: 403 });
    if (options.method !== 'GET') return Response.json(url.includes('resend') ? { delivery: { status: 'sent' } } : {});
    const data = { ...user, providers, account_status: account, ...(platform ? { tenant_memberships: [member, second] } : member) };
    return Response.json(url.includes('?') ? { items: [data], total: 1 } : data);
  });
  vi.stubGlobal('fetch', fetchMock);
});
afterEach(() => { cleanup(); vi.unstubAllGlobals(); });
async function openUser() { render(<UserLifecycle />); fireEvent.click(await screen.findByRole('button', { name: 'John Smith' })); await screen.findByRole('heading', { name: 'John Smith' }); }
const writes = () => fetchMock.mock.calls.filter(call => call[1].method !== 'GET');
it.each(['', '2', 'all'])('loads platform directory without inherited tenant or empty search (%s)', async staleTenant => {
  tenant = staleTenant;
  render(<UserLifecycle />);
  await screen.findByRole('button', { name: 'John Smith' });
  const [path, options] = fetchMock.mock.calls[0];
  const url = new URL(path, 'https://localhost:13000');
  expect(url.searchParams.has('search')).toBe(false);
  expect(url.searchParams.has('tenant_id')).toBe(false);
  expect(options.headers).not.toHaveProperty('X-Tenant-ID');
});

it.each([422, 500])('shows directory failure without false empty state for HTTP %s', async status => {
  fetchMock.mockImplementation(async () => Response.json({ detail: 'failure' }, { status }));
  render(<UserLifecycle />);
  expect(await screen.findByRole('alert')).toHaveTextContent('Unable to load users');
  expect(screen.getByRole('alert')).toHaveTextContent('The platform user directory could not be retrieved.');
  expect(screen.queryByText('No users found.')).not.toBeInTheDocument();
  expect(screen.queryByText(/0 matching users/)).not.toBeInTheDocument();
});

it('shows empty state only for successful empty directory', async () => {
  fetchMock.mockImplementation(async () => Response.json({ items: [], total: 0 }));
  render(<UserLifecycle />);
  await screen.findByText('No users found.');
  expect(screen.queryByRole('alert')).not.toBeInTheDocument();
});

it('keeps users visible and retries metadata independently', async () => {
  listTenants.mockRejectedValue(new Error('unavailable'));
  render(<UserLifecycle />);
  await screen.findByRole('button', { name: 'John Smith' });
  expect(await screen.findByRole('alert')).toHaveTextContent('Some filter information could not be loaded.');
  expect(screen.getByRole('button', { name: 'John Smith' })).toBeInTheDocument();
  listTenants.mockResolvedValue([]);
  fireEvent.click(screen.getByRole('button', { name: 'Retry filters' }));
  await waitFor(() => expect(screen.queryByRole('alert')).not.toBeInTheDocument());
  expect(fetchMock).toHaveBeenCalledTimes(1);
});

it('shows a platform-only administrator with zero memberships', async () => {
  fetchMock.mockImplementation(async () => Response.json({ items: [{ ...user, is_platform_admin: true, active_tenant_count: 0 }], total: 1 }));
  render(<UserLifecycle />);
  await screen.findByText('Platform Administrator');
  expect(screen.getByText(/0 active tenant memberships/)).toBeInTheDocument();
});

describe('user lifecycle administration', () => {
  it('paginates and shows empty results', async () => {
    fetchMock.mockResolvedValue(Response.json({ items: [user], total: 41 }));
    render(<UserLifecycle />); await screen.findByRole('button', { name: 'John Smith' });
    fetchMock.mockImplementation(async () => Response.json({ items: [], total: 41 }));
    fireEvent.click(screen.getByRole('button', { name: 'Next' }));
    await screen.findByText('No users found.');
    expect(fetchMock.mock.calls.at(-1)?.[0]).toContain('page=2');
  });
  it('has an accessible table and detail structure', async () => {
    const { container } = render(<UserLifecycle />);
    fireEvent.click(await screen.findByRole('button', { name: 'John Smith' }));
    await screen.findByRole('heading', { name: 'John Smith' });
    const result = await axe(container); expect(result.violations).toEqual([]);
  });
  it('filters status, role, tenant, provider and sort on the server', async () => {
    render(<UserLifecycle />); await screen.findByRole('button', { name: 'John Smith' });
    for (const [label, value, key] of [['Account status','LOCKED','local_status'], ['Role','VIEWER','role'], ['Provider','NATIVE','provider'], ['Sort','email','sort_by']]) {
      fireEvent.change(screen.getByLabelText(label), { target: { value } });
      await waitFor(() => expect(fetchMock.mock.calls.some(c => c[0].includes(`${key}=${value}`))).toBe(true));
    }
    fireEvent.click(screen.getByRole('button', { name: 'Tenant' }));
    fireEvent.click(await screen.findByRole('button', { name: 'Hospital B — hospital-b' }));
    await waitFor(() => expect(fetchMock.mock.calls.some(c => c[0].includes('tenant_id=2'))).toBe(true));
    expect(fetchMock.mock.calls.at(-1)?.[1].headers).not.toHaveProperty('X-Tenant-ID');
    fireEvent.click(screen.getByRole('button', { name: 'Tenant' }));
    fireEvent.click(screen.getByRole('button', { name: 'All tenants' }));
    await waitFor(() => expect(fetchMock.mock.calls.at(-1)?.[0]).not.toContain('tenant_id='));
    fireEvent.change(screen.getByLabelText('Provider'), { target: { value: 'HCL_CS' } });
    await waitFor(() => expect(fetchMock.mock.calls.at(-1)?.[0]).toContain('provider=HCL_CS'));
    fireEvent.change(screen.getByLabelText('Role'), { target: { value: 'PLATFORM_ADMIN' } });
    await waitFor(() => expect(fetchMock.mock.calls.at(-1)?.[0]).toContain('is_platform_admin=true'));
  });
  it('confirms logout all with the global native scope', async () => {
    await openUser(); fireEvent.click(screen.getByRole('button', { name: 'Logout all native sessions' }));
    expect(writes()).toHaveLength(0); expect(screen.getByRole('dialog')).toHaveTextContent('every tenant');
    fireEvent.click(screen.getByRole('button', { name: 'Confirm' })); await waitFor(() => expect(writes()).toHaveLength(1));
    expect(writes()[0][0]).toContain('/platform/users/42/logout-all');
  });
  it('loads platform list, filters and all memberships', async () => {
    await openUser();
    expect(screen.getByText('Hospital B · ACTIVE')).toBeInTheDocument();
    fireEvent.change(screen.getByLabelText('Search'), { target: { value: 'john' } });
    await waitFor(() => expect(fetchMock.mock.calls.some(c => c[0].includes('search=john'))).toBe(true));
    expect(screen.getByRole('button', { name: 'Disable account globally' })).toBeInTheDocument();
    expect(screen.getAllByText('TENANT_ADMIN').length).toBeGreaterThan(0);
  });
  it('renders only selected tenant data and omits global authority', async () => {
    platform = false; await openUser();
    expect(screen.getByText('Olympus · ACTIVE')).toBeInTheDocument();
    expect(screen.queryByText(/Hospital B/)).not.toBeInTheDocument();
    expect(screen.queryByRole('button', { name: 'Disable account globally' })).not.toBeInTheDocument();
    expect(screen.queryByText('TENANT_ADMIN')).not.toBeInTheDocument();
    expect(fetchMock.mock.calls[0][0]).toContain('/tenants/1/users?');
  });
  it('requires confirmation before global disable and supports cancellation', async () => {
    await openUser(); fireEvent.click(screen.getByRole('button', { name: 'Disable account globally' }));
    expect(writes()).toHaveLength(0); expect(screen.getByRole('dialog')).toHaveTextContent('every tenant');
    fireEvent.click(screen.getByRole('button', { name: 'Cancel' })); expect(writes()).toHaveLength(0);
    fireEvent.click(screen.getByRole('button', { name: 'Disable account globally' })); fireEvent.click(screen.getByRole('button', { name: 'Confirm' }));
    await waitFor(() => expect(writes()).toHaveLength(1));
    expect(writes()[0][0]).toContain('/platform/users/42/status');
    expect(JSON.parse(writes()[0][1].body as string)).toEqual({ status: 'DISABLED' });
  });
  it('confirms tenant deactivation with explicit selected-tenant header', async () => {
    platform = false; await openUser(); fireEvent.click(screen.getByRole('button', { name: 'Deactivate access to Olympus' }));
    expect(screen.getByRole('dialog')).toHaveTextContent('Other tenants remain unaffected'); expect(writes()).toHaveLength(0);
    fireEvent.click(screen.getByRole('button', { name: 'Confirm' }));
    await waitFor(() => expect(writes()).toHaveLength(1)); expect(writes()[0][0]).toContain('/tenants/1/users/12/deactivate');
    expect(writes()[0][1].headers).toMatchObject({ 'X-Tenant-ID': '1' });
  });
  it('confirms role removal and sends optimistic version with stable user ID', async () => {
    platform = false; await openUser(); fireEvent.click(screen.getByRole('checkbox', { name: 'DEVELOPER' }));
    fireEvent.click(screen.getByRole('button', { name: 'Save roles' })); expect(writes()).toHaveLength(0);
    fireEvent.click(screen.getByRole('button', { name: 'Confirm' }));
    await waitFor(() => expect(writes()).toHaveLength(1)); expect(writes()[0][0]).toContain('/tenants/1/users/42/roles');
    expect(JSON.parse(writes()[0][1].body as string)).toEqual({ role_codes: ['VIEWER'], primary_role_code: 'VIEWER', expected_version: 4 });
  });
  it('resends activation only for pending native members', async () => {
    platform = false; account = 'PENDING_EMAIL_VERIFICATION'; await openUser(); fireEvent.click(screen.getByRole('button', { name: 'Resend activation' }));
    expect(writes()).toHaveLength(0); fireEvent.click(screen.getByRole('button', { name: 'Confirm' }));
    await screen.findByText('Activation delivery: sent.'); expect(writes()[0][0]).toContain('/tenants/1/native-users/42/resend-activation');
  });
  it('warns before force password change', async () => {
    await openUser(); fireEvent.click(screen.getByRole('button', { name: 'Force password change' }));
    expect(screen.getByRole('dialog')).toHaveTextContent('must set a new password'); expect(writes()).toHaveLength(0);
  });
  it('supports global enable and manual unlock for eligible states', async () => {
    account = 'LOCKED'; await openUser(); fireEvent.click(screen.getByRole('button', { name: 'Unlock account' }));
    expect(writes()).toHaveLength(0); fireEvent.click(screen.getByRole('button', { name: 'Confirm' }));
    await waitFor(() => expect(writes()).toHaveLength(1)); expect(writes()[0][0]).toContain('/platform/users/42/unlock');
  });
  it('shows loading and API errors', async () => {
    pending = true; const view = render(<UserLifecycle />); expect(screen.getByText('Loading users…')).toBeInTheDocument(); view.unmount();
    pending = false; failed = true; render(<UserLifecycle />); expect(await screen.findByRole('alert')).toHaveTextContent("You don't have permission");
    failed = false; fireEvent.click(screen.getByRole('button', { name: 'Retry' }));
    await screen.findByRole('button', { name: 'John Smith' }); expect(screen.queryByRole('alert')).not.toBeInTheDocument();
  });
  it('removes old details immediately when selected tenant changes', async () => {
    platform = false; const view = render(<UserLifecycle />); fireEvent.click(await screen.findByRole('button', { name: 'John Smith' })); await screen.findByText('Olympus · ACTIVE');
    tenant = '2'; pending = true; view.rerender(<UserLifecycle />); expect(screen.queryByText('Olympus · ACTIVE')).not.toBeInTheDocument();
  });
});

it('shows pending Microsoft identities with explicit approval and no native password actions', async () => {
  providers = ['MICROSOFT_ENTRA']; account = 'PENDING';
  await openUser();
  expect(screen.getAllByText(/Microsoft Entra/).length).toBeGreaterThan(0);
  expect(screen.queryByRole('button', { name: 'Force password change' })).toBeNull();
  expect(screen.queryByRole('button', { name: 'Logout all native sessions' })).toBeNull();
  fireEvent.click(screen.getByRole('button', { name: 'Approve account' }));
  expect(writes()).toHaveLength(0);
  expect(screen.getByRole('dialog')).toHaveTextContent('memberships and roles must still be assigned separately');
  fireEvent.click(screen.getByRole('button', { name: 'Confirm' }));
  await waitFor(() => expect(writes()).toHaveLength(1));
  expect(JSON.parse(writes()[0][1].body as string)).toEqual({ status: 'ACTIVE' });
});

function render(ui: ReactElement) { return rtlRender(ui, { wrapper: ToastProvider }); }

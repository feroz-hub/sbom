import { QueryClient, QueryClientProvider, QueryObserver } from '@tanstack/react-query';
// @vitest-environment jsdom
import { ToastProvider } from '@/hooks/useToast';
import type { ReactElement } from 'react';
import { render as rtlRender, screen, waitFor } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import NativeUserInviteForm from './NativeUserInviteForm';

let testClient: QueryClient;
const state = vi.hoisted(() => ({ platform: true }));
const list = vi.hoisted(() => vi.fn());
vi.mock('@/hooks/useAuth', () => ({ useAuth: () => ({
  user: { userId: 1, permissions: [] },
  activeTenantId: '00000000-0000-4000-8000-00000000000c', activeTenant: { id: "00000000-0000-4000-8000-00000000000c", name: 'Olympus Healthcare' },
  hasPermission: (permission: string) => permission === 'tenant:user:invite' || state.platform,
}) }));
vi.mock('@/lib/auth', () => ({ getActiveTenantId: () => '00000000-0000-4000-8000-00000000000c' }));
vi.mock('@/lib/api', () => ({ listPlatformTenants: list }));

describe('Native invitation', () => {
  beforeEach(() => {
    state.platform = true;
    list.mockResolvedValue([{ id: "00000000-0000-4000-8000-00000000000c", name: 'Olympus Healthcare', slug: 'olympus', status: 'ACTIVE' }]);
    vi.stubGlobal('fetch', vi.fn().mockResolvedValue({ ok: true, json: async () => ({ delivery: { status: 'PENDING' } }) }));
  });
  afterEach(() => vi.unstubAllGlobals());

  it('selects tenants by name/slug and sends the selected public UUID', async () => {
    const user = userEvent.setup();
    render(<NativeUserInviteForm />);
    expect(screen.queryByLabelText(/Tenant ID/)).not.toBeInTheDocument();
    expect(screen.queryByRole('checkbox', { name: 'PLATFORM ADMIN' })).not.toBeInTheDocument();
    await user.click(screen.getByRole('button', { name: 'Tenant' }));
    await user.type(screen.getByLabelText(/Search tenants/), 'oly');
    await user.click(await screen.findByRole('button', { name: 'Olympus Healthcare — olympus' }));
    await user.type(screen.getByLabelText(/first name/i), 'Ajmer');
    await user.type(screen.getByLabelText(/last name/i), 'Khan');
    await user.type(screen.getByLabelText(/email/i), 'ajmer@example.test');
    await user.click(screen.getByRole('button', { name: /Create and send/ }));
    await waitFor(() => expect(fetch).toHaveBeenCalled());
    const [url, options] = vi.mocked(fetch).mock.calls[0];
    expect(url).toContain('/platform/native-users');
    expect(JSON.parse(String(options?.body))).toMatchObject({ tenant_id: "00000000-0000-4000-8000-00000000000c", role_codes: ['VIEWER'] });
    expect(await screen.findByRole('status')).toHaveTextContent('Invitation created');
  });

  it('locks Tenant Admin to current tenant and shows only delegable roles', () => {
    state.platform = false;
    render(<NativeUserInviteForm />);
    expect(screen.getByLabelText('Tenant')).toHaveValue('Olympus Healthcare');
    expect(screen.getByLabelText('Tenant')).toBeDisabled();
    expect(screen.queryByLabelText(/Search tenants/)).not.toBeInTheDocument();
    expect(screen.queryByRole('checkbox', { name: 'TENANT ADMIN' })).not.toBeInTheDocument();
    expect(screen.queryByRole('checkbox', { name: 'PLATFORM ADMIN' })).not.toBeInTheDocument();
    for (const role of ['SECURITY ANALYST', 'DEVELOPER', 'VIEWER']) {
      expect(screen.getByRole('checkbox', { name: role })).toBeInTheDocument();
    }
  });

  it('offers membership management for duplicate invitations', async () => {
    state.platform = false;
    vi.mocked(fetch).mockResolvedValue({ ok: false, json: async () => ({ detail: {
      code: 'MEMBERSHIP_ALREADY_EXISTS', message: 'Ajmer is already a member of Olympus Healthcare.', roles: ['DEVELOPER'],
    } }) } as Response);
    const user = userEvent.setup();
    render(<NativeUserInviteForm />);
    await user.type(screen.getByLabelText(/first name/i), 'Ajmer');
    await user.type(screen.getByLabelText(/last name/i), 'Khan');
    await user.type(screen.getByLabelText(/email/i), 'ajmer@example.test');
    await user.click(screen.getByRole('button', { name: /Create and send/ }));
    expect(await screen.findByRole('link', { name: 'Manage existing membership' })).toHaveAttribute('href', '/settings/users');
    expect(screen.getByRole('status')).toHaveTextContent('Current roles: DEVELOPER');
  });
});

it.each([true, false])('invitation refreshes authoritative tenant membership/counts (platform=%s)', async platform => {
  state.platform = platform;
  list.mockResolvedValue([{ id: "00000000-0000-4000-8000-00000000000c", name: 'Olympus Healthcare', slug: 'olympus', status: 'ACTIVE' }]);
  vi.stubGlobal('fetch', vi.fn().mockResolvedValue(Response.json({ user_id: 55, status: 'PENDING_EMAIL_VERIFICATION', delivery: { status: 'PENDING' } })));
  const user = userEvent.setup(); render(<NativeUserInviteForm />);
  testClient.setQueryData(['platform-summary'], { total_memberships: 1 });
  testClient.setQueryData(['tenant-users', "00000000-0000-4000-8000-00000000000c"], []);
  const summary = vi.fn().mockResolvedValue({ total_memberships: 2 });
  const members = vi.fn().mockResolvedValue([{ user_id: 55, status: 'PENDING_EMAIL_VERIFICATION' }]);
  const stops = [new QueryObserver(testClient, { queryKey: ['platform-summary'], queryFn: summary }).subscribe(() => {}), new QueryObserver(testClient, { queryKey: ['tenant-users', "00000000-0000-4000-8000-00000000000c"], queryFn: members }).subscribe(() => {})];
  if (platform) { await user.click(screen.getByRole('button', { name: 'Tenant' })); await user.click(await screen.findByRole('button', { name: 'Olympus Healthcare — olympus' })); }
  for (const [label, value] of [['first name', 'New'], ['last name', 'User'], ['email', 'new@example.test']]) await user.type(screen.getByLabelText(new RegExp(label, 'i')), value);
  await user.click(screen.getByRole('button', { name: /Create and send/ }));
  await waitFor(() => expect(testClient.getQueryData(['platform-summary'])).toEqual({ total_memberships: 2 }));
  expect(testClient.getQueryData(['tenant-users', "00000000-0000-4000-8000-00000000000c"])).toEqual([{ user_id: 55, status: 'PENDING_EMAIL_VERIFICATION' }]);
  expect(summary).toHaveBeenCalledTimes(1); expect(members).toHaveBeenCalledTimes(1); stops.forEach(stop => stop());
});
it('failed invitation preserves the form and leaves cached metrics fresh', async () => {
  state.platform = false; vi.stubGlobal('fetch', vi.fn().mockResolvedValue(Response.json({ detail: 'denied' }, { status: 403 })));
  const user = userEvent.setup(); render(<NativeUserInviteForm />); testClient.setQueryData(['platform-summary'], { total_memberships: 1 });
  for (const [label, value] of [['first name', 'Draft'], ['last name', 'User'], ['email', 'new@example.test']]) await user.type(screen.getByLabelText(new RegExp(label, 'i')), value);
  await user.click(screen.getByRole('button', { name: /Create and send/ }));
  expect(await screen.findByRole('status')).toHaveTextContent('Unable to create user'); expect(screen.getByLabelText(/first name/i)).toHaveValue('Draft');
  expect(testClient.getQueryState(['platform-summary'])?.isInvalidated).toBe(false);
});

function render(ui: ReactElement) {
  const qc = new QueryClient({ defaultOptions: { queries: { retry: false, staleTime: 300000, refetchOnWindowFocus: false } } });
  testClient = qc;
  return rtlRender(ui, { wrapper: ({ children }) => <QueryClientProvider client={qc}><ToastProvider>{children}</ToastProvider></QueryClientProvider> });
}

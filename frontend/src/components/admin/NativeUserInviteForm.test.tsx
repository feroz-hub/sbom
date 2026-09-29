// @vitest-environment jsdom
import { ToastProvider } from '@/hooks/useToast';
import type { ReactElement } from 'react';
import { render as rtlRender, screen, waitFor } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import NativeUserInviteForm from './NativeUserInviteForm';

const state = vi.hoisted(() => ({ platform: true }));
const list = vi.hoisted(() => vi.fn());
vi.mock('@/hooks/useAuth', () => ({ useAuth: () => ({
  activeTenantId: '12', activeTenant: { id: 12, name: 'Olympus Healthcare' },
  hasPermission: (permission: string) => permission === 'tenant:user:invite' || state.platform,
}) }));
vi.mock('@/lib/auth', () => ({ getActiveTenantId: () => '12' }));
vi.mock('@/lib/api', () => ({ listPlatformTenants: list }));

describe('Native invitation', () => {
  beforeEach(() => {
    state.platform = true;
    list.mockResolvedValue([{ id: 12, name: 'Olympus Healthcare', slug: 'olympus', status: 'ACTIVE' }]);
    vi.stubGlobal('fetch', vi.fn().mockResolvedValue({ ok: true, json: async () => ({ delivery: { status: 'PENDING' } }) }));
  });
  afterEach(() => vi.unstubAllGlobals());

  it('selects tenants by name/slug and sends the selected internal identifier', async () => {
    const user = userEvent.setup();
    render(<NativeUserInviteForm />);
    expect(screen.queryByLabelText(/Tenant ID/)).not.toBeInTheDocument();
    expect(screen.queryByRole('checkbox', { name: 'PLATFORM ADMIN' })).not.toBeInTheDocument();
    await user.type(screen.getByLabelText(/Search tenants/), 'oly');
    await user.click(await screen.findByRole('button', { name: 'Olympus Healthcare — olympus' }));
    await user.type(screen.getByLabelText(/first name/i), 'Ajmer');
    await user.type(screen.getByLabelText(/last name/i), 'Khan');
    await user.type(screen.getByLabelText(/email/i), 'ajmer@example.test');
    await user.click(screen.getByRole('button', { name: /Create and send/ }));
    await waitFor(() => expect(fetch).toHaveBeenCalled());
    const [url, options] = vi.mocked(fetch).mock.calls[0];
    expect(url).toContain('/platform/native-users');
    expect(JSON.parse(String(options?.body))).toMatchObject({ tenant_id: 12, role_codes: ['VIEWER'] });
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
    expect(await screen.findByRole('link', { name: 'Manage existing membership' })).toHaveAttribute('href', '/settings/tenant');
    expect(screen.getByRole('status')).toHaveTextContent('Current roles: DEVELOPER');
  });
});

function render(ui: ReactElement) { return rtlRender(ui, { wrapper: ToastProvider }); }

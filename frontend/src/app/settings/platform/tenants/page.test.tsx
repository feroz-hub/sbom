// @vitest-environment jsdom

import { QueryClient, QueryClientProvider } from '@tanstack/react-query';
import { render, screen, waitFor, within } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { beforeEach, describe, expect, it, vi } from 'vitest';
import { ToastProvider } from '@/hooks/useToast';

const auth = vi.hoisted(() => ({ allowed: true, loading: false }));
const api = vi.hoisted(() => ({
  listPlatformTenants: vi.fn(),
  createPlatformTenant: vi.fn(),
  updatePlatformTenantStatus: vi.fn(),
}));

vi.mock('@/hooks/useAuth', () => ({
  useAuth: () => ({
    isLoading: auth.loading,
    hasPermission: (permission: string) => auth.allowed && permission === 'platform:tenant:create',
  }),
}));
vi.mock('@/lib/api', async (importOriginal) => ({
  ...(await importOriginal<typeof import('@/lib/api')>()),
  ...api,
}));

import { HttpError } from '@/lib/api';
import PlatformTenantsPage, { slugFromName } from './page';

const tenant = {
  id: 7,
  name: 'Default Tenant',
  slug: 'default',
  external_iam_tenant_id: 'local-default',
  status: 'ACTIVE' as const,
  created_at: '2026-07-18T00:00:00Z',
};

function renderPage() {
  const client = new QueryClient({ defaultOptions: { queries: { retry: false }, mutations: { retry: false } } });
  return render(<QueryClientProvider client={client}><ToastProvider><PlatformTenantsPage /></ToastProvider></QueryClientProvider>);
}

async function openAndFillForm() {
  const user = userEvent.setup();
  await user.click(screen.getByRole('button', { name: 'Create Tenant' }));
  const form = screen.getByRole('heading', { name: 'Create tenant' }).closest('section');
  if (!form) throw new Error('Create form did not open');
  await user.type(within(form).getByLabelText('Name'), 'Acme Security');
  await user.type(within(form).getByLabelText('External IAM Tenant ID'), 'acme-security');
  return { user, form };
}

describe('PlatformTenantsPage', () => {
  beforeEach(() => {
    vi.clearAllMocks();
    auth.allowed = true;
    auth.loading = false;
    api.listPlatformTenants.mockResolvedValue([tenant]);
    api.createPlatformTenant.mockResolvedValue({
      ...tenant,
      id: 8,
      name: 'Acme Security',
      slug: 'acme-security',
      external_iam_tenant_id: 'acme-security',
    });
    api.updatePlatformTenantStatus.mockResolvedValue({ tenant_id: 7, status: 'DISABLED' });
    vi.spyOn(window, 'confirm').mockReturnValue(true);
  });

  it('renders the tenant list and platform navigation', async () => {
    renderPage();
    expect(await screen.findByText('Default Tenant')).toBeInTheDocument();
    expect(screen.getByText('local-default')).toBeInTheDocument();
    expect(screen.getByRole('link', { name: 'Administrators' })).toHaveAttribute('href', '/settings/platform');
  });

  it('renders an empty state and refresh action', async () => {
    api.listPlatformTenants.mockResolvedValue([]);
    const user = userEvent.setup();
    renderPage();
    expect(await screen.findByText('No tenants have been created.')).toBeInTheDocument();
    await user.click(screen.getByRole('button', { name: 'Refresh' }));
    await waitFor(() => expect(api.listPlatformTenants).toHaveBeenCalledTimes(2));
  });

  it('generates an editable valid slug from the tenant name', async () => {
    renderPage();
    const { user, form } = await openAndFillForm();
    expect(within(form).getByLabelText('Slug')).toHaveValue('acme-security');
    await user.clear(within(form).getByLabelText('Slug'));
    await user.type(within(form).getByLabelText('Slug'), 'custom-tenant');
    expect(within(form).getByText('Preview: /tenants/custom-tenant')).toBeInTheDocument();
    expect(slugFromName('  Medical Devices & Security  ')).toBe('medical-devices-security');
  });

  it('validates an invalid slug before making a request', async () => {
    renderPage();
    const { user, form } = await openAndFillForm();
    await user.clear(within(form).getByLabelText('Slug'));
    await user.type(within(form).getByLabelText('Slug'), 'Bad slug');
    await user.click(within(form).getByRole('button', { name: 'Create Tenant' }));
    expect(await within(form).findByText(/lowercase letters, numbers/)).toBeInTheDocument();
    expect(api.createPlatformTenant).not.toHaveBeenCalled();
  });

  it('creates a tenant, refreshes the list, and shows the next step', async () => {
    const user = userEvent.setup();
    renderPage();
    const opened = await openAndFillForm();
    await user.click(within(opened.form).getByRole('button', { name: 'Create Tenant' }));
    await waitFor(() => expect(api.createPlatformTenant).toHaveBeenCalledWith(
      { name: 'Acme Security', slug: 'acme-security', external_iam_tenant_id: 'acme-security' },
      expect.anything(),
    ));
    expect(await screen.findByText('Tenant “Acme Security” was created successfully.')).toBeInTheDocument();
    expect(screen.getByText(/configure the corresponding HCL.CS tenant_id claim/)).toBeInTheDocument();
    await waitFor(() => expect(api.listPlatformTenants).toHaveBeenCalledTimes(2));
  });

  it.each([
    [new HttpError('A tenant with this slug already exists.', 409), 'A tenant with this slug already exists.'],
    [new HttpError('A tenant with this external IAM tenant ID already exists.', 409), 'A tenant with this external IAM tenant ID already exists.'],
    [new HttpError('Session expired', 401), 'Your session has expired. Please sign in again.'],
    [new HttpError('Forbidden', 403), 'You do not have permission to create or manage tenants.'],
    [new Error('network details'), 'The tenant could not be created. Please try again or contact the platform administrator.'],
  ])('shows a safe create error for %s', async (error, expected) => {
    api.createPlatformTenant.mockRejectedValue(error);
    const user = userEvent.setup();
    renderPage();
    const opened = await openAndFillForm();
    await user.click(within(opened.form).getByRole('button', { name: 'Create Tenant' }));
    expect(await screen.findByText(expected)).toBeInTheDocument();
  });

  it('maps backend 422 validation to a field-level error', async () => {
    api.createPlatformTenant.mockRejectedValue(new HttpError('Invalid', 422, undefined, [
      { loc: ['body', 'slug'], msg: 'invalid' },
    ]));
    const user = userEvent.setup();
    renderPage();
    const opened = await openAndFillForm();
    await user.click(within(opened.form).getByRole('button', { name: 'Create Tenant' }));
    expect(await within(opened.form).findByText(/lowercase letters, numbers/)).toBeInTheDocument();
  });

  it('blocks a non-platform user without calling the API or rendering tokens', () => {
    auth.allowed = false;
    const { container } = renderPage();
    expect(screen.getByRole('alert')).toHaveTextContent('do not have permission');
    expect(screen.queryByRole('button', { name: 'Create Tenant' })).not.toBeInTheDocument();
    expect(api.listPlatformTenants).not.toHaveBeenCalled();
    expect(container.textContent).not.toMatch(/access[_ -]?token|refresh[_ -]?token|jwt|session cookie/i);
  });

  it('confirms before disabling a tenant and calls the audited status API', async () => {
    const user = userEvent.setup();
    renderPage();
    await user.click(await screen.findByRole('button', { name: 'Disable' }));
    expect(screen.getByRole('dialog')).toHaveTextContent('Normal members will lose access');
    await user.click(screen.getByRole('button', { name: 'Disable tenant' }));
    expect(window.confirm).not.toHaveBeenCalled();
    await waitFor(() => expect(api.updatePlatformTenantStatus).toHaveBeenCalledWith(7, 'DISABLED'));
  });
});

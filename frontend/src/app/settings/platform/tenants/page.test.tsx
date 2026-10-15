// @vitest-environment jsdom

import { QueryClient, QueryClientProvider } from '@tanstack/react-query';
import {
  render,
  screen,
  waitFor,
  within,
  fireEvent,
} from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { beforeEach, describe, expect, it, vi } from 'vitest';
import { ToastProvider } from '@/hooks/useToast';
import { ThemeProvider } from '@/components/theme/ThemeProvider';

const auth = vi.hoisted(() => ({
  allowed: true,
  readOnly: false,
  loading: false,
  logout: vi.fn(),
}));
const routerPush = vi.hoisted(() => vi.fn());
const api = vi.hoisted(() => ({
  listPlatformTenants: vi.fn(),
  createPlatformTenant: vi.fn(),
  updatePlatformTenantStatus: vi.fn(),
  searchPlatformTenantAdminCandidates: vi.fn(),
}));

vi.mock('next/navigation', () => ({
  useRouter: () => ({
    push: routerPush,
    replace: vi.fn(),
    prefetch: vi.fn(),
  }),
  usePathname: () => '/settings/platform/tenants',
}));
vi.mock('@/hooks/useAuth', () => ({
  useAuth: () => ({
    isLoading: auth.loading,
    hasPermission: (permission: string) =>
      auth.allowed &&
      permission.startsWith('platform:tenant:') &&
      (!auth.readOnly || permission.endsWith(':read')),
    switchTenant: vi.fn(),
    user: {
      displayName: 'Platform Admin',
      email: 'admin@example.test',
      roles: ['PLATFORM_ADMIN'],
      isPlatformAdmin: true,
    },
    config: { enabled: true },
    logout: auth.logout,
  }),
}));
vi.mock('@/lib/api', async (importOriginal) => ({
  ...(await importOriginal<typeof import('@/lib/api')>()),
  ...api,
}));

import { HttpError } from '@/lib/api';
import { slugFromName } from '@/lib/tenantForm';
import PlatformTenantsPage from './page';

const tenant = {
  id: 7,
  name: 'Default Tenant',
  slug: 'default',
  external_iam_tenant_id: 'local-default',
  status: 'ACTIVE' as const,
  created_at: '2026-07-18T00:00:00Z',
};

function renderPage() {
  const client = new QueryClient({
    defaultOptions: { queries: { retry: false }, mutations: { retry: false } },
  });
  return render(
    <QueryClientProvider client={client}>
      <ThemeProvider>
        <ToastProvider>
          <PlatformTenantsPage />
        </ToastProvider>
      </ThemeProvider>
    </QueryClientProvider>,
  );
}

async function openAndFillForm() {
  const user = userEvent.setup();
  await user.click(screen.getByRole('button', { name: 'Create Tenant' }));
  const form = screen.getByRole('dialog', { name: 'Create tenant' });
  if (!form) throw new Error('Create form did not open');
  // jsdom has no layout: the shared dialog focuses its panel rather than a visible child.
  await waitFor(() => expect(form).toHaveFocus());
  await user.type(within(form).getByLabelText('Name'), 'Acme Security');
  const userSearch = within(form).getByPlaceholderText(
    /Search existing SBOM users/,
  );
  await user.type(userSearch, 'Feroze');
  const option = await screen.findByRole('button', { name: /Feroze Basha/ });
  await user.click(option);
  return { user, form };
}

describe('PlatformTenantsPage', () => {
  it('creates a tenant and invites a new initial administrator without raw identifiers', async () => {
    const user = userEvent.setup();
    renderPage();
    await user.click(screen.getByRole('button', { name: 'Create Tenant' }));
    await user.type(screen.getByLabelText('Name'), 'Olympus Healthcare');
    await user.click(screen.getByRole('radio', { name: 'Invite new user' }));
    await user.type(screen.getByLabelText(/First name/i), 'Ajmer');
    await user.type(screen.getByLabelText(/Last name/i), 'Khan');
    await user.type(screen.getByLabelText(/Email/i), 'ajmer@example.test');
    expect(screen.getByText('TENANT_ADMIN')).toBeInTheDocument();
    expect(
      screen.getByText('Ajmer Khan (ajmer@example.test)'),
    ).toBeInTheDocument();
    await user.click(
      screen.getByRole('button', { name: 'Create Tenant & Invite Admin' }),
    );
    await waitFor(() => expect(api.createPlatformTenant).toHaveBeenCalled());
    expect(api.createPlatformTenant.mock.calls[0][0]).toEqual({
      name: 'Olympus Healthcare',
      slug: 'olympus-healthcare',
      initial_admin_invitation: {
        first_name: 'Ajmer',
        last_name: 'Khan',
        email: 'ajmer@example.test',
        phone: '',
      },
    });
  });

  beforeEach(() => {
    vi.clearAllMocks();
    window.history.replaceState(null, '', '/settings/platform/tenants');
    auth.allowed = true;
    auth.readOnly = false;
    auth.loading = false;
    api.listPlatformTenants.mockResolvedValue([tenant]);
    api.createPlatformTenant.mockResolvedValue({
      ...tenant,
      id: 8,
      name: 'Acme Security',
      slug: 'acme-security',
      external_iam_tenant_id: null,
    });
    api.updatePlatformTenantStatus.mockResolvedValue({
      tenant_id: 7,
      status: 'DISABLED',
    });
    api.searchPlatformTenantAdminCandidates.mockResolvedValue([
      {
        id: 3,
        display_name: 'Feroze Basha',
        email: 'ferozebasha.s@hcltech.com',
        username: 'ferozebasha',
        status: 'ACTIVE',
        email_verified: true,
        verification_required: false,
      },
    ]);
    vi.spyOn(window, 'confirm').mockReturnValue(true);
  });

  it('opens the existing creation form from the dashboard anchor', async () => {
    window.history.replaceState(
      null,
      '',
      '/settings/platform/tenants#create-tenant',
    );
    renderPage();
    expect(
      await screen.findByRole('heading', { name: 'Create tenant' }),
    ).toBeInTheDocument();
    expect(api.createPlatformTenant).not.toHaveBeenCalled();
  });

  it('renders the tenant list and platform navigation without external mapping column', async () => {
    renderPage();
    expect(await screen.findByText('Default Tenant')).toBeInTheDocument();
    expect(screen.getByText('default')).toBeInTheDocument();
    expect(screen.getByText('Active')).toBeInTheDocument();
    expect(
      screen.queryByText(/External tenant mapping/i),
    ).not.toBeInTheDocument();
    expect(
      screen.queryByText(/Connected to HCL.CS tenant/i),
    ).not.toBeInTheDocument();
    expect(
      screen.getByRole('link', { name: 'Administrators' }),
    ).toHaveAttribute('href', '/settings/platform');
  });

  it('offers the shared user menu and Sign Out in platform context', async () => {
    const user = userEvent.setup();
    renderPage();
    expect(
      screen.getByRole('heading', { name: 'Platform Tenants' }),
    ).toBeInTheDocument();
    await user.click(screen.getByRole('button', { name: /Platform Admin/i }));
    await user.click(screen.getByRole('menuitem', { name: 'Sign Out' }));
    expect(auth.logout).toHaveBeenCalledTimes(1);
  });

  it('renders an empty state and refresh action', async () => {
    api.listPlatformTenants.mockResolvedValue([]);
    const user = userEvent.setup();
    renderPage();
    expect(
      await screen.findByText('No tenants have been created.'),
    ).toBeInTheDocument();
    await user.click(screen.getByRole('button', { name: 'Refresh' }));
    await waitFor(() =>
      expect(api.listPlatformTenants).toHaveBeenCalledTimes(2),
    );
  });

  it('generates an editable valid slug from the tenant name', async () => {
    renderPage();
    const { user, form } = await openAndFillForm();
    expect(within(form).getByLabelText('Slug')).toHaveValue('acme-security');
    await user.clear(within(form).getByLabelText('Slug'));
    await user.type(within(form).getByLabelText('Slug'), 'custom-tenant');
    expect(
      within(form).getByText('Preview: /tenants/custom-tenant'),
    ).toBeInTheDocument();
    expect(slugFromName('  Medical Devices & Security  ')).toBe(
      'medical-devices-security',
    );
  });

  it('validates an invalid slug before making a request', async () => {
    renderPage();
    const { user, form } = await openAndFillForm();
    await user.clear(within(form).getByLabelText('Slug'));
    await user.type(within(form).getByLabelText('Slug'), 'Bad slug');
    expect(
      within(form).getByRole('button', { name: 'Create Tenant' }),
    ).toBeDisabled();
    expect(api.createPlatformTenant).not.toHaveBeenCalled();
  });

  it('creates a tenant, refreshes the list, and shows the next step', async () => {
    const user = userEvent.setup();
    renderPage();
    const opened = await openAndFillForm();
    await user.click(
      within(opened.form).getByRole('button', { name: 'Create Tenant' }),
    );
    await waitFor(() =>
      expect(api.createPlatformTenant).toHaveBeenCalledWith(
        {
          name: 'Acme Security',
          slug: 'acme-security',
          initial_admin_user_id: 3,
        },
        expect.anything(),
      ),
    );
    expect(
      await screen.findByText(
        'Tenant “Acme Security” was created successfully.',
      ),
    ).toBeInTheDocument();
    await waitFor(() => expect(api.listPlatformTenants).toHaveBeenCalled());
    expect(routerPush).toHaveBeenCalledWith('/settings/platform/tenants/8');
  });

  it('shows only the normal local tenant fields and no external IAM requirement', async () => {
    renderPage();
    const user = userEvent.setup();
    await user.click(screen.getByRole('button', { name: 'Create Tenant' }));
    const form = screen.getByRole('dialog', { name: 'Create tenant' });
    if (!form) throw new Error('Create form did not open');
    expect(within(form).getByLabelText('Name')).toBeRequired();
    expect(within(form).getByLabelText('Slug')).toBeRequired();
    expect(
      within(form).getAllByText('Initial Tenant Administrator').length,
    ).toBeGreaterThan(0);
    expect(
      within(form).queryByLabelText(/External IAM Tenant ID/i),
    ).not.toBeInTheDocument();
    expect(form).not.toHaveTextContent(
      /HCL\.CS.*tenant_id|externally managed identity prerequisite/i,
    );
  });

  it('prevents duplicate tenant creation submissions while pending', async () => {
    let resolveCreate: (value: typeof tenant) => void = () => {};
    api.createPlatformTenant.mockImplementation(
      () =>
        new Promise((resolve) => {
          resolveCreate = resolve;
        }),
    );
    const user = userEvent.setup();
    renderPage();
    const opened = await openAndFillForm();
    const submit = within(opened.form).getByRole('button', {
      name: 'Create Tenant',
    });
    await user.dblClick(submit);
    expect(api.createPlatformTenant).toHaveBeenCalledTimes(1);
    expect(
      within(opened.form).getByRole('button', { name: 'Creating…' }),
    ).toBeDisabled();
    resolveCreate({ ...tenant, id: 8, name: 'Acme Security' });
  });

  it.each([
    [
      new HttpError('A tenant with this slug already exists.', 409),
      'A tenant with this slug already exists.',
    ],
    [
      new HttpError(
        'A tenant with this external IAM tenant ID already exists.',
        409,
      ),
      'A tenant with this external IAM tenant ID already exists.',
    ],
    [
      new HttpError('Session expired', 401),
      'Your session has expired. Please sign in again.',
    ],
    [
      new HttpError('Forbidden', 403),
      'You do not have permission to create or manage tenants.',
    ],
    [
      new Error('network details'),
      'The tenant could not be created. Please try again or contact the platform administrator.',
    ],
  ])('shows a safe create error for %s', async (error, expected) => {
    api.createPlatformTenant.mockRejectedValue(error);
    const user = userEvent.setup();
    renderPage();
    const opened = await openAndFillForm();
    await user.click(
      within(opened.form).getByRole('button', { name: 'Create Tenant' }),
    );
    expect(await screen.findByText(expected)).toBeInTheDocument();
  });

  it('maps backend 422 validation to a field-level error', async () => {
    api.createPlatformTenant.mockRejectedValue(
      new HttpError('Invalid', 422, undefined, [
        { loc: ['body', 'slug'], msg: 'invalid' },
      ]),
    );
    const user = userEvent.setup();
    renderPage();
    const opened = await openAndFillForm();
    await user.click(
      within(opened.form).getByRole('button', { name: 'Create Tenant' }),
    );
    expect(
      await within(opened.form).findByText(/lowercase letters, numbers/),
    ).toBeInTheDocument();
  });

  it('blocks a non-platform user without calling the API or rendering tokens', () => {
    auth.allowed = false;
    const { container } = renderPage();
    expect(screen.getByRole('alert')).toHaveTextContent(
      'do not have permission',
    );
    expect(
      screen.queryByRole('button', { name: 'Create Tenant' }),
    ).not.toBeInTheDocument();
    expect(api.listPlatformTenants).not.toHaveBeenCalled();
    expect(container.textContent).not.toMatch(
      /access[_ -]?token|refresh[_ -]?token|jwt|session cookie/i,
    );
  });

  it('confirms before disabling a tenant and calls the audited status API', async () => {
    const user = userEvent.setup();
    renderPage();
    await user.click(
      await screen.findByRole('button', { name: 'Disable Default Tenant' }),
    );
    expect(screen.getByRole('dialog')).toHaveTextContent(
      'Normal members will lose access',
    );
    await user.click(screen.getByRole('button', { name: 'Disable tenant' }));
    expect(window.confirm).not.toHaveBeenCalled();
    await waitFor(() =>
      expect(api.updatePlatformTenantStatus).toHaveBeenCalledWith(
        7,
        'DISABLED',
      ),
    );
  });
});

describe('Tenant directory interactions', () => {
  beforeEach(() => {
    vi.clearAllMocks();
    window.history.replaceState(null, '', '/settings/platform/tenants');
    auth.allowed = true;
    auth.readOnly = false;
    auth.loading = false;
    api.listPlatformTenants.mockResolvedValue([tenant]);
    api.createPlatformTenant.mockResolvedValue({ ...tenant, id: 8 });
    api.updatePlatformTenantStatus.mockResolvedValue({
      tenant_id: 7,
      status: 'ACTIVE',
    });
  });
  it('debounces search and clears it without sending intermediate requests', async () => {
    renderPage();
    await screen.findByText('Default Tenant');
    const search = screen.getByRole('searchbox', { name: 'Search tenants' });
    fireEvent.change(search, { target: { value: 'A' } });
    fireEvent.change(search, { target: { value: 'Acme' } });
    expect(api.listPlatformTenants).toHaveBeenCalledTimes(1);
    expect(screen.getByText('Updating search…')).toBeInTheDocument();
    await waitFor(() =>
      expect(api.listPlatformTenants).toHaveBeenCalledWith('Acme', 1),
    );
    expect(api.listPlatformTenants).not.toHaveBeenCalledWith(
      'A',
      expect.anything(),
    );
    await userEvent.click(screen.getByRole('button', { name: 'Clear search' }));
    expect(search).toHaveValue('');
    await waitFor(() =>
      expect(api.listPlatformTenants).toHaveBeenLastCalledWith('', 1),
    );
  });
  it('uses the 50-row next-page heuristic and recovers from an empty later page', async () => {
    api.listPlatformTenants.mockImplementation(async (_query, page) =>
      page === 1
        ? Array.from({ length: 50 }, (_, i) => ({
            ...tenant,
            id: i + 1,
            name: `Tenant ${i + 1}`,
          }))
        : [],
    );
    renderPage();
    await screen.findByText('Tenant 50');
    await userEvent.click(screen.getByRole('button', { name: 'Next tenants' }));
    expect(
      await screen.findByText('No more tenants on this page.'),
    ).toBeInTheDocument();
    expect(
      screen.queryByText('No tenants have been created.'),
    ).not.toBeInTheDocument();
    expect(screen.getByRole('button', { name: 'Next tenants' })).toBeDisabled();
    await userEvent.click(
      screen.getByRole('button', { name: 'Previous tenants' }),
    );
    expect(await screen.findByText('Tenant 50')).toBeInTheDocument();
    expect(api.listPlatformTenants).toHaveBeenCalledWith('', 2);
  });
  it('resets pagination atomically when the debounced query changes', async () => {
    api.listPlatformTenants.mockImplementation(async () =>
      Array.from({ length: 50 }, (_, i) => ({
        ...tenant,
        id: i,
        name: `Tenant ${i}`,
      })),
    );
    renderPage();
    await screen.findByText('Tenant 49');
    await userEvent.click(screen.getByRole('button', { name: 'Next tenants' }));
    await waitFor(() =>
      expect(api.listPlatformTenants).toHaveBeenCalledWith('', 2),
    );
    fireEvent.change(
      screen.getByRole('searchbox', { name: 'Search tenants' }),
      { target: { value: 'new' } },
    );
    await waitFor(() =>
      expect(api.listPlatformTenants).toHaveBeenCalledWith('new', 1),
    );
    expect(api.listPlatformTenants).not.toHaveBeenCalledWith('new', 2);
    expect(
      screen.getByRole('button', { name: 'Previous tenants' }),
    ).toBeDisabled();
  });
  it('distinguishes no matching tenants and offers clear search', async () => {
    renderPage();
    await screen.findByText('Default Tenant');
    api.listPlatformTenants.mockResolvedValue([]);
    fireEvent.change(
      screen.getByRole('searchbox', { name: 'Search tenants' }),
      { target: { value: 'missing' } },
    );
    expect(await screen.findByText('No matching tenants.')).toBeInTheDocument();
    expect(
      screen.queryByText('No tenants have been created.'),
    ).not.toBeInTheDocument();
    await userEvent.click(
      screen.getAllByRole('button', { name: 'Clear search' })[0],
    );
    expect(
      screen.getByRole('searchbox', { name: 'Search tenants' }),
    ).toHaveValue('');
  });
  it('shows failures and retries without claiming the directory is empty', async () => {
    api.listPlatformTenants.mockRejectedValue(
      new HttpError('Service unavailable', 503),
    );
    renderPage();
    expect(await screen.findByRole('alert')).toHaveTextContent(
      'Unable to load tenants',
    );
    expect(
      screen.queryByText('No tenants have been created.'),
    ).not.toBeInTheDocument();
    api.listPlatformTenants.mockResolvedValue([tenant]);
    await userEvent.click(screen.getByRole('button', { name: 'Retry' }));
    expect(await screen.findByText('Default Tenant')).toBeInTheDocument();
  });
  it('keeps read-only management links but hides creation and status controls', async () => {
    auth.readOnly = true;
    renderPage();
    await screen.findByText('Default Tenant');
    expect(
      screen.queryByRole('button', { name: 'Create Tenant' }),
    ).not.toBeInTheDocument();
    expect(
      screen.queryByRole('button', { name: 'Disable Default Tenant' }),
    ).not.toBeInTheDocument();
    expect(
      screen.getByRole('link', { name: 'Manage Default Tenant' }),
    ).toHaveAttribute('href', '/settings/platform/tenants/7');
  });
  it('does not load or expose the create deep link before permissions resolve', () => {
    auth.loading = true;
    window.history.replaceState(
      null,
      '',
      '/settings/platform/tenants#create-tenant',
    );
    renderPage();
    expect(
      screen.getByText('Verifying platform permission…'),
    ).toBeInTheDocument();
    expect(api.listPlatformTenants).not.toHaveBeenCalled();
    expect(screen.queryByRole('dialog')).not.toBeInTheDocument();
  });
  it('cancels the disable confirmation without a write', async () => {
    renderPage();
    await userEvent.click(
      await screen.findByRole('button', { name: 'Disable Default Tenant' }),
    );
    await userEvent.click(screen.getByRole('button', { name: 'Cancel' }));
    expect(screen.queryByRole('dialog')).not.toBeInTheDocument();
    expect(api.updatePlatformTenantStatus).not.toHaveBeenCalled();
  });
  it('enables an existing disabled tenant and reports success', async () => {
    api.listPlatformTenants.mockResolvedValue([
      { ...tenant, status: 'DISABLED' },
    ]);
    renderPage();
    await userEvent.click(
      await screen.findByRole('button', { name: 'Enable Default Tenant' }),
    );
    await waitFor(() =>
      expect(api.updatePlatformTenantStatus).toHaveBeenCalledWith(7, 'ACTIVE'),
    );
    expect(
      await screen.findByText(
        'Tenant “Default Tenant” was activated successfully.',
      ),
    ).toBeInTheDocument();
  });
  it('blocks duplicate status requests while a change is pending', async () => {
    api.listPlatformTenants.mockResolvedValue([
      { ...tenant, status: 'DISABLED' },
    ]);
    api.updatePlatformTenantStatus.mockReturnValue(new Promise(() => {}));
    renderPage();
    const enable = await screen.findByRole('button', {
      name: 'Enable Default Tenant',
    });
    await userEvent.dblClick(enable);
    expect(api.updatePlatformTenantStatus).toHaveBeenCalledTimes(1);
    expect(enable).toBeDisabled();
  });
  it('reports status mutation failures without hiding the tenant', async () => {
    api.updatePlatformTenantStatus.mockRejectedValue(
      new HttpError('Status update failed', 500),
    );
    renderPage();
    await userEvent.click(
      await screen.findByRole('button', { name: 'Disable Default Tenant' }),
    );
    await userEvent.click(
      screen.getByRole('button', { name: 'Disable tenant' }),
    );
    expect(
      await screen.findByText(
        'The operation could not be completed because the service is temporarily unavailable.',
      ),
    ).toBeInTheDocument();
    expect(screen.getByText('Default Tenant')).toBeInTheDocument();
  });
  it('shows unavailable values explicitly and formats a reported zero member count', async () => {
    api.listPlatformTenants.mockResolvedValue([
      { ...tenant, member_count: 0, created_at: undefined },
      { ...tenant, id: 8, name: 'Other Tenant', created_at: undefined },
    ]);
    renderPage();
    await screen.findByText('Default Tenant');
    expect(screen.getByText('0')).toBeInTheDocument();
    expect(
      screen.getByLabelText('Member count unavailable'),
    ).toBeInTheDocument();
    expect(screen.getAllByLabelText('Created date unavailable')).toHaveLength(
      2,
    );
  });
  it('closes creation with Escape and restores focus to the trigger', async () => {
    renderPage();
    const create = screen.getByRole('button', { name: 'Create Tenant' });
    await userEvent.click(create);
    expect(screen.getByRole('dialog')).toBeInTheDocument();
    await userEvent.keyboard('{Escape}');
    expect(screen.queryByRole('dialog')).not.toBeInTheDocument();
    expect(create).toHaveFocus();
  });
  it('keeps a manually overridden slug when the tenant name changes', async () => {
    renderPage();
    await userEvent.click(
      screen.getByRole('button', { name: 'Create Tenant' }),
    );
    await userEvent.type(screen.getByLabelText('Name'), 'First name');
    await userEvent.clear(screen.getByLabelText('Slug'));
    await userEvent.type(screen.getByLabelText('Slug'), 'manual-slug');
    await userEvent.clear(screen.getByLabelText('Name'));
    await userEvent.type(screen.getByLabelText('Name'), 'Second name');
    expect(screen.getByLabelText('Slug')).toHaveValue('manual-slug');
  });
  it('preserves phone in the invitation payload and renders invitation API field errors', async () => {
    api.createPlatformTenant.mockRejectedValue(
      new HttpError('Invalid invitation', 422, undefined, undefined, {
        'initial_admin_invitation.email': ['This email cannot be invited.'],
      }),
    );
    renderPage();
    const user = userEvent.setup();
    await user.click(screen.getByRole('button', { name: 'Create Tenant' }));
    await user.type(screen.getByLabelText('Name'), 'Invited Tenant');
    await user.click(screen.getByRole('radio', { name: 'Invite new user' }));
    await user.type(screen.getByLabelText(/First name/i), 'Sam');
    await user.type(screen.getByLabelText(/Last name/i), 'Test');
    await user.type(screen.getByLabelText(/Email/i), 'sam@example.test');
    await user.type(screen.getByLabelText(/Phone/i), '+12345678');
    await user.click(
      screen.getByRole('button', { name: 'Create Tenant & Invite Admin' }),
    );
    expect(
      await screen.findByText('This email cannot be invited.'),
    ).toBeInTheDocument();
    expect(
      api.createPlatformTenant.mock.calls[0][0].initial_admin_invitation.phone,
    ).toBe('+12345678');
    expect(screen.getByLabelText(/Email/i)).toHaveValue('sam@example.test');
  });
});

// @vitest-environment jsdom

import { QueryClient, QueryClientProvider } from '@tanstack/react-query';
import { render, screen, waitFor } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import type { ReactNode } from 'react';
import { beforeEach, describe, expect, it, vi } from 'vitest';
import { TenantSwitcher } from './TenantSwitcher';

const mockSwitchTenant = vi.fn();
const mockSelectTenant = vi.fn();
const mockClearTenantSelection = vi.fn();
const mockListPlatformTenants = vi.fn();
const mockReplace = vi.fn();
let mockPathname = '/';

vi.mock('next/navigation', () => ({
  usePathname: () => mockPathname,
  useRouter: () => ({ replace: mockReplace }),
}));

beforeEach(() => { mockPathname = '/'; });

const sampleTenants = [
  {
    id: 1,
    name: 'Wellysis',
    slug: 'wellysis',
    externalIamTenantId: 'ext-1',
    status: 'ACTIVE',
    role: 'TENANT_ADMIN',
    roles: ['TENANT_ADMIN'],
    membershipStatus: 'ACTIVE',
    platformContextAvailable: false,
  },
  {
    id: 2,
    name: 'Acme Corp',
    slug: 'acme',
    externalIamTenantId: 'ext-2',
    status: 'ACTIVE',
    role: 'VIEWER',
    roles: ['VIEWER'],
    membershipStatus: 'ACTIVE',
    platformContextAvailable: false,
  },
];

let mockAuthContext: Record<string, unknown>;

function authContext(overrides: Record<string, unknown> = {}) {
  return {
    tenants: sampleTenants,
    activeTenantId: '1',
    switchTenant: mockSwitchTenant,
    selectTenant: mockSelectTenant,
    clearTenantSelection: mockClearTenantSelection,
    user: null,
    ...overrides,
  };
}

vi.mock('@/hooks/useAuth', () => ({
  useAuth: () => mockAuthContext,
}));

vi.mock('@/lib/api', () => ({
  listPlatformTenants: () => mockListPlatformTenants(),
}));

function renderSwitcher(children: ReactNode = <TenantSwitcher />) {
  const queryClient = new QueryClient({ defaultOptions: { queries: { retry: false } } });
  return render(<QueryClientProvider client={queryClient}>{children}</QueryClientProvider>);
}

describe('TenantSwitcher', () => {
  beforeEach(() => {
    vi.clearAllMocks();
    mockSelectTenant.mockResolvedValue(undefined);
    mockListPlatformTenants.mockResolvedValue([]);
    mockAuthContext = authContext();
  });

  it('shows active workspace context and a compact accessible trigger', async () => {
    const user = userEvent.setup(); renderSwitcher(<TenantSwitcher compact />);
    const trigger = screen.getByRole('button', { name: 'Switch tenant' });
    expect(trigger).toHaveAttribute('title', 'Switch tenant · Wellysis');
    expect(screen.getByText('Active tenant')).toBeInTheDocument();
    await user.click(trigger);
    expect(trigger).toHaveAttribute('aria-controls', 'tenant-switcher-options');
    expect(screen.getByRole('listbox')).toHaveClass('md:left-full');
  });

  it('supports arrow-key selection and returns focus on Escape', async () => {
    const user = userEvent.setup(); renderSwitcher();
    const trigger = screen.getByRole('button', { name: 'Switch tenant' });
    await user.click(trigger); await user.keyboard('{ArrowDown}');
    expect(screen.getByRole('option', { name: /Wellysis/ })).toHaveFocus();
    await user.keyboard('{ArrowDown}');
    expect(screen.getByRole('option', { name: /Acme Corp/ })).toHaveFocus();
    await user.keyboard('{Escape}'); expect(trigger).toHaveFocus();
    expect(screen.queryByRole('listbox')).not.toBeInTheDocument();
    expect(mockSelectTenant).not.toHaveBeenCalled();
  });

  it('renders interactive button for a single available tenant', async () => {
    mockAuthContext = authContext({ tenants: [sampleTenants[0]] });

    renderSwitcher();
    const trigger = screen.getByRole('button', { name: /switch tenant/i });
    expect(trigger).toBeInTheDocument();
    expect(trigger).toHaveTextContent('Wellysis');
  });

  it('opens dropdown list on click and highlights active tenant', async () => {
    const user = userEvent.setup();

    renderSwitcher();
    const trigger = screen.getByRole('button', { name: /switch tenant/i });
    await user.click(trigger);

    expect(screen.getByRole('listbox')).toBeInTheDocument();
    const options = screen.getAllByRole('option');
    expect(options).toHaveLength(2);
    expect(options[0]).toHaveAttribute('aria-selected', 'true');
    expect(options[1]).toHaveAttribute('aria-selected', 'false');
  });

  it('calls selectTenant when a different tenant is clicked', async () => {
    const user = userEvent.setup();

    renderSwitcher();
    await user.click(screen.getByRole('button', { name: /switch tenant/i }));
    await user.click(screen.getByRole('option', { name: /Acme Corp/i }));

    expect(mockSelectTenant).toHaveBeenCalledWith('2');
    expect(mockReplace).toHaveBeenCalledWith('/', { scroll: false });
    expect(mockReplace.mock.invocationCallOrder[0]).toBeLessThan(mockSelectTenant.mock.invocationCallOrder[0]!);
  });

  it('keeps the dashboard filters when the current tenant is selected again', async () => {
    const user = userEvent.setup();
    renderSwitcher();
    await user.click(screen.getByRole('button', { name: /switch tenant/i }));
    await user.click(screen.getByRole('option', { name: /Wellysis/i }));
    expect(mockSelectTenant).not.toHaveBeenCalled();
    expect(mockReplace).not.toHaveBeenCalled();
  });

  it('keeps other page navigation unchanged when switching tenant', async () => {
    mockPathname = '/projects';
    const user = userEvent.setup();
    renderSwitcher();
    await user.click(screen.getByRole('button', { name: /switch tenant/i }));
    await user.click(screen.getByRole('option', { name: /Acme Corp/i }));
    expect(mockSelectTenant).toHaveBeenCalledWith('2');
    expect(mockReplace).not.toHaveBeenCalled();
  });

  it('closes dropdown on Escape key', async () => {
    const user = userEvent.setup();

    renderSwitcher();
    await user.click(screen.getByRole('button', { name: /switch tenant/i }));
    expect(screen.getByRole('listbox')).toBeInTheDocument();

    await user.keyboard('{Escape}');
    await waitFor(() => expect(screen.queryByRole('listbox')).not.toBeInTheDocument());
  });

  it('does not fetch the platform tenant list for a normal tenant user', async () => {
    const user = userEvent.setup();

    renderSwitcher();
    await user.click(screen.getByRole('button', { name: /switch tenant/i }));

    expect(screen.queryByRole('option', { name: /^Platform/ })).not.toBeInTheDocument();
    expect(mockListPlatformTenants).not.toHaveBeenCalled();
  });
});

describe('TenantSwitcher platform administrator', () => {
  const platformAdmin = { isPlatformAdmin: true };

  beforeEach(() => {
    vi.clearAllMocks();
    mockListPlatformTenants.mockResolvedValue([
      { id: 42, name: 'Nova', slug: 'nova', status: 'ACTIVE' },
      { id: 43, name: 'Orion', slug: 'orion', status: 'ACTIVE' },
    ]);
    mockAuthContext = authContext({ tenants: [], activeTenantId: null, user: platformAdmin });
  });

  it('has no normal tenant selector without explicit memberships', () => {
    renderSwitcher();

    expect(screen.queryByRole('button', { name: /switch tenant/i })).not.toBeInTheDocument();
    expect(mockListPlatformTenants).not.toHaveBeenCalled();
  });

  it('offers Platform plus explicit memberships only', async () => {
    mockAuthContext = authContext({ tenants: sampleTenants, activeTenantId: null, user: platformAdmin });
    const user = userEvent.setup();
    renderSwitcher();

    await user.click(screen.getByRole('button', { name: /switch tenant/i }));

    const platformOption = await screen.findByRole('option', { name: /Platform administration/ });
    expect(platformOption).toHaveAttribute('aria-selected', 'true');
    expect(await screen.findByRole('option', { name: /Wellysis/ })).toBeInTheDocument();

    await user.type(screen.getByRole('searchbox', { name: /search tenants/i }), 'acme');
    expect(screen.queryByRole('option', { name: /Nova/ })).not.toBeInTheDocument();
    expect(screen.getByRole('option', { name: /Acme/ })).toBeInTheDocument();
    expect(mockListPlatformTenants).not.toHaveBeenCalled();
  });

  it('renders a capped list instead of every reachable tenant', async () => {
    mockAuthContext = authContext({ tenants: Array.from({ length: 120 }, (_, index) => ({ ...sampleTenants[0], id: index + 1, name: `Tenant ${index + 1}` })), activeTenantId: null, user: platformAdmin });
    mockListPlatformTenants.mockResolvedValue(
      Array.from({ length: 120 }, (_, index) => ({
        id: index + 1,
        name: `Tenant ${index + 1}`,
        slug: `tenant-${index + 1}`,
        status: 'ACTIVE',
      })),
    );
    const user = userEvent.setup();
    renderSwitcher();

    await user.click(screen.getByRole('button', { name: /switch tenant/i }));
    await screen.findByRole('option', { name: /Tenant 1\b/ });

    // 25 tenants + the Platform entry.
    expect(screen.getAllByRole('option')).toHaveLength(26);
    expect(screen.getByText(/Showing 25 of 120 tenants/)).toBeInTheDocument();
  });

  it('selects an explicit membership, never the platform tenant list', async () => {
    mockSelectTenant.mockResolvedValue(undefined);
    mockAuthContext = authContext({ tenants: [{ ...sampleTenants[0], id: 42, name: 'Nova' }], activeTenantId: null, user: platformAdmin });
    const user = userEvent.setup();
    renderSwitcher();

    await user.click(screen.getByRole('button', { name: /switch tenant/i }));
    await user.click(await screen.findByRole('option', { name: /Nova/ }));

    expect(mockSelectTenant).toHaveBeenCalledWith('42');
    expect(mockClearTenantSelection).not.toHaveBeenCalled();
  });

  it('clears the active tenant when switching back to Platform', async () => {
    mockAuthContext = authContext({
      tenants: [{ ...sampleTenants[0], id: 42, name: 'Nova', membershipStatus: null }],
      activeTenantId: '42',
      user: platformAdmin,
    });
    const user = userEvent.setup();
    renderSwitcher();

    expect(screen.getByRole('button', { name: /switch tenant/i })).toHaveTextContent('Nova');
    await user.click(screen.getByRole('button', { name: /switch tenant/i }));
    await user.click(await screen.findByRole('option', { name: /Platform administration/ }));

    expect(mockClearTenantSelection).toHaveBeenCalledTimes(1);
    expect(mockSelectTenant).not.toHaveBeenCalled();
  });
});

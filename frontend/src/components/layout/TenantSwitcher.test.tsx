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
    mockListPlatformTenants.mockResolvedValue([]);
    mockAuthContext = authContext();
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

  it('shows Platform as the current context with no memberships at all', () => {
    renderSwitcher();

    expect(screen.getByRole('button', { name: /switch tenant/i })).toHaveTextContent('Platform');
  });

  it('offers Platform plus the searchable tenant list', async () => {
    const user = userEvent.setup();
    renderSwitcher();

    await user.click(screen.getByRole('button', { name: /switch tenant/i }));

    const platformOption = await screen.findByRole('option', { name: /Platform administration/ });
    expect(platformOption).toHaveAttribute('aria-selected', 'true');
    expect(await screen.findByRole('option', { name: /Nova/ })).toBeInTheDocument();

    await user.type(screen.getByRole('searchbox', { name: /search tenants/i }), 'orion');
    expect(screen.queryByRole('option', { name: /Nova/ })).not.toBeInTheDocument();
    expect(screen.getByRole('option', { name: /Orion/ })).toBeInTheDocument();
  });

  it('renders a capped list instead of every reachable tenant', async () => {
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

  it('selects a tenant explicitly from the platform list', async () => {
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

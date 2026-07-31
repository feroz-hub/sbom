// @vitest-environment jsdom

import { render, screen, waitFor } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { beforeEach, describe, expect, it, vi } from 'vitest';
import { TenantSwitcher } from './TenantSwitcher';

const mockSwitchTenant = vi.fn();
const mockSelectTenant = vi.fn();

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

let mockAuthContext = {
  tenants: sampleTenants,
  activeTenantId: '1',
  switchTenant: mockSwitchTenant,
  selectTenant: mockSelectTenant,
};

vi.mock('@/hooks/useAuth', () => ({
  useAuth: () => mockAuthContext,
}));

describe('TenantSwitcher', () => {
  beforeEach(() => {
    vi.clearAllMocks();
  });

  it('renders interactive button for a single available tenant', async () => {
    mockAuthContext = {
      tenants: [sampleTenants[0]],
      activeTenantId: '1',
      switchTenant: mockSwitchTenant,
      selectTenant: mockSelectTenant,
    };

    render(<TenantSwitcher />);
    const trigger = screen.getByRole('button', { name: /switch tenant/i });
    expect(trigger).toBeInTheDocument();
    expect(trigger).toHaveTextContent('Wellysis');
  });

  it('opens dropdown list on click and highlights active tenant', async () => {
    const user = userEvent.setup();
    mockAuthContext = {
      tenants: sampleTenants,
      activeTenantId: '1',
      switchTenant: mockSwitchTenant,
      selectTenant: mockSelectTenant,
    };

    render(<TenantSwitcher />);
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
    mockAuthContext = {
      tenants: sampleTenants,
      activeTenantId: '1',
      switchTenant: mockSwitchTenant,
      selectTenant: mockSelectTenant,
    };

    render(<TenantSwitcher />);
    await user.click(screen.getByRole('button', { name: /switch tenant/i }));
    await user.click(screen.getByRole('option', { name: /Acme Corp/i }));

    expect(mockSelectTenant).toHaveBeenCalledWith('2');
  });

  it('closes dropdown on Escape key', async () => {
    const user = userEvent.setup();
    mockAuthContext = {
      tenants: sampleTenants,
      activeTenantId: '1',
      switchTenant: mockSwitchTenant,
      selectTenant: mockSelectTenant,
    };

    render(<TenantSwitcher />);
    await user.click(screen.getByRole('button', { name: /switch tenant/i }));
    expect(screen.getByRole('listbox')).toBeInTheDocument();

    await user.keyboard('{Escape}');
    await waitFor(() => expect(screen.queryByRole('listbox')).not.toBeInTheDocument());
  });
});

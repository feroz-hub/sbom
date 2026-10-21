// @vitest-environment jsdom
import { render, screen } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { describe, expect, it } from 'vitest';
import { TenantContextHeader, TenantAccessInformation } from './TenantContextHeader';

describe('Compact tenant context', () => {
  it('shows distinct tenant and membership states, count and slug without duplicate access cards', () => {
    render(<TenantContextHeader name="Wellysis" slug="wellysis" tenantStatus="ACTIVE" membershipStatus="ACTIVE" memberCount={5} externalIamTenantId="private-mapping" />);
    expect(screen.getByRole('heading', { name: 'Wellysis', level: 2 })).toBeInTheDocument();
    expect(screen.getByText('wellysis')).toBeInTheDocument();
    expect(screen.getByText('5 members')).toBeInTheDocument();
    expect(screen.getByText('Active')).toBeInTheDocument();
    expect(screen.getByText('Current membership: Active')).toBeInTheDocument();
    expect(screen.queryByText('Authentication')).not.toBeInTheDocument();
    expect(screen.queryByText('private-mapping')).not.toBeInTheDocument();
  });
  it.each([['ACTIVE', 'DISABLED', 'Your membership is not active'], ['DISABLED', 'ACTIVE', 'This tenant is not active']])('keeps warnings visible for tenant %s, membership %s', (tenant, membership, warning) => {
    render(<TenantContextHeader name="Tenant" slug="tenant" tenantStatus={tenant} membershipStatus={membership} />);
    expect(screen.getByRole('alert')).toHaveTextContent(warning);
  });
  it('keeps access details expandable and uses provider-neutral authentication terminology', async () => {
    render(<TenantAccessInformation />);
    const summary = screen.getByText('Access Information').closest('summary')!;
    const details = summary.closest('details')!;
    expect(details).not.toHaveAttribute('open');
    await userEvent.setup().click(summary);
    expect(details).toHaveAttribute('open');
    expect(screen.getByText(/HCL.CS, a native account or Microsoft Entra/)).toBeVisible();
    expect(screen.getByText('Managed in SBOM.')).toBeVisible();
  });
});

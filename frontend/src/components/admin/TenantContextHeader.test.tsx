// @vitest-environment jsdom

import { render, screen } from '@testing-library/react';
import { describe, expect, it } from 'vitest';
import { TenantContextHeader } from './TenantContextHeader';

describe('TenantContextHeader identity & access model UX', () => {
  it('displays Authentication: HCL.CS and Tenant access: Managed in SBOM without external mapping details', () => {
    render(
      <TenantContextHeader
        name="Wellysis"
        slug="wellysis"
        externalIamTenantId="wellysis-iam-99"
        tenantStatus="ACTIVE"
        membershipStatus="ACTIVE"
        memberCount={5}
      />,
    );

    expect(screen.getByText('Wellysis')).toBeInTheDocument();
    expect(screen.getByText('Authentication')).toBeInTheDocument();
    expect(screen.getByText('HCL.CS')).toBeInTheDocument();
    expect(screen.getByText('User identity is verified by HCL.CS.')).toBeInTheDocument();

    expect(screen.getByText('Tenant access')).toBeInTheDocument();
    expect(screen.getByText('Managed in SBOM')).toBeInTheDocument();
    expect(screen.getByText('Controlled by memberships and tenant roles.')).toBeInTheDocument();

    expect(screen.getByText('Tenant status: Active')).toBeInTheDocument();
    expect(screen.getByText('Current membership: Active')).toBeInTheDocument();

    expect(screen.queryByText(/External tenant mapping/i)).not.toBeInTheDocument();
    expect(screen.queryByText(/Technical identity details/i)).not.toBeInTheDocument();
    expect(screen.queryByText(/Identity mode/i)).not.toBeInTheDocument();
    expect(screen.queryByText('wellysis-iam-99')).not.toBeInTheDocument();
  });

  it('renders identical clean UI when external_iam_tenant_id is null', () => {
    render(
      <TenantContextHeader
        name="Medtronics"
        slug="medtronics"
        externalIamTenantId={null}
        tenantStatus="ACTIVE"
        membershipStatus="ACTIVE"
        memberCount={1}
      />,
    );

    expect(screen.getByText('Medtronics')).toBeInTheDocument();
    expect(screen.getByText('HCL.CS')).toBeInTheDocument();
    expect(screen.getByText('Managed in SBOM')).toBeInTheDocument();

    expect(screen.queryByText(/Local authentication/i)).not.toBeInTheDocument();
    expect(screen.queryByText(/Local authorization/i)).not.toBeInTheDocument();
    expect(screen.queryByText(/Not configured/i)).not.toBeInTheDocument();
    expect(screen.queryByText(/External tenant mapping/i)).not.toBeInTheDocument();
  });

  it('displays distinct tenant status and current membership badges', () => {
    render(
      <TenantContextHeader
        name="Tenant Beta"
        slug="beta"
        tenantStatus="ACTIVE"
        membershipStatus="DISABLED"
        memberCount={3}
      />,
    );

    expect(screen.getByText('Tenant status: Active')).toBeInTheDocument();
    expect(screen.getByText('Current membership: Disabled')).toBeInTheDocument();
  });

  it('hides technical identity details expander even for Platform Administrators', () => {
    render(
      <TenantContextHeader
        name="Admin View Tenant"
        slug="admin-view"
        externalIamTenantId="secret-iam-claim-123"
        isPlatformAdmin={true}
        tenantStatus="ACTIVE"
        membershipStatus="ACTIVE"
      />,
    );

    expect(screen.getByText('HCL.CS')).toBeInTheDocument();
    expect(screen.getByText('Managed in SBOM')).toBeInTheDocument();
    expect(screen.queryByText(/Technical identity details/i)).not.toBeInTheDocument();
    expect(screen.queryByText('secret-iam-claim-123')).not.toBeInTheDocument();
  });
});

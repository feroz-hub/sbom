// @vitest-environment jsdom

import { render, screen } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { describe, expect, it, vi } from 'vitest';
import { TenantContextHeader } from './TenantContextHeader';

describe('TenantContextHeader identity & access model UX', () => {
  it('displays "Connected to HCL.CS tenant" when external tenant mapping exists', () => {
    render(
      <TenantContextHeader
        name="Wellysis"
        slug="wellysis"
        externalIamTenantId="wellysis-iam-99"
        status="ACTIVE"
        memberCount={5}
      />,
    );

    expect(screen.getByText('Wellysis')).toBeInTheDocument();
    expect(screen.getByText('Authentication:')).toBeInTheDocument();
    expect(screen.getByText('HCL.CS')).toBeInTheDocument();
    expect(screen.getByText('Tenant access:')).toBeInTheDocument();
    expect(screen.getByText('Managed in SBOM')).toBeInTheDocument();
    expect(screen.getByText('External tenant mapping:')).toBeInTheDocument();
    expect(screen.getByText('Connected to HCL.CS tenant')).toBeInTheDocument();
    expect(screen.queryByText(/legacy metadata/i)).not.toBeInTheDocument();
    expect(screen.queryByText('wellysis-iam-99')).not.toBeInTheDocument();
  });

  it('displays "Not configured" for an unmapped tenant without claiming local auth', () => {
    render(
      <TenantContextHeader
        name="Medtronics"
        slug="medtronics"
        externalIamTenantId={null}
        status="ACTIVE"
        memberCount={1}
      />,
    );

    expect(screen.getByText('Medtronics')).toBeInTheDocument();
    expect(screen.getByText('Authentication:')).toBeInTheDocument();
    expect(screen.getByText('HCL.CS')).toBeInTheDocument();
    expect(screen.getByText('Tenant access:')).toBeInTheDocument();
    expect(screen.getByText('Managed in SBOM')).toBeInTheDocument();
    expect(screen.getByText('External tenant mapping:')).toBeInTheDocument();
    expect(screen.getByText('Not configured')).toBeInTheDocument();

    expect(screen.queryByText(/Local authentication/i)).not.toBeInTheDocument();
    expect(screen.queryByText(/Local authorization/i)).not.toBeInTheDocument();
    expect(screen.queryByText(/legacy metadata/i)).not.toBeInTheDocument();
  });

  it('does not classify an omitted mapping value as legacy', () => {
    render(
      <TenantContextHeader
        name="Standard Tenant"
        slug="standard"
        identityMapping={null}
        status="ACTIVE"
      />,
    );

    expect(screen.getByText('Not configured')).toBeInTheDocument();
    expect(screen.queryByText(/legacy/i)).not.toBeInTheDocument();
  });

  it('displays "Mapping status unavailable" with retry action on API error', async () => {
    const user = userEvent.setup();
    const mockRetry = vi.fn();

    render(
      <TenantContextHeader
        name="Tenant Error"
        slug="error"
        status="ACTIVE"
        isApiError={true}
        onRetryMapping={mockRetry}
      />,
    );

    expect(screen.getByText('Mapping status unavailable')).toBeInTheDocument();
    const retryBtn = screen.getByRole('button', { name: /retry/i });
    expect(retryBtn).toBeInTheDocument();

    await user.click(retryBtn);
    expect(mockRetry).toHaveBeenCalledTimes(1);
  });

  it('shows explicit legacy flag only in technical details for Platform Administrator', () => {
    render(
      <TenantContextHeader
        name="Legacy Tenant"
        slug="legacy"
        externalIamTenantId="old-id"
        identityMapping={{ state: 'LEGACY', mode: 'LEGACY', is_legacy: true, display_status: 'Legacy record' }}
        isPlatformAdmin={true}
        status="ACTIVE"
      />,
    );

    expect(screen.getByText('Legacy record')).toBeInTheDocument();
    expect(screen.getByText('Technical identity details')).toBeInTheDocument();
    expect(screen.getByText(/Legacy Flag: True/)).toBeInTheDocument();
  });

  it('hides raw external_iam_tenant_id from normal users', () => {
    render(
      <TenantContextHeader
        name="Private IAM"
        slug="private"
        externalIamTenantId="secret-iam-claim-123"
        isPlatformAdmin={false}
        status="ACTIVE"
      />,
    );

    expect(screen.getByText('Connected to HCL.CS tenant')).toBeInTheDocument();
    expect(screen.queryByText('secret-iam-claim-123')).not.toBeInTheDocument();
    expect(screen.queryByText('Technical identity details')).not.toBeInTheDocument();
  });

  it('makes raw external ID available inside technical details for Platform Administrator', () => {
    render(
      <TenantContextHeader
        name="Admin IAM"
        slug="admin-tenant"
        externalIamTenantId="admin-iam-claim-456"
        isPlatformAdmin={true}
        status="ACTIVE"
      />,
    );

    expect(screen.getByText('Technical identity details')).toBeInTheDocument();
    expect(screen.getByText(/External IAM Tenant ID: admin-iam-claim-456/)).toBeInTheDocument();
  });
});

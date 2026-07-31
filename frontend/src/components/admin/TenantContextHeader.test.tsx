// @vitest-environment jsdom

import { render, screen } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { describe, expect, it, vi } from 'vitest';
import { TenantContextHeader } from './TenantContextHeader';

describe('TenantContextHeader identity mapping UX', () => {
  it('displays "HCL.CS connected" when external mapping exists', () => {
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
    expect(screen.getByText('HCL.CS connected')).toBeInTheDocument();
    expect(screen.queryByText(/legacy metadata/i)).not.toBeInTheDocument();
    expect(screen.queryByText('wellysis-iam-99')).not.toBeInTheDocument();
  });

  it('displays "Local authorization" when external mapping is absent', () => {
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
    expect(screen.getByText('Local authorization')).toBeInTheDocument();
    expect(screen.queryByText(/legacy metadata/i)).not.toBeInTheDocument();
    expect(screen.queryByText(/Not configured/i)).not.toBeInTheDocument();
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

    expect(screen.getByText('Local authorization')).toBeInTheDocument();
    expect(screen.queryByText(/legacy/i)).not.toBeInTheDocument();
  });

  it('displays "Identity mapping unavailable" with retry action on API error', async () => {
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

    expect(screen.getByText('Identity mapping unavailable')).toBeInTheDocument();
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
        identityMapping={{ mode: 'LEGACY', is_legacy: true, display_status: 'Legacy record' }}
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

    expect(screen.getByText('HCL.CS connected')).toBeInTheDocument();
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

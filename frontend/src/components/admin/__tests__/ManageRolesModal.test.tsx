// @vitest-environment jsdom

import { render, screen, waitFor } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { describe, expect, it, vi } from 'vitest';
import { ManageRolesModal } from '../ManageRolesModal';

describe('ManageRolesModal', () => {
  const defaultProps = {
    open: true,
    onClose: vi.fn(),
    displayName: 'HCLCS Administrator',
    tenantName: 'Default Tenant',
    currentRoles: ['VIEWER'],
    isMembershipActive: true,
    loading: false,
    errorMessage: null,
    onSave: vi.fn().mockResolvedValue(undefined),
  };

  it('preselects current roles and shows role descriptions', () => {
    render(<ManageRolesModal {...defaultProps} />);

    expect(screen.getByText('Manage roles — HCLCS Administrator')).toBeInTheDocument();
    expect(screen.getByText('Default Tenant')).toBeInTheDocument();

    const viewerCheckbox = screen.getByRole('checkbox', { name: /Viewer/i });
    expect(viewerCheckbox).toBeChecked();

    const adminCheckbox = screen.getByRole('checkbox', { name: /Tenant Admin/i });
    expect(adminCheckbox).not.toBeChecked();

    expect(screen.getByText('Can manage tenant users, roles and tenant configuration.')).toBeInTheDocument();
  });

  it('maintains local draft and shows live Change Summary without calling API immediately', async () => {
    const user = userEvent.setup();
    const mockSave = vi.fn().mockResolvedValue(undefined);
    render(<ManageRolesModal {...defaultProps} onSave={mockSave} />);

    expect(screen.getByRole('button', { name: 'Save changes' })).toBeDisabled();
    expect(mockSave).not.toHaveBeenCalled();

    await user.click(screen.getByRole('checkbox', { name: /Security Analyst/i }));

    expect(mockSave).not.toHaveBeenCalled();
    expect(screen.getByText('Change Summary:')).toBeInTheDocument();
    expect(screen.getByText('Adding:')).toBeInTheDocument();
    expect(screen.getAllByText('Security Analyst')).toHaveLength(2);
    expect(screen.getByRole('button', { name: 'Save changes' })).not.toBeDisabled();

    await user.click(screen.getByRole('button', { name: 'Save changes' }));
    expect(mockSave).toHaveBeenCalledTimes(1);
    expect(mockSave).toHaveBeenCalledWith(['VIEWER', 'SECURITY_ANALYST']);
  });

  it('disables Save changes when active membership has 0 roles selected', async () => {
    const user = userEvent.setup();
    render(<ManageRolesModal {...defaultProps} currentRoles={['VIEWER']} />);

    await user.click(screen.getByRole('checkbox', { name: /Viewer/i }));

    expect(screen.getByText('Active tenant memberships require at least one assigned role.')).toBeInTheDocument();
    expect(screen.getByRole('button', { name: 'Save changes' })).toBeDisabled();
  });

  it('preserves draft and keeps modal open on Save error', async () => {
    const user = userEvent.setup();
    const mockSave = vi.fn().mockRejectedValue(new Error('The last effective Tenant Administrator cannot be removed.'));
    render(<ManageRolesModal {...defaultProps} currentRoles={['TENANT_ADMIN']} onSave={mockSave} />);

    await user.click(screen.getByRole('checkbox', { name: /Viewer/i }));
    await user.click(screen.getByRole('button', { name: 'Save changes' }));

    await waitFor(() => {
      expect(screen.getByText('The last effective Tenant Administrator cannot be removed.')).toBeInTheDocument();
    });
    expect(screen.getByRole('heading', { name: /Manage roles/i })).toBeInTheDocument();
  });

  it('discards draft when Cancel is clicked', async () => {
    const user = userEvent.setup();
    const mockClose = vi.fn();
    const mockSave = vi.fn();
    render(<ManageRolesModal {...defaultProps} onClose={mockClose} onSave={mockSave} />);

    await user.click(screen.getByRole('checkbox', { name: /Developer/i }));
    await user.click(screen.getByRole('button', { name: 'Cancel' }));

    expect(mockClose).toHaveBeenCalledTimes(1);
    expect(mockSave).not.toHaveBeenCalled();
  });
});

// @vitest-environment jsdom

import { render, screen } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { describe, expect, it, vi } from 'vitest';
import { DisableMembershipDialog, EnableMembershipDialog, RemoveMemberDialog } from '../MembershipConfirmDialogs';

describe('MembershipConfirmDialogs', () => {
  describe('DisableMembershipDialog', () => {
    it('renders disable confirmation message and optional self-warning', () => {
      render(
        <DisableMembershipDialog
          open={true}
          onClose={vi.fn()}
          displayName="HCLCS Administrator"
          tenantName="Default Tenant"
          isSelf={true}
          onConfirm={vi.fn().mockResolvedValue(undefined)}
        />,
      );

      expect(screen.getByText('Disable tenant membership?')).toBeInTheDocument();
      expect(screen.getByText(/will no longer be able to access/i)).toBeInTheDocument();
      expect(screen.getByText(/Warning: You are disabling your own membership/i)).toBeInTheDocument();
      expect(screen.getByRole('button', { name: 'Disable membership' })).toBeInTheDocument();
    });
  });

  describe('EnableMembershipDialog', () => {
    it('renders enable confirmation message', () => {
      render(
        <EnableMembershipDialog
          open={true}
          onClose={vi.fn()}
          displayName="HCLCS Administrator"
          tenantName="Default Tenant"
          onConfirm={vi.fn().mockResolvedValue(undefined)}
        />,
      );

      expect(screen.getByText('Enable tenant membership?')).toBeInTheDocument();
      expect(screen.getByText(/will regain access to/i)).toBeInTheDocument();
      expect(screen.getByRole('button', { name: 'Enable membership' })).toBeInTheDocument();
    });
  });

  describe('RemoveMemberDialog', () => {
    it('keeps Remove button disabled until confirmation checkbox is checked', async () => {
      const user = userEvent.setup();
      const mockConfirm = vi.fn().mockResolvedValue(undefined);

      render(
        <RemoveMemberDialog
          open={true}
          onClose={vi.fn()}
          displayName="HCLCS Administrator"
          tenantName="Default Tenant"
          isSelf={true}
          onConfirm={mockConfirm}
        />,
      );

      expect(screen.getByText('Remove user from tenant?')).toBeInTheDocument();
      expect(screen.getByText(/This does not delete:/i)).toBeInTheDocument();
      expect(screen.getByText(/Warning: You are removing yourself from this tenant/i)).toBeInTheDocument();

      const confirmButton = screen.getByRole('button', { name: 'Remove from tenant' });
      expect(confirmButton).toBeDisabled();

      const checkbox = screen.getByRole('checkbox', {
        name: /I understand this user will lose access to this tenant/i,
      });

      await user.click(checkbox);
      expect(confirmButton).not.toBeDisabled();

      await user.click(confirmButton);
      expect(mockConfirm).toHaveBeenCalledTimes(1);
    });
  });
});

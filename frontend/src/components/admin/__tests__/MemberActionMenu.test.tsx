// @vitest-environment jsdom

import { render, screen } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { describe, expect, it, vi } from 'vitest';
import { MemberActionMenu } from '../MemberActionMenu';

describe('MemberActionMenu', () => {
  const defaultProps = {
    displayName: 'HCLCS Administrator',
    membershipStatus: 'ACTIVE',
    canUpdate: true,
    onManageRoles: vi.fn(),
    onDisableMembership: vi.fn(),
    onEnableMembership: vi.fn(),
    onRemoveFromTenant: vi.fn(),
  };

  it('renders menu button with accessible user-specific label', () => {
    render(<MemberActionMenu {...defaultProps} />);

    const button = screen.getByRole('button', { name: 'Open actions for HCLCS Administrator' });
    expect(button).toBeInTheDocument();
    expect(button).toHaveAttribute('aria-haspopup', 'menu');
  });

  it('shows active membership actions when menu is opened', async () => {
    const user = userEvent.setup();
    render(<MemberActionMenu {...defaultProps} />);

    await user.click(screen.getByRole('button', { name: 'Open actions for HCLCS Administrator' }));

    expect(screen.getByRole('menuitem', { name: /Manage roles/i })).toBeInTheDocument();
    expect(screen.getByRole('menuitem', { name: /Disable membership/i })).toBeInTheDocument();
    expect(screen.getByRole('menuitem', { name: /Remove from tenant/i })).toBeInTheDocument();
    expect(screen.queryByRole('menuitem', { name: /Enable membership/i })).not.toBeInTheDocument();
  });

  it('shows disabled membership actions for a disabled member', async () => {
    const user = userEvent.setup();
    render(<MemberActionMenu {...defaultProps} membershipStatus="DISABLED" />);

    await user.click(screen.getByRole('button', { name: 'Open actions for HCLCS Administrator' }));

    expect(screen.getByRole('menuitem', { name: /Manage roles/i })).toBeInTheDocument();
    expect(screen.getByRole('menuitem', { name: /Enable membership/i })).toBeInTheDocument();
    expect(screen.getByRole('menuitem', { name: /Remove from tenant/i })).toBeInTheDocument();
    expect(screen.queryByRole('menuitem', { name: /Disable membership/i })).not.toBeInTheDocument();
  });

  it('supports Escape key to close menu and return focus', async () => {
    const user = userEvent.setup();
    render(<MemberActionMenu {...defaultProps} />);

    const trigger = screen.getByRole('button', { name: 'Open actions for HCLCS Administrator' });
    await user.click(trigger);
    expect(screen.getByRole('menu')).toBeInTheDocument();

    await user.keyboard('{Escape}');
    expect(screen.queryByRole('menu')).not.toBeInTheDocument();
    expect(trigger).toHaveFocus();
  });
});

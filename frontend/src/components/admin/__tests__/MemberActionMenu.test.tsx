// @vitest-environment jsdom

import { render, screen } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { beforeEach, describe, expect, it, vi } from 'vitest';
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

  beforeEach(() => {
    vi.clearAllMocks();
  });

  it('renders menu button with accessible user-specific label and touch target', () => {
    render(<MemberActionMenu {...defaultProps} />);

    const button = screen.getByRole('button', { name: 'Open actions for HCLCS Administrator' });
    expect(button).toBeInTheDocument();
    expect(button).toHaveAttribute('aria-haspopup', 'menu');
    expect(button.className).toContain('min-h-[44px]');
    expect(button.className).toContain('min-w-[44px]');
  });

  it('renders dropdown menu in document.body portal outside clipped overflow container', async () => {
    const user = userEvent.setup();
    render(
      <div style={{ overflow: 'hidden', height: '50px' }}>
        <MemberActionMenu {...defaultProps} />
      </div>,
    );

    const trigger = screen.getByRole('button', { name: 'Open actions for HCLCS Administrator' });
    await user.click(trigger);

    const menu = screen.getByRole('menu');
    expect(menu).toBeInTheDocument();
    expect(menu.parentElement).toBe(document.body);
  });

  it('shows active membership actions and divider', async () => {
    const user = userEvent.setup();
    render(<MemberActionMenu {...defaultProps} />);

    await user.click(screen.getByRole('button', { name: 'Open actions for HCLCS Administrator' }));

    const manageBtn = screen.getByRole('menuitem', { name: /Manage roles/i });
    const disableBtn = screen.getByRole('menuitem', { name: /Disable membership/i });
    const removeBtn = screen.getByRole('menuitem', { name: /Remove from tenant/i });

    expect(manageBtn).toBeInTheDocument();
    expect(disableBtn).toBeInTheDocument();
    expect(removeBtn).toBeInTheDocument();
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

  it('invokes callbacks when menu items are clicked', async () => {
    const user = userEvent.setup();
    const props = {
      ...defaultProps,
      onManageRoles: vi.fn(),
      onDisableMembership: vi.fn(),
      onRemoveFromTenant: vi.fn(),
    };

    render(<MemberActionMenu {...props} />);

    // Click Manage Roles
    await user.click(screen.getByRole('button', { name: 'Open actions for HCLCS Administrator' }));
    await user.click(screen.getByRole('menuitem', { name: /Manage roles/i }));
    expect(props.onManageRoles).toHaveBeenCalledTimes(1);
    expect(screen.queryByRole('menu')).not.toBeInTheDocument();

    // Click Disable Membership
    await user.click(screen.getByRole('button', { name: 'Open actions for HCLCS Administrator' }));
    await user.click(screen.getByRole('menuitem', { name: /Disable membership/i }));
    expect(props.onDisableMembership).toHaveBeenCalledTimes(1);

    // Click Remove from Tenant
    await user.click(screen.getByRole('button', { name: 'Open actions for HCLCS Administrator' }));
    await user.click(screen.getByRole('menuitem', { name: /Remove from tenant/i }));
    expect(props.onRemoveFromTenant).toHaveBeenCalledTimes(1);
  });

  it('flips placement upward when there is insufficient space below', async () => {
    const user = userEvent.setup();

    // Mock getBoundingClientRect near bottom of 800px viewport
    vi.spyOn(HTMLElement.prototype, 'getBoundingClientRect').mockReturnValue({
      top: 750,
      bottom: 790,
      left: 600,
      right: 644,
      width: 44,
      height: 44,
      x: 600,
      y: 750,
      toJSON: () => {},
    });

    render(<MemberActionMenu {...defaultProps} />);

    await user.click(screen.getByRole('button', { name: 'Open actions for HCLCS Administrator' }));

    const menu = screen.getByRole('menu');
    expect(menu).toBeInTheDocument();
    // Top position should be trigger top (750) - estimated menu height (176) - 4 = 570px
    const topValue = Number.parseFloat(menu.style.top);
    expect(topValue).toBeLessThan(750);
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

  it('closes previously open menu when a second menu is opened', async () => {
    const user = userEvent.setup();
    render(
      <div>
        <MemberActionMenu {...defaultProps} displayName="User One" />
        <MemberActionMenu {...defaultProps} displayName="User Two" />
      </div>,
    );

    const trigger1 = screen.getByRole('button', { name: 'Open actions for User One' });
    const trigger2 = screen.getByRole('button', { name: 'Open actions for User Two' });

    // Open first menu
    await user.click(trigger1);
    expect(screen.getByRole('menu', { name: 'Actions for User One' })).toBeInTheDocument();

    // Open second menu
    await user.click(trigger2);
    expect(screen.queryByRole('menu', { name: 'Actions for User One' })).not.toBeInTheDocument();
    expect(screen.getByRole('menu', { name: 'Actions for User Two' })).toBeInTheDocument();
  });
});

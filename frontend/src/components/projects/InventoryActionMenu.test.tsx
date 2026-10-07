// @vitest-environment jsdom
import { fireEvent, render, screen } from '@testing-library/react';
import { describe, expect, it, vi } from 'vitest';
import { InventoryActionMenu } from './InventoryActionMenu';
describe('inventory action menu keyboard workflow', () => {
  it('opens with keyboard, skips disabled actions and restores trigger focus on Escape', () => {
    render(<InventoryActionMenu label="Application actions" actions={[{ label: 'View', href: '/products/1' }, { label: 'Unavailable', disabled: true }, { label: 'Edit', onClick: vi.fn() }, { label: 'Delete', destructive: true }]} />);
    const trigger = screen.getByRole('button', { name: 'Application actions' });
    fireEvent.keyDown(trigger, { key: 'ArrowDown' });
    const view = screen.getByRole('menuitem', { name: 'View' });
    expect(view).toHaveFocus();
    fireEvent.keyDown(view, { key: 'ArrowDown' });
    expect(screen.getByRole('menuitem', { name: 'Edit' })).toHaveFocus();
    fireEvent.keyDown(screen.getByRole('menu'), { key: 'End' });
    expect(screen.getByRole('menuitem', { name: 'Delete' })).toHaveFocus();
    fireEvent.keyDown(screen.getByRole('menu'), { key: 'Escape' });
    expect(screen.queryByRole('menu')).not.toBeInTheDocument(); expect(trigger).toHaveFocus();
  });
  it('closes before invoking an action and uses supported destination links', () => {
    const edit = vi.fn(); render(<InventoryActionMenu label="Project actions" actions={[{ label: 'Notifications', href: '/settings/notifications?scope=PROJECT&target=1' }, { label: 'Edit', onClick: edit }]} />);
    fireEvent.click(screen.getByRole('button'));
    expect(screen.getByRole('menuitem', { name: 'Notifications' })).toHaveAttribute('href', '/settings/notifications?scope=PROJECT&target=1');
    fireEvent.click(screen.getByRole('menuitem', { name: 'Edit' }));
    expect(edit).toHaveBeenCalledOnce(); expect(screen.queryByRole('menu')).not.toBeInTheDocument();
  });
});

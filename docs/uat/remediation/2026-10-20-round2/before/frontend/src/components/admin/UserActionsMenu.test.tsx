// @vitest-environment jsdom
import { fireEvent, render, screen } from '@testing-library/react';
import { expect, it, vi } from 'vitest';
import { UserActionsMenu } from './UserActionsMenu';

it('opens with keyboard-accessible details and restores focus on Escape', () => {
  const onView = vi.fn();
  render(<UserActionsMenu name="Test User" onView={onView} />);
  const trigger = screen.getByRole('button', { name: 'Actions for Test User' });
  fireEvent.click(trigger);
  expect(screen.getByRole('button', { name: 'View details' })).toHaveFocus();
  fireEvent.keyDown(screen.getByRole('button', { name: 'View details' }), { key: 'Escape' });
  expect(trigger).toHaveFocus();
  expect(trigger).toHaveAttribute('aria-expanded', 'false');
  fireEvent.click(trigger);
  fireEvent.click(screen.getByRole('button', { name: 'View details' }));
  expect(onView).toHaveBeenCalledOnce();
});

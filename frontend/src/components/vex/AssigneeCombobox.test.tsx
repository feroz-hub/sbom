// @vitest-environment jsdom
import { fireEvent, render, screen } from '@testing-library/react';
import { describe, expect, it, vi } from 'vitest';
import { AssigneeCombobox } from './AssigneeCombobox';

const candidates = [
  { id: 'membership:1', label: 'AstraMed Analyst', email: 'analyst@astramed.com', roles: ['SECURITY_ANALYST'] },
  { id: 'membership:2', label: 'AstraMed Developer', email: 'developer@astramed.com', roles: ['DEVELOPER'] },
];

describe('Assignee combobox', () => {
  it('opens immediately, searches email case-insensitively, and selects with keyboard', () => {
    const select = vi.fn();
    render(<AssigneeCombobox candidates={candidates} selected="" onSelect={select} />);
    const input = screen.getByRole('combobox', { name: 'Assignee' });
    fireEvent.focus(input);
    expect(screen.getAllByRole('option')).toHaveLength(2);
    expect(screen.getByRole('listbox').parentElement).toBe(document.body);
    fireEvent.change(input, { target: { value: 'DEVELOPER@' } });
    expect(screen.getAllByRole('option')).toHaveLength(1);
    fireEvent.keyDown(input, { key: 'Enter' });
    expect(select).toHaveBeenCalledWith('membership:2');
    expect(input).toHaveAttribute('aria-expanded', 'false');
  });

  it('supports arrow navigation and Escape', () => {
    const select = vi.fn();
    render(<AssigneeCombobox candidates={candidates} selected="" onSelect={select} />);
    const input = screen.getByRole('combobox');
    fireEvent.focus(input);
    fireEvent.keyDown(input, { key: 'ArrowDown' });
    expect(input.getAttribute('aria-activedescendant')).toBe(screen.getAllByRole('option')[1].id);
    fireEvent.keyDown(input, { key: 'ArrowUp' });
    fireEvent.keyDown(input, { key: 'Escape' });
    expect(screen.queryByRole('listbox')).not.toBeInTheDocument();
  });

  it('shows contextual empty states and closes on Tab blur', () => {
    render(<AssigneeCombobox candidates={candidates} selected="membership:2" onSelect={vi.fn()} />);
    const input = screen.getByRole('combobox');
    expect(input).toHaveValue('AstraMed Developer');
    fireEvent.focus(input);
    fireEvent.change(input, { target: { value: 'unknown' } });
    expect(screen.getByText('No eligible assignees found')).toBeInTheDocument();
    fireEvent.blur(input);
    expect(screen.queryByRole('listbox')).not.toBeInTheDocument();
  });

  it('explains when the tenant has no eligible users', () => {
    render(<AssigneeCombobox candidates={[]} selected="" onSelect={vi.fn()} />);
    fireEvent.focus(screen.getByRole('combobox'));
    expect(screen.getByText('No eligible assignees')).toBeInTheDocument();
  });
});

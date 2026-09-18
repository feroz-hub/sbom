// @vitest-environment jsdom

import { describe, expect, it, vi } from 'vitest';
import { fireEvent, render, screen } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { Select } from '../Select';

describe('Select Component', () => {
  describe('Default variant', () => {
    it('renders a standard select with label and options', () => {
      const handleChange = vi.fn();
      render(
        <Select label="Environment" value="prod" onChange={handleChange}>
          <option value="dev">Development</option>
          <option value="prod">Production</option>
        </Select>,
      );

      expect(screen.getByLabelText('Environment')).toBeInTheDocument();
      const select = screen.getByRole('combobox');
      expect(select).toHaveValue('prod');

      fireEvent.change(select, { target: { value: 'dev' } });
      expect(handleChange).toHaveBeenCalled();
    });
  });

  describe('Filter variant (Modern Dropdown UI)', () => {
    const defaultOptions = [
      { value: '', label: 'ALL' },
      { value: 'proj-1', label: 'Alpha Service' },
      { value: 'proj-2', label: 'Beta Service' },
      { value: 'proj-3', label: 'Gamma Service' },
    ];

    it('renders modern trigger button and displays current selection', () => {
      render(
        <Select
          variant="filter"
          label="Project"
          value="proj-2"
          options={defaultOptions}
          onChange={() => {}}
        />
      );

      expect(screen.getByText('Project')).toBeInTheDocument();
      const trigger = screen.getByRole('button', { name: /Beta Service/i });
      expect(trigger).toBeInTheDocument();
      expect(trigger).toHaveAttribute('aria-haspopup', 'listbox');
      expect(trigger).toHaveAttribute('aria-expanded', 'false');
    });

    it('opens dropdown popup on click and displays options with checkmark on active item', async () => {
      const user = userEvent.setup();
      render(
        <Select
          variant="filter"
          label="Project"
          value="proj-2"
          options={defaultOptions}
          onChange={() => {}}
        />
      );

      const trigger = screen.getByRole('button', { name: /Beta Service/i });
      await user.click(trigger);

      expect(trigger).toHaveAttribute('aria-expanded', 'true');
      const listbox = screen.getByRole('listbox');
      expect(listbox).toBeInTheDocument();

      const options = screen.getAllByRole('option');
      expect(options.length).toBe(defaultOptions.length);

      // Selected option should have aria-selected=true
      const selectedOption = options.find((opt) => opt.getAttribute('aria-selected') === 'true');
      expect(selectedOption).toHaveTextContent('Beta Service');
    });

    it('calls onChange and closes popup when an option is clicked', async () => {
      const user = userEvent.setup();
      const handleChange = vi.fn();
      render(
        <Select
          variant="filter"
          label="Project"
          value=""
          options={defaultOptions}
          onChange={handleChange}
        />,
      );

      const trigger = screen.getByRole('button', { name: /ALL/i });
      await user.click(trigger);

      const optionToSelect = screen.getByRole('option', { name: 'Gamma Service' });
      await user.click(optionToSelect);

      expect(handleChange).toHaveBeenCalled();
      expect(screen.queryByRole('listbox')).not.toBeInTheDocument();
    });

    it('supports keyboard navigation (ArrowDown, Enter, Escape)', async () => {
      const user = userEvent.setup();
      const handleChange = vi.fn();
      render(
        <Select
          variant="filter"
          label="Project"
          value=""
          options={defaultOptions}
          onChange={handleChange}
        />,
      );

      const trigger = screen.getByRole('button', { name: /ALL/i });
      trigger.focus();

      // Open with Enter
      await user.keyboard('{Enter}');
      expect(screen.getByRole('listbox')).toBeInTheDocument();

      // Close with Escape
      await user.keyboard('{Escape}');
      expect(screen.queryByRole('listbox')).not.toBeInTheDocument();

      // Open with Space, ArrowDown to next, Enter to select
      await user.keyboard(' ');
      expect(screen.getByRole('listbox')).toBeInTheDocument();
      await user.keyboard('{ArrowDown}');
      await user.keyboard('{Enter}');
      expect(handleChange).toHaveBeenCalled();
      expect(screen.queryByRole('listbox')).not.toBeInTheDocument();
    });

    it('does not display search input when options count is less than 10', async () => {
      const user = userEvent.setup();
      render(
        <Select
          variant="filter"
          label="Project"
          value=""
          options={defaultOptions}
          onChange={() => {}}
        />,
      );

      const trigger = screen.getByRole('button', { name: /ALL/i });
      await user.click(trigger);

      expect(screen.queryByPlaceholderText(/search/i)).not.toBeInTheDocument();
    });

    it('displays search input and filters options when options count >= 10', async () => {
      const user = userEvent.setup();
      const manyOptions = Array.from({ length: 15 }, (_, i) => ({
        value: `val-${i}`,
        label: i === 7 ? 'Unique Project Name' : `Item ${i}`,
      }));

      render(
        <Select
          variant="filter"
          label="Project"
          value=""
          options={manyOptions}
          onChange={() => {}}
        />,
      );

      const trigger = screen.getByRole('button');
      await user.click(trigger);

      const searchInput = screen.getByPlaceholderText(/search/i);
      expect(searchInput).toBeInTheDocument();

      await user.type(searchInput, 'Unique');
      const filteredOptions = screen.getAllByRole('option');
      expect(filteredOptions.length).toBe(1);
      expect(filteredOptions[0]).toHaveTextContent('Unique Project Name');
    });

    it('closes dropdown when clicking outside', async () => {
      const user = userEvent.setup();
      render(
        <div>
          <button type="button">Outside Button</button>
          <Select
            variant="filter"
            label="Project"
            value=""
            options={defaultOptions}
            onChange={() => {}}
          />
        </div>,
      );

      const trigger = screen.getByRole('button', { name: /ALL/i });
      await user.click(trigger);
      expect(screen.getByRole('listbox')).toBeInTheDocument();

      await user.click(screen.getByText('Outside Button'));
      expect(screen.queryByRole('listbox')).not.toBeInTheDocument();
    });

    it('does not open when disabled', async () => {
      const user = userEvent.setup();
      render(
        <Select
          variant="filter"
          label="Project"
          value=""
          options={defaultOptions}
          disabled
          onChange={() => {}}
        />,
      );

      const trigger = screen.getByRole('button', { name: /ALL/i });
      expect(trigger).toBeDisabled();

      await user.click(trigger);
      expect(screen.queryByRole('listbox')).not.toBeInTheDocument();
    });
  });
});

// @vitest-environment jsdom

/**
 * Column-resize wiring for the shared Table primitive.
 *
 * jsdom performs no layout — every `getBoundingClientRect()` returns zeroes —
 * so the pixel arithmetic of a drag cannot be asserted here. What these tests
 * do cover is everything that decides whether the feature reaches the user at
 * all: a handle on every column, the documented opt-out, keyboard reachability,
 * and the "stay on auto layout until the user actually drags" contract that
 * keeps untouched tables looking exactly as they did before.
 */

import { render, screen } from '@testing-library/react';
import { describe, expect, it } from 'vitest';
import { SortableTh, Table, TableBody, TableHead, Td, Th } from './Table';

function renderTable(options: { gutterResizable?: boolean } = {}) {
  return render(
    <Table ariaLabel="Test table">
      <TableHead>
        <tr>
          <Th resizable={options.gutterResizable ?? true}>Select</Th>
          <Th>Name</Th>
          <SortableTh sortKey="created" activeKey={null} direction="asc" onToggle={() => {}}>
            Created
          </SortableTh>
        </tr>
      </TableHead>
      <TableBody>
        <tr>
          <Td>x</Td>
          <Td>demo</Td>
          <Td>today</Td>
        </tr>
      </TableBody>
    </Table>,
  );
}

const handles = () => screen.getAllByRole('separator');

describe('Table column resizing', () => {
  it('renders a resize handle on plain and sortable columns alike', () => {
    renderTable();
    expect(handles()).toHaveLength(3);
    expect(screen.getByLabelText('Resize Name column')).toBeInTheDocument();
    expect(screen.getByLabelText('Resize Created column')).toBeInTheDocument();
  });

  it('omits the handle when a column opts out', () => {
    renderTable({ gutterResizable: false });
    expect(handles()).toHaveLength(2);
    expect(screen.queryByLabelText('Resize Select column')).not.toBeInTheDocument();
  });

  it('exposes each handle to the keyboard as a vertical separator', () => {
    renderTable();
    for (const handle of handles()) {
      expect(handle).toHaveAttribute('tabindex', '0');
      expect(handle).toHaveAttribute('aria-orientation', 'vertical');
    }
  });

  it('leaves the table on automatic layout until a column is actually resized', () => {
    const { container } = renderTable();
    const table = container.querySelector('table')!;
    expect(table.style.tableLayout).toBe('');
    expect(table.style.width).toBe('');
    expect(table.classList.contains('is-column-resized')).toBe(false);
    expect(table.dataset.columnsFrozen).toBeUndefined();
  });

  it('keeps the sort control clickable alongside the handle', async () => {
    let toggled = 0;
    render(
      <Table ariaLabel="Sortable">
        <TableHead>
          <tr>
            <SortableTh
              sortKey="created"
              activeKey={null}
              direction="asc"
              onToggle={() => {
                toggled += 1;
              }}
            >
              Created
            </SortableTh>
          </tr>
        </TableHead>
        <TableBody>
          <tr>
            <Td>today</Td>
          </tr>
        </TableBody>
      </Table>,
    );

    screen.getByRole('button', { name: 'Sort by Created' }).click();
    expect(toggled).toBe(1);
  });
});

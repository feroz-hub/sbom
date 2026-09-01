import React from 'react';
import { ArrowDown, ArrowUp, ArrowUpDown } from 'lucide-react';
import { cn } from '@/lib/utils';
import type { ReactNode } from 'react';

interface TableProps {
  children: ReactNode;
  className?: string;
  ariaLabel?: string;
  /** Alternating row background for long scannable lists. */
  striped?: boolean;
  /**
   * Outer frame plus vertical cell separators. Opt-in: wide, dense tables
   * read better with column rules, narrow ones look boxed-in without them.
   */
  bordered?: boolean;
}

export function Table({ children, className, ariaLabel, striped, bordered }: TableProps) {
  return (
    <div
      className="overflow-x-auto rounded-lg focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-primary/30"
      role={ariaLabel ? 'region' : undefined}
      aria-label={ariaLabel}
      tabIndex={ariaLabel ? 0 : undefined}
    >
      <table
        className={cn(
          'w-full bg-surface text-sm text-foreground',
          striped && '[&_tbody_tr:nth-child(odd)]:bg-surface [&_tbody_tr:nth-child(even)]:bg-row-alt',
          '[&_tbody_tr]:transition-colors [&_tbody_tr]:hover:bg-row-hover',
          bordered &&
            'border border-border [&_th]:border-r [&_th]:border-white/25 [&_td]:border-r [&_td]:border-border/60 [&_th:last-child]:border-r-0 [&_td:last-child]:border-r-0',
          // Once a column has been dragged the table switches to fixed
          // layout, so a narrowed cell would otherwise bleed into its
          // neighbour. Clip instead. Applied only in that state so untouched
          // tables keep their natural content-driven sizing.
          '[&.is-column-resized_td]:overflow-hidden [&.is-column-resized_td]:text-ellipsis',
          '[&.is-column-resized_th]:overflow-hidden [&.is-column-resized_th]:text-ellipsis',
          className,
        )}
      >
        {ariaLabel && <caption className="sr-only">{ariaLabel}</caption>}
        {children}
      </table>
    </div>
  );
}

export function TableHead({ children }: { children: ReactNode }) {
  return (
    <thead
      className="sticky top-0 z-[1]"
      style={{
        background: 'linear-gradient(90deg, var(--table-header-grad-start) 0%, var(--table-header-grad-mid) 55%, var(--table-header-grad-end) 100%)',
      }}
    >
      {children}
    </thead>
  );
}

export function TableBody({ children }: { children: ReactNode }) {
  return <tbody className="divide-y divide-border/60">{children}</tbody>;
}


// ---------------------------------------------------------------------------
// Column resizing
// ---------------------------------------------------------------------------

/** Smallest column a drag may produce, in px. */
const MIN_COLUMN_WIDTH = 56;

/**
 * Freeze every header cell at its currently rendered width and switch the
 * table to fixed layout.
 *
 * Called once, lazily, on the first drag. Doing it up-front would change how
 * every table sizes its columns; doing it here means an untouched table keeps
 * the browser's content-driven `table-layout: auto` widths, and the very first
 * drag starts from exactly what the user was already looking at instead of
 * reflowing the whole table under the cursor.
 */
function freezeColumnWidths(table: HTMLTableElement, headerRow: HTMLTableRowElement): void {
  if (table.dataset.columnsFrozen === 'true') return;
  const widths = Array.from(headerRow.cells, (cell) => cell.getBoundingClientRect().width);
  table.style.width = `${table.getBoundingClientRect().width}px`;
  Array.from(headerRow.cells).forEach((cell, i) => {
    cell.style.width = `${widths[i]}px`;
  });
  table.style.tableLayout = 'fixed';
  table.classList.add('is-column-resized');
  table.dataset.columnsFrozen = 'true';
}

/**
 * Resolve the `<th>` / `<table>` / header-row trio a handle belongs to.
 *
 * Walking up the DOM rather than threading React context keeps the handle
 * self-contained: any `<th>` that renders one becomes resizable, with no
 * cooperation needed from the table that owns it.
 */
function resolveTarget(handle: HTMLElement) {
  const th = handle.closest('th');
  const table = th?.closest('table');
  const headerRow = th?.parentElement;
  if (!(th instanceof HTMLTableCellElement)) return null;
  if (!(table instanceof HTMLTableElement)) return null;
  if (!(headerRow instanceof HTMLTableRowElement)) return null;
  return { th, table, headerRow };
}

/**
 * Apply a width to one column, widening or narrowing the table by the same
 * amount so sibling columns keep the width the user gave them and the
 * container scrolls instead of redistributing the difference.
 */
function applyWidth(
  target: { th: HTMLTableCellElement; table: HTMLTableElement },
  nextWidth: number,
  startWidth: number,
  startTableWidth: number,
): void {
  const clamped = Math.max(MIN_COLUMN_WIDTH, nextWidth);
  target.th.style.width = `${clamped}px`;
  target.table.style.width = `${startTableWidth + (clamped - startWidth)}px`;
}

function ColumnResizeHandle({ columnLabel }: { columnLabel?: string }) {
  const onPointerDown = (event: React.PointerEvent<HTMLSpanElement>) => {
    if (event.button !== 0) return;
    // Keep the gesture off the sort button this handle sits next to.
    event.preventDefault();
    event.stopPropagation();

    const target = resolveTarget(event.currentTarget);
    if (!target) return;
    freezeColumnWidths(target.table, target.headerRow);

    const startX = event.clientX;
    const startWidth = target.th.getBoundingClientRect().width;
    const startTableWidth = target.table.getBoundingClientRect().width;

    const onMove = (moveEvent: PointerEvent) => {
      applyWidth(target, startWidth + (moveEvent.clientX - startX), startWidth, startTableWidth);
    };
    const onUp = () => {
      window.removeEventListener('pointermove', onMove);
      window.removeEventListener('pointerup', onUp);
      window.removeEventListener('pointercancel', onUp);
      document.body.style.removeProperty('cursor');
      document.body.style.removeProperty('user-select');
    };

    window.addEventListener('pointermove', onMove);
    window.addEventListener('pointerup', onUp);
    window.addEventListener('pointercancel', onUp);
    document.body.style.cursor = 'col-resize';
    document.body.style.userSelect = 'none';
  };

  // Keyboard equivalent — a pointer-only affordance would put column width
  // out of reach for keyboard and screen-reader users.
  const onKeyDown = (event: React.KeyboardEvent<HTMLSpanElement>) => {
    const step = event.shiftKey ? 40 : 12;
    const delta = event.key === 'ArrowLeft' ? -step : event.key === 'ArrowRight' ? step : 0;
    if (delta === 0) return;
    event.preventDefault();

    const target = resolveTarget(event.currentTarget);
    if (!target) return;
    freezeColumnWidths(target.table, target.headerRow);

    const startWidth = target.th.getBoundingClientRect().width;
    const startTableWidth = target.table.getBoundingClientRect().width;
    applyWidth(target, startWidth + delta, startWidth, startTableWidth);
  };

  const onDoubleClick = (event: React.MouseEvent<HTMLSpanElement>) => {
    event.preventDefault();
    event.stopPropagation();
    const target = resolveTarget(event.currentTarget);
    if (!target) return;
    // Hand the column back to the browser's content-driven sizing.
    target.th.style.removeProperty('width');
  };

  return (
    <span
      role="separator"
      aria-orientation="vertical"
      aria-label={columnLabel ? `Resize ${columnLabel} column` : 'Resize column'}
      tabIndex={0}
      onPointerDown={onPointerDown}
      onKeyDown={onKeyDown}
      onDoubleClick={onDoubleClick}
      title="Drag to resize · double-click to reset"
      className="absolute right-0 top-0 z-10 flex h-full w-2 translate-x-1/2 cursor-col-resize touch-none items-center justify-center focus-visible:outline-none"
    >
      <span
        aria-hidden="true"
        className="h-1/2 w-px rounded bg-white/0 transition-colors group-hover/th:bg-white/40 [span:focus-visible>&]:bg-white [span:hover>&]:bg-white/70"
      />
    </span>
  );
}

export function Th({
  children,
  className,
  scope = 'col',
  resizable = true,
}: {
  children: ReactNode;
  className?: string;
  scope?: 'col' | 'row';
  /** Set false for columns that must keep a fixed width (e.g. a checkbox gutter). */
  resizable?: boolean;
}) {
  return (
    <th
      scope={scope}
      className={cn(
        'group/th relative px-4 py-3 text-left text-xs font-semibold uppercase tracking-wide text-white',
        className,
      )}
    >
      {children}
      {resizable ? (
        <ColumnResizeHandle columnLabel={typeof children === 'string' ? children : undefined} />
      ) : null}
    </th>
  );
}

export function Td({
  children,
  className,
  onClick,
}: {
  children: ReactNode;
  className?: string;
  onClick?: (e: React.MouseEvent<HTMLTableCellElement>) => void;
}) {
  return (
    <td
      className={cn('px-4 py-3 align-middle text-foreground', className)}
      onClick={onClick}
    >
      {children}
    </td>
  );
}

interface SortableThProps {
  children: ReactNode;
  /** Column key — must match a key registered with \`useTableSort\`. */
  sortKey: string;
  /** Currently active sort key on the table (null if none). */
  activeKey: string | null;
  /** Direction of the active sort. Ignored when \`activeKey !== sortKey\`. */
  direction: 'asc' | 'desc';
  onToggle: (key: string) => void;
  className?: string;
  /** Hint shown on hover, e.g. "Sort by severity". */
  ariaLabel?: string;
  /** Set false for columns that must keep a fixed width. */
  resizable?: boolean;
}

export function SortableTh({
  children,
  sortKey,
  activeKey,
  direction,
  onToggle,
  className,
  ariaLabel,
  resizable = true,
}: SortableThProps) {
  const isActive = activeKey === sortKey;
  const ariaSort = isActive ? (direction === 'asc' ? 'ascending' : 'descending') : 'none';

  const Icon = isActive ? (direction === 'asc' ? ArrowUp : ArrowDown) : ArrowUpDown;

  return (
    <th
      scope="col"
      aria-sort={ariaSort}
      className={cn(
        'group/th relative px-4 py-3 text-left text-xs font-semibold uppercase tracking-wide text-white',
        className,
      )}
    >
      <button
        type="button"
        onClick={() => onToggle(sortKey)}
        aria-label={ariaLabel ?? `Sort by ${typeof children === 'string' ? children : sortKey}`}
        className={cn(
          'group inline-flex items-center gap-1 rounded-sm transition-colors text-white/90 hover:text-white focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-white/40',
          isActive && 'text-white',
        )}
      >
        <span>{children}</span>
        <Icon
          className={cn(
            'h-3 w-3 transition-opacity',
            isActive ? 'opacity-100' : 'opacity-40 group-hover:opacity-80',
          )}
          aria-hidden="true"
        />
      </button>
      {resizable ? (
        <ColumnResizeHandle columnLabel={typeof children === 'string' ? children : sortKey} />
      ) : null}
    </th>
  );
}

export function EmptyRow({
  cols,
  message,
  action,
}: {
  cols: number;
  message: string;
  action?: ReactNode;
}) {
  return (
    <tr>
      <td colSpan={cols} className="px-4 py-14 text-center">
        <p className="mx-auto max-w-sm text-sm leading-relaxed text-hcl-muted">{message}</p>
        {action ? <div className="mt-3 flex justify-center">{action}</div> : null}
      </td>
    </tr>
  );
}

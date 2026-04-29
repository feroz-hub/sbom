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
}

export function Table({ children, className, ariaLabel, striped }: TableProps) {
  return (
    <div
      className="overflow-x-auto rounded-lg focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-primary/30"
      role={ariaLabel ? 'region' : undefined}
      aria-label={ariaLabel}
      tabIndex={ariaLabel ? 0 : undefined}
    >
      <table
        className={cn(
          'w-full text-sm',
          striped && '[&_tbody_tr:nth-child(even)]:bg-surface-muted/50',
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
    <thead className="sticky top-0 z-[1] border-b-2 border-border bg-surface-muted">
      {children}
    </thead>
  );
}

export function TableBody({ children }: { children: ReactNode }) {
  return <tbody className="divide-y divide-border/70">{children}</tbody>;
}

export function Th({
  children,
  className,
  scope = 'col',
}: {
  children: ReactNode;
  className?: string;
  scope?: 'col' | 'row';
}) {
  return (
    <th
      scope={scope}
      className={cn(
        'px-4 py-3 text-left text-xs font-semibold uppercase tracking-wide text-hcl-navy',
        className,
      )}
    >
      {children}
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
      className={cn('px-4 py-3 align-middle text-foreground/90', className)}
      onClick={onClick}
    >
      {children}
    </td>
  );
}

interface SortableThProps {
  children: ReactNode;
  /** Column key — must match a key registered with `useTableSort`. */
  sortKey: string;
  /** Currently active sort key on the table (null if none). */
  activeKey: string | null;
  /** Direction of the active sort. Ignored when `activeKey !== sortKey`. */
  direction: 'asc' | 'desc';
  onToggle: (key: string) => void;
  className?: string;
  /** Hint shown on hover, e.g. "Sort by severity". */
  ariaLabel?: string;
}

export function SortableTh({
  children,
  sortKey,
  activeKey,
  direction,
  onToggle,
  className,
  ariaLabel,
}: SortableThProps) {
  const isActive = activeKey === sortKey;
  const ariaSort = isActive ? (direction === 'asc' ? 'ascending' : 'descending') : 'none';

  const Icon = isActive ? (direction === 'asc' ? ArrowUp : ArrowDown) : ArrowUpDown;

  return (
    <th
      scope="col"
      aria-sort={ariaSort}
      className={cn(
        'px-4 py-3 text-left text-xs font-semibold uppercase tracking-wide text-hcl-navy',
        className,
      )}
    >
      <button
        type="button"
        onClick={() => onToggle(sortKey)}
        aria-label={ariaLabel ?? `Sort by ${typeof children === 'string' ? children : sortKey}`}
        className={cn(
          'group inline-flex items-center gap-1 rounded-sm transition-colors hover:text-hcl-blue focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-hcl-blue/30',
          isActive && 'text-hcl-blue',
        )}
      >
        <span>{children}</span>
        <Icon
          className={cn(
            'h-3 w-3 transition-opacity',
            isActive ? 'opacity-100' : 'opacity-30 group-hover:opacity-70',
          )}
          aria-hidden="true"
        />
      </button>
    </th>
  );
}

export function EmptyRow({ cols, message }: { cols: number; message: string }) {
  return (
    <tr>
      <td colSpan={cols} className="px-4 py-14 text-center">
        <p className="mx-auto max-w-sm text-sm leading-relaxed text-hcl-muted">{message}</p>
      </td>
    </tr>
  );
}

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
          'w-full bg-surface text-sm text-foreground',
          striped && '[&_tbody_tr:nth-child(odd)]:bg-surface [&_tbody_tr:nth-child(even)]:bg-row-alt',
          '[&_tbody_tr]:transition-colors [&_tbody_tr]:hover:bg-row-hover',
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
        'px-4 py-3 text-left text-xs font-semibold uppercase tracking-wide text-white',
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
        'px-4 py-3 text-left text-xs font-semibold uppercase tracking-wide text-white',
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

import React from 'react';
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

export function EmptyRow({ cols, message }: { cols: number; message: string }) {
  return (
    <tr>
      <td colSpan={cols} className="px-4 py-14 text-center">
        <p className="mx-auto max-w-sm text-sm leading-relaxed text-hcl-muted">{message}</p>
      </td>
    </tr>
  );
}

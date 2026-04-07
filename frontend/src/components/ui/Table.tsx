import React from 'react';
import { cn } from '@/lib/utils';
import type { ReactNode } from 'react';

interface TableProps {
  children: ReactNode;
  className?: string;
  /** Accessible name read by screen readers. Appears as a visually-hidden caption. */
  ariaLabel?: string;
}

// The overflow-x-auto wrapper is tabindex=0 so keyboard-only users can scroll
// horizontal overflow (WCAG 2.1.1 Keyboard). role="region" + aria-label turns
// it into a navigable landmark for screen readers.
export function Table({ children, className, ariaLabel }: TableProps) {
  return (
    <div
      className="overflow-x-auto focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-hcl-blue/40 rounded-lg"
      role={ariaLabel ? 'region' : undefined}
      aria-label={ariaLabel}
      tabIndex={ariaLabel ? 0 : undefined}
    >
      <table className={cn('w-full text-sm', className)}>
        {ariaLabel && <caption className="sr-only">{ariaLabel}</caption>}
        {children}
      </table>
    </div>
  );
}

export function TableHead({ children }: { children: ReactNode }) {
  return (
    <thead className="bg-hcl-light border-b-2 border-hcl-border">
      {children}
    </thead>
  );
}

export function TableBody({ children }: { children: ReactNode }) {
  return <tbody className="divide-y divide-hcl-border/60">{children}</tbody>;
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
        'px-4 py-3 text-left text-xs font-semibold text-hcl-navy uppercase tracking-wide',
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
    <td className={cn('px-4 py-3 text-slate-700 align-middle', className)} onClick={onClick}>
      {children}
    </td>
  );
}

export function EmptyRow({ cols, message }: { cols: number; message: string }) {
  return (
    <tr>
      <td colSpan={cols} className="px-4 py-12 text-center text-hcl-muted text-sm">
        {message}
      </td>
    </tr>
  );
}

'use client';

import { Search, X } from 'lucide-react';
import type { ReactNode } from 'react';
import { Button } from '@/components/ui/Button';
import { cn } from '@/lib/utils';

interface TableFilterBarProps {
  children: ReactNode;
  className?: string;
  /** Shown when any filter is active so users can reset. */
  onClear?: () => void;
  clearDisabled?: boolean;
  /** e.g. "Showing 5 of 24" */
  resultHint?: string;
}

export function TableFilterBar({
  children,
  className,
  onClear,
  clearDisabled,
  resultHint,
}: TableFilterBarProps) {
  return (
    <div
      className={cn(
        'flex flex-col gap-3 border-b border-border bg-surface-muted/60 px-4 py-3 sm:flex-row sm:flex-wrap sm:items-end',
        className,
      )}
    >
      <div className="flex min-w-0 flex-1 flex-wrap items-end gap-3">{children}</div>
      <div className="flex shrink-0 items-center gap-2 sm:ml-auto">
        {resultHint ? (
          <p className="text-xs text-hcl-muted tabular-nums" aria-live="polite">
            {resultHint}
          </p>
        ) : null}
        {onClear ? (
          <Button
            type="button"
            variant="ghost"
            size="sm"
            onClick={onClear}
            disabled={clearDisabled}
            className="shrink-0 gap-1"
          >
            <X className="h-3.5 w-3.5" aria-hidden />
            Clear filters
          </Button>
        ) : null}
      </div>
    </div>
  );
}

interface TableSearchInputProps {
  id?: string;
  value: string;
  onChange: (value: string) => void;
  placeholder?: string;
  label?: string;
  className?: string;
}

export function TableSearchInput({
  id = 'table-filter-search',
  value,
  onChange,
  placeholder = 'Search…',
  label = 'Search table',
  className,
}: TableSearchInputProps) {
  return (
    <div className={cn('min-w-[min(100%,18rem)] max-w-md flex-1', className)}>
      <label htmlFor={id} className="mb-1 block text-xs font-medium text-hcl-muted">
        {label}
      </label>
      <div className="relative">
        <Search
          className="pointer-events-none absolute left-3 top-1/2 h-4 w-4 -translate-y-1/2 text-hcl-muted"
          aria-hidden
        />
        <input
          id={id}
          type="search"
          value={value}
          onChange={(e) => onChange(e.target.value)}
          placeholder={placeholder}
          autoComplete="off"
          className={cn(
            'h-10 w-full rounded-lg border border-border bg-surface py-2 pl-9 pr-3 text-sm text-foreground',
            'placeholder:text-hcl-muted',
            'transition-colors placeholder:transition-colors',
            'focus-visible:border-primary focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-primary/30',
          )}
        />
      </div>
    </div>
  );
}

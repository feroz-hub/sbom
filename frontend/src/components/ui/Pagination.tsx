'use client';

import { ChevronLeft, ChevronRight, ChevronsLeft, ChevronsRight } from 'lucide-react';
import { cn } from '@/lib/utils';

interface PaginationProps {
  page: number;
  pageSize: number;
  total: number;
  totalPages: number;
  rangeStart: number;
  rangeEnd: number;
  hasPrev: boolean;
  hasNext: boolean;
  onPageChange: (page: number) => void;
  onPageSizeChange: (size: number) => void;
  pageSizeOptions?: number[];
  /** Singular noun used in "Showing X-Y of Z findings". */
  itemNoun?: string;
  className?: string;
}

const DEFAULT_PAGE_SIZE_OPTIONS = [10, 25, 50, 100];

function pageRange(current: number, total: number): (number | 'ellipsis')[] {
  // Compact pager: always show first / last and a small window around the
  // current page, with "…" sentinels for skipped ranges. ~7 slots max.
  if (total <= 7) {
    return Array.from({ length: total }, (_, i) => i + 1);
  }
  const out: (number | 'ellipsis')[] = [1];
  const start = Math.max(2, current - 1);
  const end = Math.min(total - 1, current + 1);
  if (start > 2) out.push('ellipsis');
  for (let i = start; i <= end; i += 1) out.push(i);
  if (end < total - 1) out.push('ellipsis');
  out.push(total);
  return out;
}

export function Pagination({
  page,
  pageSize,
  total,
  totalPages,
  rangeStart,
  rangeEnd,
  hasPrev,
  hasNext,
  onPageChange,
  onPageSizeChange,
  pageSizeOptions = DEFAULT_PAGE_SIZE_OPTIONS,
  itemNoun = 'item',
  className,
}: PaginationProps) {
  if (total === 0) return null;

  const range = pageRange(page, totalPages);
  const noun = total === 1 ? itemNoun : `${itemNoun}s`;

  return (
    <nav
      aria-label="Pagination"
      className={cn(
        'flex flex-col gap-3 border-t border-hcl-border bg-surface px-4 py-3 text-sm sm:flex-row sm:items-center sm:justify-between',
        className,
      )}
    >
      <div className="flex flex-wrap items-center gap-3">
        <span className="text-xs text-hcl-muted tabular-nums">
          Showing <span className="font-medium text-hcl-navy">{rangeStart.toLocaleString()}</span>
          {' – '}
          <span className="font-medium text-hcl-navy">{rangeEnd.toLocaleString()}</span>
          {' of '}
          <span className="font-medium text-hcl-navy">{total.toLocaleString()}</span> {noun}
        </span>

        <label className="flex items-center gap-2 text-xs text-hcl-muted">
          <span className="hidden sm:inline">Rows per page</span>
          <span className="sm:hidden">Rows</span>
          <select
            value={pageSize}
            onChange={(e) => onPageSizeChange(Number(e.target.value))}
            className="rounded-md border border-hcl-border bg-surface px-2 py-1 text-xs text-hcl-navy focus:border-hcl-blue focus:outline-none focus:ring-2 focus:ring-hcl-blue/20"
            aria-label="Rows per page"
          >
            {pageSizeOptions.map((size) => (
              <option key={size} value={size}>
                {size}
              </option>
            ))}
          </select>
        </label>
      </div>

      <div className="flex items-center gap-1">
        <button
          type="button"
          onClick={() => onPageChange(1)}
          disabled={!hasPrev}
          aria-label="First page"
          className="rounded-md border border-hcl-border p-1.5 text-hcl-muted transition-colors hover:bg-hcl-light hover:text-hcl-navy disabled:cursor-not-allowed disabled:opacity-40 disabled:hover:bg-transparent disabled:hover:text-hcl-muted"
        >
          <ChevronsLeft className="h-4 w-4" />
        </button>
        <button
          type="button"
          onClick={() => onPageChange(page - 1)}
          disabled={!hasPrev}
          aria-label="Previous page"
          className="rounded-md border border-hcl-border p-1.5 text-hcl-muted transition-colors hover:bg-hcl-light hover:text-hcl-navy disabled:cursor-not-allowed disabled:opacity-40 disabled:hover:bg-transparent disabled:hover:text-hcl-muted"
        >
          <ChevronLeft className="h-4 w-4" />
        </button>

        <ul className="flex items-center gap-1">
          {range.map((entry, idx) => {
            if (entry === 'ellipsis') {
              return (
                <li
                  key={`ellipsis-${idx}`}
                  className="px-2 text-xs text-hcl-muted"
                  aria-hidden="true"
                >
                  …
                </li>
              );
            }
            const isCurrent = entry === page;
            return (
              <li key={entry}>
                <button
                  type="button"
                  onClick={() => onPageChange(entry)}
                  aria-current={isCurrent ? 'page' : undefined}
                  className={cn(
                    'min-w-[2rem] rounded-md border px-2 py-1 text-xs font-medium transition-colors tabular-nums',
                    isCurrent
                      ? 'border-hcl-blue bg-hcl-blue text-white'
                      : 'border-hcl-border text-hcl-muted hover:bg-hcl-light hover:text-hcl-navy',
                  )}
                >
                  {entry}
                </button>
              </li>
            );
          })}
        </ul>

        <button
          type="button"
          onClick={() => onPageChange(page + 1)}
          disabled={!hasNext}
          aria-label="Next page"
          className="rounded-md border border-hcl-border p-1.5 text-hcl-muted transition-colors hover:bg-hcl-light hover:text-hcl-navy disabled:cursor-not-allowed disabled:opacity-40 disabled:hover:bg-transparent disabled:hover:text-hcl-muted"
        >
          <ChevronRight className="h-4 w-4" />
        </button>
        <button
          type="button"
          onClick={() => onPageChange(totalPages)}
          disabled={!hasNext}
          aria-label="Last page"
          className="rounded-md border border-hcl-border p-1.5 text-hcl-muted transition-colors hover:bg-hcl-light hover:text-hcl-navy disabled:cursor-not-allowed disabled:opacity-40 disabled:hover:bg-transparent disabled:hover:text-hcl-muted"
        >
          <ChevronsRight className="h-4 w-4" />
        </button>
      </div>
    </nav>
  );
}

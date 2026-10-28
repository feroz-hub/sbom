'use client';

import { useEffect, useMemo, useState } from 'react';

export interface UsePaginationOptions {
  /** Initial page size. Must match one of `pageSizeOptions` if provided. */
  defaultPageSize?: number;
  /** Storage key for persisting page-size across reloads. Skip persistence if omitted. */
  storageKey?: string;
}

export interface UsePaginationResult<T> {
  page: number;
  pageSize: number;
  totalPages: number;
  total: number;
  pageItems: T[];
  /** 1-based start of the current page (0 if empty). */
  rangeStart: number;
  /** 1-based end of the current page (0 if empty). */
  rangeEnd: number;
  setPage: (page: number) => void;
  setPageSize: (size: number) => void;
  /** Reset to page 1. Call when filters change. */
  resetPage: () => void;
  goNext: () => void;
  goPrev: () => void;
  goFirst: () => void;
  goLast: () => void;
  hasNext: boolean;
  hasPrev: boolean;
}

const DEFAULT_PAGE_SIZE = 25;

function readStoredPageSize(key: string | undefined, fallback: number): number {
  if (!key || typeof window === 'undefined') return fallback;
  try {
    const raw = window.localStorage.getItem(`sbom.pagesize.${key}`);
    if (!raw) return fallback;
    const n = Number(raw);
    return Number.isFinite(n) && n > 0 ? n : fallback;
  } catch {
    return fallback;
  }
}

function writeStoredPageSize(key: string | undefined, size: number): void {
  if (!key || typeof window === 'undefined') return;
  try {
    window.localStorage.setItem(`sbom.pagesize.${key}`, String(size));
  } catch {
    // ignore quota / privacy-mode errors
  }
}

/**
 * Client-side pagination over an in-memory list. Pair with sort + filter
 * upstream so the slice always operates on the user's filtered/sorted view.
 */
export function usePagination<T>(
  items: T[],
  options: UsePaginationOptions = {},
): UsePaginationResult<T> {
  const { defaultPageSize = DEFAULT_PAGE_SIZE, storageKey } = options;

  const initialSize = readStoredPageSize(storageKey, defaultPageSize);
  const [page, setPageRaw] = useState(1);
  const [pageSize, setPageSizeRaw] = useState(initialSize);

  const total = items.length;
  const totalPages = Math.max(1, Math.ceil(total / pageSize));

  // Clamp the page to a valid range whenever the underlying data shrinks
  // (filter applied, rows removed). Preserve the user's intent otherwise.
  useEffect(() => {
    if (page > totalPages) setPageRaw(totalPages);
    if (page < 1) setPageRaw(1);
  }, [page, totalPages]);

  const pageItems = useMemo(() => {
    const start = (page - 1) * pageSize;
    return items.slice(start, start + pageSize);
  }, [items, page, pageSize]);

  const rangeStart = total === 0 ? 0 : (page - 1) * pageSize + 1;
  const rangeEnd = total === 0 ? 0 : Math.min(page * pageSize, total);

  const setPage = (next: number) => {
    const clamped = Math.min(Math.max(1, next), totalPages);
    setPageRaw(clamped);
  };

  const setPageSize = (size: number) => {
    if (!Number.isFinite(size) || size <= 0) return;
    setPageSizeRaw(size);
    setPageRaw(1);
    writeStoredPageSize(storageKey, size);
  };

  return {
    page,
    pageSize,
    totalPages,
    total,
    pageItems,
    rangeStart,
    rangeEnd,
    setPage,
    setPageSize,
    resetPage: () => setPageRaw(1),
    goNext: () => setPage(page + 1),
    goPrev: () => setPage(page - 1),
    goFirst: () => setPage(1),
    goLast: () => setPage(totalPages),
    hasNext: page < totalPages,
    hasPrev: page > 1,
  };
}

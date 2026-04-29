'use client';

import { useMemo, useState } from 'react';

export type SortDirection = 'asc' | 'desc';

export interface SortState<K extends string> {
  key: K | null;
  direction: SortDirection;
}

export interface UseTableSortOptions<K extends string> {
  initialKey?: K;
  initialDirection?: SortDirection;
}

export interface UseTableSortResult<T, K extends string> {
  sort: SortState<K>;
  /** Sorted view of `rows`. Returns `rows` unchanged when no key is active. */
  sortedRows: T[];
  /** Click a header — toggle direction if same key, else activate ascending. */
  toggle: (key: K) => void;
  /** Set sort direction explicitly. */
  setSort: (next: SortState<K>) => void;
}

type Comparator<T> = (a: T, b: T) => number;

/**
 * Generic in-memory table sort with stable ordering for ties.
 *
 * `accessors` maps each column key to a value extractor. Strings sort
 * locale-insensitive; numbers numerically; null/undefined always end up last
 * regardless of direction. Tie-breaking falls back to the row's index in the
 * input list so ascending↔descending is fully deterministic.
 */
export function useTableSort<T, K extends string>(
  rows: T[],
  accessors: Record<K, (row: T) => string | number | null | undefined>,
  options: UseTableSortOptions<K> = {},
): UseTableSortResult<T, K> {
  const { initialKey = null, initialDirection = 'asc' } = options;
  const [sort, setSort] = useState<SortState<K>>({
    key: initialKey,
    direction: initialDirection,
  });

  const sortedRows = useMemo(() => {
    if (!sort.key) return rows;
    const accessor = accessors[sort.key];
    if (!accessor) return rows;

    const directionFactor = sort.direction === 'asc' ? 1 : -1;

    const indexed = rows.map((row, index) => ({ row, index }));

    const comparator: Comparator<{ row: T; index: number }> = (a, b) => {
      const va = accessor(a.row);
      const vb = accessor(b.row);

      // Null-like values sort last regardless of direction.
      const aNull = va == null || va === '';
      const bNull = vb == null || vb === '';
      if (aNull && bNull) return a.index - b.index;
      if (aNull) return 1;
      if (bNull) return -1;

      let result = 0;
      if (typeof va === 'number' && typeof vb === 'number') {
        result = va - vb;
      } else {
        result = String(va).localeCompare(String(vb), undefined, {
          numeric: true,
          sensitivity: 'base',
        });
      }
      if (result === 0) return a.index - b.index;
      return result * directionFactor;
    };

    return [...indexed].sort(comparator).map((entry) => entry.row);
  }, [rows, sort, accessors]);

  const toggle = (key: K) => {
    setSort((prev) => {
      if (prev.key !== key) return { key, direction: 'asc' };
      return { key, direction: prev.direction === 'asc' ? 'desc' : 'asc' };
    });
  };

  return { sort, sortedRows, toggle, setSort };
}

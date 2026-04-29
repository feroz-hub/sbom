'use client';

import { useQuery } from '@tanstack/react-query';
import { getSboms } from '@/lib/api';

/** Single list fetch size so Analysis, SBOMs table, and upload dup-check share one React Query cache. */
export const SBOMS_LIST_PAGE_SIZE = 500;

export function useSbomsList(options?: { enabled?: boolean }) {
  return useQuery({
    queryKey: ['sboms'],
    queryFn: ({ signal }) => getSboms(1, SBOMS_LIST_PAGE_SIZE, signal),
    ...options,
  });
}

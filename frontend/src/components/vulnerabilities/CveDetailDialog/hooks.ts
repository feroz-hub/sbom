'use client';

import { useQuery, useQueryClient } from '@tanstack/react-query';
import { useCallback, useRef } from 'react';
import { getCveDetail } from '@/lib/api';
import { classifyVulnId } from '@/lib/vulnIds';
import type { CveDetail, CveDetailWithContext } from '@/types';
import { cveQueryKey } from './queryKey';

export { cveQueryKey };

const HOVER_PREFETCH_MS = 200;

/**
 * Fetches the merged CVE detail. Server is cache-of-record; we keep a 5 min
 * client-side staleTime so the dialog opens instantly within a session
 * after the first fetch.
 */
export function useCveDetail({
  cveId,
  scanId,
  enabled,
}: {
  cveId: string | null;
  scanId?: number | null;
  enabled: boolean;
}) {
  // Suppress the network call for ids the frontend already knows the
  // backend will 400. The state mapper handles the UI; this gate is what
  // makes the "no fetch for FOOBAR-123" test assertable.
  const isRecognised = cveId != null && classifyVulnId(cveId).kind !== 'unknown';
  return useQuery<CveDetail | CveDetailWithContext, Error>({
    queryKey: cveQueryKey(scanId, cveId ?? ''),
    queryFn: ({ signal }) => getCveDetail({ cveId: cveId ?? '', scanId: scanId ?? null }, signal),
    enabled: enabled && Boolean(cveId) && isRecognised,
    staleTime: 5 * 60 * 1000,
    gcTime: 30 * 60 * 1000,
    retry: (failureCount, error) => {
      const status = (error as { status?: number }).status ?? 0;
      return status >= 500 && failureCount < 2;
    },
  });
}

/**
 * Hover-prefetch helper — only fires after the cursor has rested for
 * ``HOVER_PREFETCH_MS`` so a fast scroll doesn't trigger a fetch storm.
 *
 * Usage:
 *   const { onHoverStart, onHoverEnd } = useCveHoverPrefetch();
 *   <button onMouseEnter={onHoverStart(cveId, scanId)} onMouseLeave={onHoverEnd}>
 */
export function useCveHoverPrefetch() {
  const queryClient = useQueryClient();
  const timerRef = useRef<ReturnType<typeof setTimeout> | null>(null);

  const onHoverEnd = useCallback(() => {
    if (timerRef.current != null) {
      clearTimeout(timerRef.current);
      timerRef.current = null;
    }
  }, []);

  const onHoverStart = useCallback(
    (cveId: string, scanId?: number | null) => () => {
      onHoverEnd();
      timerRef.current = setTimeout(() => {
        queryClient.prefetchQuery({
          queryKey: cveQueryKey(scanId, cveId),
          queryFn: ({ signal }) => getCveDetail({ cveId, scanId: scanId ?? null }, signal),
          staleTime: 5 * 60 * 1000,
        });
      }, HOVER_PREFETCH_MS);
    },
    [onHoverEnd, queryClient],
  );

  return { onHoverStart, onHoverEnd };
}

'use client';

import { useContext, useEffect } from 'react';
import { useQuery } from '@tanstack/react-query';
import { getRunAiFixProgress } from '@/lib/api';
import type { AiBatchProgress } from '@/types/ai';
import { AiBatchProgressContext } from './AiBatchProgressContext';

/**
 * Subscribe to a run's batch progress via the global provider.
 *
 * Calling this hook registers the run with the provider on mount; the
 * provider keeps the SSE subscription alive across route changes, so
 * navigating away from the run page and back doesn't reset progress.
 *
 * Returns a TanStack Query result against ``['ai-batch-progress', runId]``.
 * The provider writes to that cache key from its EventSource handler, so
 * the consumer just reads.
 *
 * If no provider is mounted (e.g. in unit tests), the query falls back to
 * a one-shot snapshot — there's no live update path without the provider,
 * which matches the test expectation of a deterministic state.
 */
export function useGlobalAiBatchProgress(
  runId: number | null,
  args: { enabled?: boolean } = {},
) {
  const { enabled = true } = args;
  const ctx = useContext(AiBatchProgressContext);
  const active = enabled && runId != null;

  useEffect(() => {
    if (!active || !ctx) return;
    ctx.register(runId as number);
    // We deliberately do NOT auto-unregister on unmount. The provider
    // keeps the run tracked until terminal status, so navigating away
    // doesn't kill the subscription. Auto-cleanup happens server-side
    // (terminal event) + provider linger timer.
  }, [active, ctx, runId]);

  return useQuery<AiBatchProgress>({
    queryKey: ['ai-batch-progress', runId],
    queryFn: ({ signal }) => getRunAiFixProgress(runId as number, signal),
    enabled: active,
  });
}

/**
 * Hook for the global banner — returns the set of run ids the provider
 * is currently tracking. Empty set when no provider is mounted.
 */
export function useTrackedAiBatches(): readonly number[] {
  const ctx = useContext(AiBatchProgressContext);
  if (!ctx) return [];
  return Array.from(ctx.tracked);
}

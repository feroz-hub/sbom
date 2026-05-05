'use client';

import { useContext, useEffect } from 'react';
import { useQuery } from '@tanstack/react-query';
import { getRunAiBatch, getRunAiFixProgress } from '@/lib/api';
import type { AiBatchProgress } from '@/types/ai';
import {
  AiBatchProgressContext,
  type AiBatchTrackingKey,
} from './AiBatchProgressContext';
import { batchProgressQueryKey } from './AiBatchProgressProvider';

/**
 * Subscribe to a run's batch progress via the global provider.
 *
 * Calling this hook registers the (runId, batchId) tuple with the
 * provider on mount; the provider keeps the SSE subscription alive
 * across route changes, so navigating away from the run page and back
 * doesn't reset progress.
 *
 * ``batchId``: pass ``null`` for the legacy single-batch surface (the
 * provider streams the most-recent batch from the deprecated
 * run-scoped endpoint). Pass a UUID for the multi-batch surface.
 *
 * Returns a TanStack Query result. The provider writes to the cache
 * key from its EventSource handler — consumers just read.
 *
 * If no provider is mounted (unit tests), the query falls back to a
 * one-shot snapshot — there's no live update path without the
 * provider, which matches the test expectation of a deterministic
 * state.
 */
export function useGlobalAiBatchProgress(
  runId: number | null,
  args: {
    enabled?: boolean;
    batchId?: string | null;
    scopeLabel?: string | null;
  } = {},
) {
  const { enabled = true, batchId = null, scopeLabel = null } = args;
  const ctx = useContext(AiBatchProgressContext);
  const active = enabled && runId != null;

  useEffect(() => {
    if (!active || !ctx) return;
    ctx.register({
      runId: runId as number,
      batchId,
      scopeLabel,
    });
    // Deliberately do NOT auto-unregister on unmount. The provider
    // keeps the entry tracked until terminal status, so navigating
    // away doesn't kill the subscription. Auto-cleanup happens
    // server-side (terminal event) + provider linger timer.
  }, [active, ctx, runId, batchId, scopeLabel]);

  return useQuery<AiBatchProgress>({
    queryKey: batchProgressQueryKey(runId ?? -1, batchId),
    queryFn: ({ signal }) => {
      if (batchId == null) {
        return getRunAiFixProgress(runId as number, signal);
      }
      return getRunAiBatch(runId as number, batchId, signal).then(
        (detail) => detail.progress as AiBatchProgress,
      );
    },
    enabled: active,
  });
}

/**
 * Hook for the global banner — returns every tracked entry the
 * provider is following. Empty when no provider is mounted.
 *
 * Returns the *full* tuple list (one entry per concurrent batch),
 * not the legacy ``readonly number[]`` of run ids. Banner code
 * consumes this directly to render per-batch rows with their own
 * scope labels.
 */
export function useTrackedAiBatches(): readonly AiBatchTrackingKey[] {
  const ctx = useContext(AiBatchProgressContext);
  if (!ctx) return [];
  return ctx.tracked;
}

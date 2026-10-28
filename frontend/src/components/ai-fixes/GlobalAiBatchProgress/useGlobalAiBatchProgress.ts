'use client';

import { useContext, useEffect } from 'react';
import { useMutationScope } from '@/hooks/useMutationScope';
import { isAiBatchTerminal, reconcileAiBatchTerminal } from '@/lib/aiBatchSync';
import { useQuery, useQueryClient } from '@tanstack/react-query';
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
function isTrackableStatus(status: AiBatchProgress['status'] | undefined): boolean {
  // A run/batch is worth subscribing to only while it's heading somewhere.
  // Terminal states (and ``undefined``, i.e. an idle 204 → null) must NOT
  // register — otherwise the provider's terminal teardown re-fires forever.
  return (
    status === 'pending' ||
    status === 'queued' ||
    status === 'in_progress' ||
    status === 'paused_budget'
  );
}

export function useGlobalAiBatchProgress(
  runId: string | null,
  args: {
    enabled?: boolean;
    batchId?: string | null;
    scopeLabel?: string | null;
  } = {},
) {
  const { enabled = true, batchId = null, scopeLabel = null } = args;
  const ctx = useContext(AiBatchProgressContext);
  // Pull the *stable* register callback rather than depending on ``ctx``.
  // The provider's context value changes identity every time its tracked
  // set mutates; depending on the whole ``ctx`` made this effect re-run on
  // every (un)register, so a terminal/idle unregister immediately
  // re-registered — an infinite ~9s poll loop. ``register`` is a
  // ``useCallback([])``, so this effect now fires on real state changes only.
  const register = ctx?.register;
  const { key: scopeKey, ready: scopeReady, capture } = useMutationScope();
  const qc = useQueryClient();
  const active = enabled && runId != null && scopeReady;

  const query = useQuery<AiBatchProgress | null>({
    queryKey: batchProgressQueryKey(runId ?? '', batchId),
    queryFn: ({ signal }) => {
      if (batchId == null) {
        return getRunAiFixProgress(runId as string, signal);
      }
      return getRunAiBatch(runId as string, batchId, signal).then(
        (detail) => detail.progress ?? null,
      );
    },
    enabled: active,
  });

  // Only subscribe (open the SSE stream / poll fallback) while a batch is
  // actually running. An idle run (204 → null) or a finished batch never
  // registers, so there's no background polling when nothing is happening.
  // A freshly triggered batch seeds this cache key with a live status (see
  // useTriggerScopedAiFixes), which flips ``shouldTrack`` and subscribes.
  const shouldTrack = active && isTrackableStatus(query.data?.status) && !(query.data && isAiBatchTerminal(query.data));
  useEffect(() => {
    if (!shouldTrack || !register) return;
    register({
      runId: runId as string,
      batchId,
      scopeLabel,
    });
    // Deliberately do NOT auto-unregister on unmount. The provider keeps
    // the entry tracked until terminal status, so navigating away doesn't
    // kill the subscription. Auto-cleanup happens server-side (terminal
    // event) + provider linger timer.
  }, [shouldTrack, register, runId, batchId, scopeLabel]);

  useEffect(() => {
    if (!active || !query.data) return;
    void reconcileAiBatchTerminal(qc, { progress: query.data, batchId, scope: scopeKey, isCurrent: capture() });
  }, [active, query.data, batchId, qc, scopeKey, capture]);
  return query;
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

'use client';

import { useCallback, useEffect, useMemo, useRef, useState } from 'react';
import { useQueryClient } from '@tanstack/react-query';
import {
  aiFixBatchStreamUrl,
  aiFixStreamUrl,
  getRunAiBatch,
  getRunAiFixProgress,
} from '@/lib/api';
import type { AiBatchProgress } from '@/types/ai';
import {
  AiBatchProgressContext,
  type AiBatchTrackingKey,
  trackingKeyId,
} from './AiBatchProgressContext';

const POLL_FALLBACK_MS = 2_000;
const TERMINAL_LINGER_MS = 8_000;

function isTerminal(status: AiBatchProgress['status']): boolean {
  return status === 'complete' || status === 'failed' || status === 'cancelled';
}

/** TanStack Query cache key. ``batchId === null`` is the legacy run-only
 *  variant; the new multi-batch flow keys by ``[run_id, batch_id]`` so
 *  two batches on one run live in two cache entries. */
export function batchProgressQueryKey(
  runId: number,
  batchId: string | null,
): readonly unknown[] {
  return batchId == null
    ? ['ai-batch-progress', runId]
    : ['ai-batch-progress', runId, batchId];
}

/**
 * Owns one EventSource per registered tracking key. Renders nothing —
 * its job is to keep the corresponding TanStack Query cache key fresh
 * while the entry stays tracked. Banner / CTA / table-indicator
 * consumers all read the same key without spinning their own
 * subscriptions.
 */
function BatchStreamSubscription({
  entry,
  onTerminal,
}: {
  entry: AiBatchTrackingKey;
  onTerminal(): void;
}) {
  const qc = useQueryClient();
  const onTerminalRef = useRef(onTerminal);
  onTerminalRef.current = onTerminal;

  const { runId, batchId } = entry;

  // Initial snapshot. Without this the cache stays empty until the
  // first SSE message arrives, which can be several seconds for a
  // slow batch.
  useEffect(() => {
    let cancelled = false;
    const fetchInitial = async () => {
      try {
        if (batchId == null) {
          const snap = await getRunAiFixProgress(runId);
          if (cancelled) return;
          qc.setQueryData(batchProgressQueryKey(runId, null), snap);
          if (isTerminal(snap.status)) onTerminalRef.current();
          return;
        }
        const detail = await getRunAiBatch(runId, batchId);
        if (cancelled) return;
        if (detail.progress) {
          qc.setQueryData(batchProgressQueryKey(runId, batchId), detail.progress);
          if (isTerminal(detail.progress.status)) onTerminalRef.current();
        }
      } catch {
        /* SSE/poll loop fills in once the network recovers. */
      }
    };
    fetchInitial();
    return () => {
      cancelled = true;
    };
  }, [runId, batchId, qc]);

  // SSE first; polling fallback when EventSource isn't supported or
  // the stream errors. The poll loop only runs after SSE has failed
  // at least once, so we don't double-subscribe.
  useEffect(() => {
    let stopped = false;
    let pollTimer: ReturnType<typeof setInterval> | null = null;
    let es: EventSource | null = null;

    const queryKey = batchProgressQueryKey(runId, batchId);
    const streamUrl = batchId == null
      ? aiFixStreamUrl(runId)
      : aiFixBatchStreamUrl(runId, batchId);

    const fetchSnapshot = async (): Promise<AiBatchProgress | null> => {
      if (batchId == null) return getRunAiFixProgress(runId);
      try {
        const detail = await getRunAiBatch(runId, batchId);
        return detail.progress;
      } catch {
        return null;
      }
    };

    const startPolling = () => {
      if (stopped || pollTimer) return;
      pollTimer = setInterval(async () => {
        if (stopped) return;
        try {
          const snap = await fetchSnapshot();
          if (snap) {
            qc.setQueryData(queryKey, snap);
            if (isTerminal(snap.status)) {
              stopped = true;
              if (pollTimer) clearInterval(pollTimer);
              onTerminalRef.current();
            }
          }
        } catch {
          /* keep polling */
        }
      }, POLL_FALLBACK_MS);
    };

    if (typeof window === 'undefined' || typeof EventSource === 'undefined') {
      startPolling();
      return () => {
        stopped = true;
        if (pollTimer) clearInterval(pollTimer);
      };
    }

    try {
      es = new EventSource(streamUrl, { withCredentials: false });
    } catch {
      startPolling();
      return () => {
        stopped = true;
        if (pollTimer) clearInterval(pollTimer);
      };
    }

    es.addEventListener('progress', (event: MessageEvent) => {
      try {
        const parsed = JSON.parse(event.data) as AiBatchProgress;
        qc.setQueryData(queryKey, parsed);
        if (isTerminal(parsed.status)) {
          es?.close();
          es = null;
          stopped = true;
          onTerminalRef.current();
        }
      } catch {
        /* drop malformed event; the next one or poll fallback recovers */
      }
    });

    es.addEventListener('end', () => {
      es?.close();
      es = null;
    });

    es.onerror = () => {
      // Connection lost — switch to polling so the banner doesn't go
      // stale during a deploy or transient outage.
      es?.close();
      es = null;
      if (!stopped) startPolling();
    };

    return () => {
      stopped = true;
      es?.close();
      if (pollTimer) clearInterval(pollTimer);
    };
  }, [runId, batchId, qc]);

  return null;
}

interface ProviderProps {
  children: React.ReactNode;
}

/**
 * Wraps the app and tracks every active AI fix batch across navigation.
 * Per Phase 4 multi-batch: the tracked set is keyed by
 * ``${runId}:${batchId}`` so two batches on the same run are
 * independent rows in the global banner.
 */
export function AiBatchProgressProvider({ children }: ProviderProps) {
  const [tracked, setTracked] = useState<Map<string, AiBatchTrackingKey>>(
    () => new Map(),
  );
  // Hold timeouts that auto-unregister terminal batches after a brief
  // linger so the banner can flash a "complete" state.
  const lingerTimers = useRef<Map<string, ReturnType<typeof setTimeout>>>(
    new Map(),
  );

  const register = useCallback((entry: AiBatchTrackingKey) => {
    const id = trackingKeyId(entry);
    setTracked((prev) => {
      const existing = prev.get(id);
      // No-op when the entry's identity AND label are unchanged. New
      // labels (rare — typically the first SSE event refining the
      // banner copy) are merged in so the banner re-renders without
      // dropping the subscription.
      if (existing && existing.scopeLabel === entry.scopeLabel) return prev;
      const next = new Map(prev);
      next.set(id, entry);
      return next;
    });
    // Re-registering after an early unregister cancels any pending
    // linger so the entry isn't dropped while the user is still
    // watching.
    const timer = lingerTimers.current.get(id);
    if (timer) {
      clearTimeout(timer);
      lingerTimers.current.delete(id);
    }
  }, []);

  const unregister = useCallback((runId: number, batchId: string | null) => {
    const id = trackingKeyId({ runId, batchId });
    setTracked((prev) => {
      if (!prev.has(id)) return prev;
      const next = new Map(prev);
      next.delete(id);
      return next;
    });
    const timer = lingerTimers.current.get(id);
    if (timer) {
      clearTimeout(timer);
      lingerTimers.current.delete(id);
    }
  }, []);

  const handleTerminal = useCallback(
    (entry: AiBatchTrackingKey) => {
      const id = trackingKeyId(entry);
      const existing = lingerTimers.current.get(id);
      if (existing) clearTimeout(existing);
      const t = setTimeout(() => {
        lingerTimers.current.delete(id);
        unregister(entry.runId, entry.batchId);
      }, TERMINAL_LINGER_MS);
      lingerTimers.current.set(id, t);
    },
    [unregister],
  );

  // Cleanup pending timers on provider unmount (HMR / route refresh).
  useEffect(() => {
    const map = lingerTimers.current;
    return () => {
      map.forEach((t) => clearTimeout(t));
      map.clear();
    };
  }, []);

  const trackedArray = useMemo(() => Array.from(tracked.values()), [tracked]);

  const contextValue = useMemo(
    () => ({
      tracked: trackedArray as ReadonlyArray<AiBatchTrackingKey>,
      register,
      unregister,
    }),
    [trackedArray, register, unregister],
  );

  return (
    <AiBatchProgressContext.Provider value={contextValue}>
      {children}
      {trackedArray.map((entry) => (
        <BatchStreamSubscription
          key={trackingKeyId(entry)}
          entry={entry}
          onTerminal={() => handleTerminal(entry)}
        />
      ))}
    </AiBatchProgressContext.Provider>
  );
}

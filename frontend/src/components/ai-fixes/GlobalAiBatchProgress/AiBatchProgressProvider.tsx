'use client';

import { useCallback, useEffect, useMemo, useRef, useState } from 'react';
import { useQueryClient } from '@tanstack/react-query';
import { aiFixStreamUrl, getRunAiFixProgress } from '@/lib/api';
import type { AiBatchProgress } from '@/types/ai';
import { AiBatchProgressContext } from './AiBatchProgressContext';

const POLL_FALLBACK_MS = 2_000;
const TERMINAL_LINGER_MS = 8_000;

function isTerminal(status: AiBatchProgress['status']): boolean {
  return status === 'complete' || status === 'failed' || status === 'cancelled';
}

/**
 * Owns one EventSource per registered run. Renders nothing — its job is to
 * keep the ``['ai-batch-progress', runId]`` cache key fresh while the run
 * stays in the provider's tracked set, so any consumer reading the same
 * key (run detail page, global banner, findings table indicator) gets
 * live updates without spinning up its own subscription.
 */
function BatchStreamSubscription({
  runId,
  onTerminal,
}: {
  runId: number;
  onTerminal(): void;
}) {
  const qc = useQueryClient();
  const onTerminalRef = useRef(onTerminal);
  onTerminalRef.current = onTerminal;

  // Initial snapshot. Without this the cache stays empty until the first
  // SSE message arrives, which can be several seconds for a slow batch.
  useEffect(() => {
    let cancelled = false;
    getRunAiFixProgress(runId)
      .then((snap) => {
        if (!cancelled) {
          qc.setQueryData(['ai-batch-progress', runId], snap);
          if (isTerminal(snap.status)) onTerminalRef.current();
        }
      })
      .catch(() => {
        /* The SSE / poll loop will fill in once the network recovers. */
      });
    return () => {
      cancelled = true;
    };
  }, [runId, qc]);

  // SSE first; polling fallback when EventSource isn't supported or the
  // stream errors. The polling loop only runs after SSE has failed at
  // least once, so we don't double-subscribe.
  useEffect(() => {
    let stopped = false;
    let pollTimer: ReturnType<typeof setInterval> | null = null;
    let es: EventSource | null = null;

    const startPolling = () => {
      if (stopped || pollTimer) return;
      pollTimer = setInterval(async () => {
        if (stopped) return;
        try {
          const snap = await getRunAiFixProgress(runId);
          qc.setQueryData(['ai-batch-progress', runId], snap);
          if (isTerminal(snap.status)) {
            stopped = true;
            if (pollTimer) clearInterval(pollTimer);
            onTerminalRef.current();
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
      es = new EventSource(aiFixStreamUrl(runId), { withCredentials: false });
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
        qc.setQueryData(['ai-batch-progress', runId], parsed);
        if (isTerminal(parsed.status)) {
          es?.close();
          es = null;
          stopped = true;
          onTerminalRef.current();
        }
      } catch {
        /* drop malformed event; the next one or the poll fallback recovers */
      }
    });

    es.addEventListener('end', () => {
      es?.close();
      es = null;
    });

    es.onerror = () => {
      // Connection lost — close the stream and switch to polling so the
      // banner doesn't go stale during a deploy or transient outage.
      es?.close();
      es = null;
      if (!stopped) startPolling();
    };

    return () => {
      stopped = true;
      es?.close();
      if (pollTimer) clearInterval(pollTimer);
    };
  }, [runId, qc]);

  return null;
}

interface ProviderProps {
  children: React.ReactNode;
}

/**
 * Wraps the app and tracks active AI fix batches across navigation.
 * Reads/writes via TanStack Query cache key ``['ai-batch-progress', runId]``,
 * so consumers can use ``useQuery`` against the same key without knowing
 * a provider exists.
 */
export function AiBatchProgressProvider({ children }: ProviderProps) {
  const [tracked, setTracked] = useState<Set<number>>(() => new Set());
  // Hold timeouts that auto-unregister terminal batches after a brief
  // linger so the global banner can flash a "complete" state.
  const lingerTimers = useRef<Map<number, ReturnType<typeof setTimeout>>>(
    new Map(),
  );

  const register = useCallback((runId: number) => {
    setTracked((prev) => {
      if (prev.has(runId)) return prev;
      const next = new Set(prev);
      next.add(runId);
      return next;
    });
    // Re-registering after an early unregister cancels any pending
    // linger so the run isn't dropped while the user is still watching.
    const timer = lingerTimers.current.get(runId);
    if (timer) {
      clearTimeout(timer);
      lingerTimers.current.delete(runId);
    }
  }, []);

  const unregister = useCallback((runId: number) => {
    setTracked((prev) => {
      if (!prev.has(runId)) return prev;
      const next = new Set(prev);
      next.delete(runId);
      return next;
    });
    const timer = lingerTimers.current.get(runId);
    if (timer) {
      clearTimeout(timer);
      lingerTimers.current.delete(runId);
    }
  }, []);

  const handleTerminal = useCallback(
    (runId: number) => {
      const existing = lingerTimers.current.get(runId);
      if (existing) clearTimeout(existing);
      const t = setTimeout(() => {
        lingerTimers.current.delete(runId);
        unregister(runId);
      }, TERMINAL_LINGER_MS);
      lingerTimers.current.set(runId, t);
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

  const contextValue = useMemo(
    () => ({ tracked: tracked as ReadonlySet<number>, register, unregister }),
    [tracked, register, unregister],
  );

  return (
    <AiBatchProgressContext.Provider value={contextValue}>
      {children}
      {Array.from(tracked).map((runId) => (
        <BatchStreamSubscription
          key={runId}
          runId={runId}
          onTerminal={() => handleTerminal(runId)}
        />
      ))}
    </AiBatchProgressContext.Provider>
  );
}

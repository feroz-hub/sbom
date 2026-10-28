'use client';

import { useCallback, useEffect, useMemo, useRef, useState } from 'react';
import { useMutationScope } from '@/hooks/useMutationScope';
import { isAiBatchTerminal, reconcileAiBatchTerminal } from '@/lib/aiBatchSync';
import { useQueryClient } from '@tanstack/react-query';
import {
  HttpError,
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
// Defensive watchdog: an entry tracked this long without ever reaching
// a terminal status is almost certainly a leak (e.g. a backend that
// silently never emits ``complete``). Force-unregister so the banner
// row can't survive across an entire workday.
const STALE_TRACKING_TIMEOUT_MS = 60 * 60_000;

/** TanStack Query cache key. ``batchId === null`` is the legacy run-only
 *  variant; the new multi-batch flow keys by ``[run_id, batch_id]`` so
 *  two batches on one run live in two cache entries. */
export function batchProgressQueryKey(
  runId: string,
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
  const { key: scopeKey, ready: scopeReady, capture } = useMutationScope();
  const onTerminalRef = useRef(onTerminal);
  onTerminalRef.current = onTerminal;
  const { runId, batchId } = entry;

  useEffect(() => {
    if (!scopeReady) return;
    const isCurrent = capture();
    const controller = new AbortController();
    let stopped = false, reading = false, revision = 0;
    let pollTimer: ReturnType<typeof setInterval> | null = null;
    let es: EventSource | null = null;
    const queryKey = batchProgressQueryKey(runId, batchId);
    const stop = () => {
      stopped = true; es?.close(); es = null;
      if (pollTimer) { clearInterval(pollTimer); pollTimer = null; }
    };
    const accept = (snap: AiBatchProgress) => {
      if (stopped || !isCurrent() || snap.run_id !== runId || (batchId != null && snap.batch_id != null && snap.batch_id !== batchId)) return;
      revision += 1;
      qc.setQueryData(queryKey, snap);
      if (isAiBatchTerminal(snap)) {
        stop();
        void reconcileAiBatchTerminal(qc, { progress: snap, batchId, scope: scopeKey, isCurrent });
        onTerminalRef.current();
      }
    };
    const read = async () => {
      if (stopped || reading || !isCurrent()) return;
      reading = true; const before = revision;
      try {
        const snap = batchId == null ? await getRunAiFixProgress(runId, controller.signal)
          : (await getRunAiBatch(runId, batchId, controller.signal)).progress;
        if (stopped || !isCurrent() || before !== revision) return;
        if (snap) accept(snap);
        else if (batchId == null) { qc.setQueryData(queryKey, null); stop(); onTerminalRef.current(); }
      } catch (err) {
        if (!stopped && isCurrent() && err instanceof HttpError && err.status === 404) { stop(); onTerminalRef.current(); }
        // Network/server failures retain tracking and use the existing fallback.
      } finally { reading = false; }
    };
    const startPolling = () => {
      if (!stopped && !pollTimer && isCurrent()) pollTimer = setInterval(() => { void read(); }, POLL_FALLBACK_MS);
    };
    // Registration commonly follows an authoritative query/trigger snapshot.
    // Reuse it rather than immediately issuing the same HTTP read again.
    const cached = qc.getQueryData<AiBatchProgress | null>(queryKey);
    if (cached) accept(cached);
    else if (cached === null) { stop(); onTerminalRef.current(); }
    else void read();
    if (stopped) return () => { controller.abort(); };
    const url = batchId == null ? aiFixStreamUrl(runId) : aiFixBatchStreamUrl(runId, batchId);
    if (typeof window === 'undefined' || typeof EventSource === 'undefined') startPolling();
    else {
      try {
        es = new EventSource(url, { withCredentials: true });
        es.addEventListener('progress', (event: MessageEvent) => {
          try { accept(JSON.parse(event.data) as AiBatchProgress); } catch { /* malformed events are ignored */ }
        });
        es.addEventListener('end', () => { es?.close(); es = null; startPolling(); });
        es.onerror = () => { es?.close(); es = null; startPolling(); };
      } catch { startPolling(); }
    }
    return () => { stop(); controller.abort(); };
  }, [runId, batchId, qc, scopeKey, scopeReady, capture]);

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
  const { key: scopeKey, ready: scopeReady } = useMutationScope();
  return <ScopedAiBatchProgressProvider identity={`${scopeKey}:${scopeReady}`} enabled={scopeReady}>{children}</ScopedAiBatchProgressProvider>;
}

function ScopedAiBatchProgressProvider({ children, enabled, identity }: ProviderProps & { enabled: boolean; identity: string }) {
  const [tracking, setTracking] = useState<{ identity: string; entries: Map<string, AiBatchTrackingKey> }>(() => ({ identity, entries: new Map() }));
  const tracked = tracking.identity === identity && enabled ? tracking.entries : null;
  const identityRef = useRef(identity);
  identityRef.current = identity;
  const setTracked = useCallback((update: (previous: Map<string, AiBatchTrackingKey>) => Map<string, AiBatchTrackingKey>) => {
    if (identityRef.current !== identity || !enabled) return;
    setTracking(previous => {
      if (identityRef.current !== identity) return previous;
      const entries = previous.identity === identity ? previous.entries : new Map<string, AiBatchTrackingKey>();
      const next = update(entries);
      return previous.identity === identity && next === entries ? previous : { identity, entries: next };
    });
  }, [identity, enabled]);
  useEffect(() => {
    setTracking(previous => previous.identity === identity ? previous : { identity, entries: new Map() });
  }, [identity]);
  // Hold timeouts that auto-unregister terminal batches after a brief
  // linger so the banner can flash a "complete" state.
  const lingerTimers = useRef<Map<string, ReturnType<typeof setTimeout>>>(
    new Map(),
  );
  const staleTimers = useRef<Map<string, ReturnType<typeof setTimeout>>>(
    new Map(),
  );

  const register = useCallback((entry: AiBatchTrackingKey) => {
    if (!enabled || identityRef.current !== identity) return;
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
    // Arm the stale watchdog. Cleared when the entry transitions to
    // terminal (handleTerminal) or is explicitly unregistered.
    if (!staleTimers.current.has(id)) {
      const t = setTimeout(() => {
        staleTimers.current.delete(id);
        // Inline drop to avoid a stale closure over `unregister`.
        setTracked((prev) => {
          if (!prev.has(id)) return prev;
          const next = new Map(prev);
          next.delete(id);
          return next;
        });
        const lt = lingerTimers.current.get(id);
        if (lt) {
          clearTimeout(lt);
          lingerTimers.current.delete(id);
        }
      }, STALE_TRACKING_TIMEOUT_MS);
      staleTimers.current.set(id, t);
    }
  }, [enabled, identity, setTracked]);

  const unregister = useCallback((runId: string, batchId: string | null) => {
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
    const stale = staleTimers.current.get(id);
    if (stale) {
      clearTimeout(stale);
      staleTimers.current.delete(id);
    }
  }, [setTracked]);

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
    const linger = lingerTimers.current;
    const stale = staleTimers.current;
    return () => {
      linger.forEach((t) => clearTimeout(t));
      linger.clear();
      stale.forEach((t) => clearTimeout(t));
      stale.clear();
    };
  }, [identity]);

  const trackedArray = useMemo(() => tracked ? Array.from(tracked.values()) : [], [tracked]);

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

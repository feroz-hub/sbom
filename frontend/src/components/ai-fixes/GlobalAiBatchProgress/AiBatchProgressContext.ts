'use client';

import { createContext } from 'react';

/**
 * Identity of one tracked batch.
 *
 * ``batchId === null`` means the legacy run-scoped subscription — we
 * stream the most-recent batch via the deprecated SSE endpoint. Used
 * by call sites that haven't been migrated to the multi-batch surface
 * yet.
 */
export interface AiBatchTrackingKey {
  runId: number;
  batchId: string | null;
  /** Banner copy. Pre-supplied at register time so the row can render
   *  without waiting for the first progress event. */
  scopeLabel?: string | null;
}

export interface AiBatchProgressContextValue {
  /** Currently-tracked entries. The provider opens an SSE subscription per entry. */
  tracked: ReadonlyArray<AiBatchTrackingKey>;
  /** Add a (runId, batchId) pair to the tracked list. Idempotent. Pass
   *  ``batchId=null`` for the legacy single-batch subscription. */
  register(entry: AiBatchTrackingKey): void;
  /** Remove a tracked entry. Auto-called for terminal batches after
   *  the linger timer. */
  unregister(runId: number, batchId: string | null): void;
}

export const AiBatchProgressContext =
  createContext<AiBatchProgressContextValue | null>(null);

export function trackingKeyId(entry: AiBatchTrackingKey): string {
  return entry.batchId == null
    ? `legacy:${entry.runId}`
    : `${entry.runId}:${entry.batchId}`;
}

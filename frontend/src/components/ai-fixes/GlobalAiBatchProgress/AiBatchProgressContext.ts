'use client';

import { createContext } from 'react';

export interface AiBatchProgressContextValue {
  /** Currently-tracked runs. The provider opens an SSE subscription for each. */
  tracked: ReadonlySet<number>;
  /** Add a run to the tracked set. Idempotent; safe to call from a render
   *  effect without causing churn. */
  register(runId: number): void;
  /** Remove a run from the tracked set. Normally called automatically when
   *  a batch reaches a terminal state — consumers can call manually to
   *  cancel tracking early. */
  unregister(runId: number): void;
}

export const AiBatchProgressContext =
  createContext<AiBatchProgressContextValue | null>(null);

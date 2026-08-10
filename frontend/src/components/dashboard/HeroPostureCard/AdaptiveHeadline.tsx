'use client';

import { cn } from '@/lib/utils';
import {
  computeHeadlineCopy,
  toneToHeadlineClass,
  type HeadlineInputs,
} from '@/lib/headlineCopy';
import type { HeadlineState } from '@/types';

interface AdaptiveHeadlineProps {
  /** Server-computed posture framing — see `docs/dashboard-redesign.md` §2. */
  state: HeadlineState;
  /** Counts the rule may interpolate into the headline / sub-line. */
  data: HeadlineInputs;
}

/**
 * The single most-visible piece of dashboard copy. State and data come
 * from the API; this component is pure presentation. `aria-live="polite"`
 * so screen readers announce posture changes without interrupting the
 * user mid-task — same pattern as the v1 hero.
 */
export function AdaptiveHeadline({ state, data }: AdaptiveHeadlineProps) {
  const copy = computeHeadlineCopy(state, data);
  const headlineToneClass = toneToHeadlineClass(copy.tone);

  return (
    <div role="status" aria-live="polite" className="min-w-0 space-y-2">
      <h2
        className={cn(
          'text-display-lg font-semibold tracking-display',
          headlineToneClass,
        )}
      >
        {copy.headline}
      </h2>
      <p className="max-w-2xl text-sm leading-relaxed text-hcl-muted">
        {copy.subline}
      </p>
    </div>
  );
}

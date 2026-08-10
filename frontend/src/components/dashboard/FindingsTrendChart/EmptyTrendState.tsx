'use client';

import { EmptyState } from '@/components/ui/EmptyState';

interface EmptyTrendStateProps {
  /** How many runs have happened so far. Powers the "{N} runs so far" line. */
  runsSoFar: number;
}

/**
 * Renders when fewer than ~7 days of run history exists. Tells the user
 * the chart is "warming up" rather than implying their portfolio is
 * empty — accuracy matters more than aesthetics here.
 *
 * Locked copy from `docs/dashboard-redesign.md` §5.1.
 */
export function EmptyTrendState({ runsSoFar }: EmptyTrendStateProps) {
  const tail =
    runsSoFar === 0
      ? 'Run an analysis to start the series.'
      : `${runsSoFar.toLocaleString()} ${runsSoFar === 1 ? 'run' : 'runs'} so far.`;
  return (
    <EmptyState
      illustration="no-runs"
      title="Trend will appear after a week of regular scanning"
      description={tail}
      compact
    />
  );
}

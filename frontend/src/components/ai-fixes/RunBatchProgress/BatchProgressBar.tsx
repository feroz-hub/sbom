'use client';

import type { AiBatchProgress } from '@/types/ai';

interface BatchProgressBarProps {
  progress: AiBatchProgress;
}

/**
 * Stacked progress bar — cache hits land on the left (green), generated
 * misses fill the middle (primary), failures pile up on the right (red).
 *
 * Avoids ARIA's single-value progressbar role since we're showing a
 * three-way split — instead we expose semantic numbers via
 * ``aria-label``.
 */
export function BatchProgressBar({ progress }: BatchProgressBarProps) {
  const total = Math.max(progress.total, 1);
  const cachePct = Math.min((progress.from_cache / total) * 100, 100);
  const generatedPct = Math.min((progress.generated / total) * 100, 100);
  const failedPct = Math.min((progress.failed / total) * 100, 100);

  const label =
    `${progress.from_cache} cached, ${progress.generated} generated, ${progress.failed} failed of ${progress.total}`;

  return (
    <div
      className="h-2 w-full overflow-hidden rounded-full bg-surface-muted"
      role="progressbar"
      aria-label={label}
      aria-valuemin={0}
      aria-valuemax={progress.total}
      aria-valuenow={progress.from_cache + progress.generated + progress.failed}
    >
      <div className="flex h-full">
        <div
          className="h-full bg-emerald-500 transition-[width] duration-300"
          style={{ width: `${cachePct}%` }}
        />
        <div
          className="h-full bg-primary transition-[width] duration-300"
          style={{ width: `${generatedPct}%` }}
        />
        <div
          className="h-full bg-red-500 transition-[width] duration-300"
          style={{ width: `${failedPct}%` }}
        />
      </div>
    </div>
  );
}

'use client';

import { CircleX } from 'lucide-react';
import type { EnrichedFinding } from '@/types';

interface SelectionToolbarProps {
  /** Selected finding IDs — drives the count + summary copy. */
  selectedIds: ReadonlySet<number>;
  /** Findings currently in scope (post-server-fetch, pre-pagination)
   *  so the summary can compute "across N severities" without seeing
   *  the rows from other pages. */
  findings: ReadonlyArray<EnrichedFinding> | undefined;
  /** Reset the selection to an empty set. */
  onClear: () => void;
}

/**
 * Bulk action affordance shown above the findings table when at least
 * one row is selected. The Generate action lives on the
 * scope-aware CTA above; this toolbar is purely a status + clear
 * surface so users know how many they've picked and have a one-click
 * exit back to filter-driven scope.
 *
 * Selection persists across filter changes — the count here is the
 * full selection size, not just rows currently visible. The "across N
 * severities" summary is computed from whichever findings are in the
 * loaded set; rows on other paginated pages count too because the
 * full-server-fetch hook used by the run detail page returns every
 * finding for the run in one shot.
 */
export function SelectionToolbar({
  selectedIds,
  findings,
  onClear,
}: SelectionToolbarProps) {
  if (selectedIds.size === 0) return null;

  const findingsById = new Map<number, EnrichedFinding>();
  for (const f of findings ?? []) findingsById.set(f.id, f);

  const severities = new Set<string>();
  for (const id of selectedIds) {
    const f = findingsById.get(id);
    if (!f) continue;
    severities.add((f.severity ?? 'UNKNOWN').toUpperCase());
  }

  const summary = severities.size > 0
    ? `${selectedIds.size} selected · across ${severities.size} ${severities.size === 1 ? 'severity' : 'severities'}`
    : `${selectedIds.size} selected`;

  return (
    <div
      role="region"
      aria-label="Selection toolbar"
      aria-live="polite"
      data-testid="selection-toolbar"
      className="motion-reduce:transition-none flex items-center justify-between gap-3 rounded-lg border border-primary/30 bg-primary/5 px-3 py-2 text-sm text-hcl-navy shadow-card transition-[opacity,transform] duration-base dark:bg-primary/10"
    >
      <span className="font-medium tabular-nums" data-testid="selection-summary">
        {summary}
      </span>
      <button
        type="button"
        onClick={onClear}
        className="inline-flex items-center gap-1 rounded-md border border-border-subtle bg-surface px-2 py-1 text-xs font-medium text-hcl-navy hover:bg-surface-muted focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-hcl-blue/30"
        data-testid="selection-clear"
      >
        <CircleX className="h-3.5 w-3.5" aria-hidden />
        Clear selection
      </button>
    </div>
  );
}

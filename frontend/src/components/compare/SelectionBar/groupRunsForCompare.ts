/**
 * Pure grouping helper for the Compare runs picker.
 *
 * The Compare flow's most common workflow is "diff the same SBOM at two
 * points in time." When the user has already picked one side, the other
 * picker should surface other runs of that same logical SBOM at the top of
 * the list — and exclude the already-picked run entirely so the user can't
 * land on a degenerate self-compare.
 *
 * "Same logical SBOM" is identified by ``sbom_name + project_id`` (matching
 * names across different projects are intentionally NOT grouped — they are
 * different logical SBOMs that happen to share a filename).
 *
 * The helper is split out from ``RunPicker`` so it can be unit-tested in
 * isolation without the combobox machinery.
 */

import type { RunSummary } from '@/types/compare';

export interface GroupedRuns {
  /** Other runs of the same logical SBOM as ``pairedRun``, sorted newest-first. */
  primary: RunSummary[];
  /** Everything else, sorted newest-first. */
  other: RunSummary[];
}

/**
 * Decide whether two runs cover the same logical SBOM.
 *
 * We deliberately compare on ``sbom_name + project_id`` rather than
 * ``sbom_id``: the backend assigns a fresh ``sbom_id`` per upload, so two
 * uploads of "the same SBOM" produced on different days actually carry
 * different sbom_ids. ``sbom_name`` alone could collide across projects,
 * which is why ``project_id`` is required to disambiguate.
 */
export function isSameLogicalSbom(a: RunSummary, b: RunSummary): boolean {
  if (a.sbom_name == null || b.sbom_name == null) return false;
  if (a.project_id == null || b.project_id == null) return false;
  return a.sbom_name === b.sbom_name && a.project_id === b.project_id;
}

const completedDescending = (a: RunSummary, b: RunSummary): number => {
  const ta = a.completed_on ? new Date(a.completed_on).getTime() : 0;
  const tb = b.completed_on ? new Date(b.completed_on).getTime() : 0;
  return tb - ta;
};

/**
 * Group ``allRuns`` into a "same SBOM" primary section and an "everything
 * else" other section relative to ``pairedRun``. The paired run itself is
 * always excluded — it would be a degenerate self-compare.
 *
 * When ``pairedRun`` is null (the symmetric "neither side picked yet" case)
 * everything lands in ``other`` and the picker renders a flat list as it
 * did before.
 */
export function groupRunsForCompare(
  allRuns: RunSummary[],
  pairedRun: RunSummary | null | undefined,
): GroupedRuns {
  if (!pairedRun) {
    return {
      primary: [],
      other: [...allRuns].sort(completedDescending),
    };
  }

  const primary: RunSummary[] = [];
  const other: RunSummary[] = [];

  for (const run of allRuns) {
    // Always drop the already-picked run — no self-compare.
    if (run.id === pairedRun.id) continue;
    if (isSameLogicalSbom(run, pairedRun)) {
      primary.push(run);
    } else {
      other.push(run);
    }
  }

  primary.sort(completedDescending);
  other.sort(completedDescending);

  return { primary, other };
}

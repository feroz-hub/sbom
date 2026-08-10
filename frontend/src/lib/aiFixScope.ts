/**
 * Helpers for the scope-aware AI fix CTA.
 *
 * Translates the findings-table filter state (chips, severity dropdown,
 * search) into:
 *
 *   - a backend scope spec (POST body for /ai-fixes and /estimate)
 *   - a human-readable label that drops onto the CTA card and the
 *     progress banner (e.g. "Critical findings", "KEV findings",
 *     "12 critical findings with fixes available")
 *
 * Selection state (Phase 4 row checkboxes) takes precedence over filters
 * — when a non-empty ``finding_ids`` list is provided, the helpers
 * derive the label from the count and ignore filter chips.
 */

import type { AiFixGenerationScope } from '@/types/ai';
import type { FindingsFilterState } from './findingFilters';

const SEVERITY_ORDER: Record<string, number> = {
  CRITICAL: 0,
  HIGH: 1,
  MEDIUM: 2,
  LOW: 3,
  UNKNOWN: 4,
};

const SEVERITY_LABELS: Record<string, string> = {
  CRITICAL: 'critical',
  HIGH: 'high',
  MEDIUM: 'medium',
  LOW: 'low',
  UNKNOWN: 'unknown-severity',
};

type Severity = 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW' | 'UNKNOWN';

const SEVERITY_VALUES: ReadonlyArray<Severity> = [
  'CRITICAL',
  'HIGH',
  'MEDIUM',
  'LOW',
  'UNKNOWN',
];

function isSeverity(value: string): value is Severity {
  return (SEVERITY_VALUES as ReadonlyArray<string>).includes(value);
}

function joinAnd(parts: readonly string[]): string {
  if (parts.length === 0) return '';
  if (parts.length === 1) return parts[0]!;
  if (parts.length === 2) return `${parts[0]} and ${parts[1]}`;
  return `${parts.slice(0, -1).join(', ')}, and ${parts.at(-1)}`;
}

function pluralFinding(n: number): string {
  return n === 1 ? 'finding' : 'findings';
}

export interface ScopeBuildArgs {
  filter: FindingsFilterState;
  /**
   * Selected finding IDs (Phase 4 row checkboxes). When non-empty,
   * filter chips are ignored and the scope is built around these IDs.
   */
  selectedIds?: number[];
}

/**
 * Build a backend scope spec from the current filter + selection
 * state. Returns ``null`` when the user is at "all findings" (no
 * filters, no selection) — callers should treat ``null`` as the
 * legacy "process the entire run" mode.
 */
export function buildScope(args: ScopeBuildArgs): AiFixGenerationScope | null {
  const { filter, selectedIds } = args;
  if (selectedIds && selectedIds.length > 0) {
    const label = `Selected (${selectedIds.length})`;
    return {
      finding_ids: [...selectedIds].sort((a, b) => a - b),
      label,
    };
  }

  const severities: Severity[] = [];
  if (filter.severityFilter && isSeverity(filter.severityFilter)) {
    severities.push(filter.severityFilter);
  }

  const scope: AiFixGenerationScope = {};
  let hasActiveFilter = false;

  if (severities.length > 0) {
    scope.severities = [...severities].sort(
      (a, b) => SEVERITY_ORDER[a]! - SEVERITY_ORDER[b]!,
    );
    hasActiveFilter = true;
  }
  if (filter.kevOnly) {
    scope.kev_only = true;
    hasActiveFilter = true;
  }
  if (filter.hasFixOnly) {
    scope.fix_available_only = true;
    hasActiveFilter = true;
  }
  const trimmed = filter.search.trim();
  if (trimmed.length > 0) {
    scope.search_query = trimmed;
    hasActiveFilter = true;
  }

  if (!hasActiveFilter) return null;

  scope.label = describeScope({ filter, selectedIds: undefined });
  return scope;
}

/**
 * Compose a human-readable description of the active scope for the
 * CTA card and the progress banner. Stable across reorderings of the
 * input filters so two filter combos that resolve to the same scope
 * produce the same string.
 *
 * Examples:
 *   - All findings, no selection           → "all findings"
 *   - severityFilter=CRITICAL              → "Critical findings"
 *   - kevOnly                              → "KEV findings"
 *   - hasFixOnly + severityFilter=HIGH     → "High findings with fixes available"
 *   - kevOnly + severityFilter=CRITICAL    → "Critical KEV findings"
 *   - search_query="log4j"                 → "Findings matching 'log4j'"
 *   - selectedIds=[1,2,3,4,5]              → "5 selected findings"
 *   - finding_ids=[1] (single)             → "1 selected finding"
 */
export function describeScope(args: ScopeBuildArgs): string {
  const { filter, selectedIds } = args;
  if (selectedIds && selectedIds.length > 0) {
    return `${selectedIds.length} selected ${pluralFinding(selectedIds.length)}`;
  }

  const parts: string[] = [];

  // Severity adjective(s) come first ("critical", "critical and high").
  const sevAdjective: string[] = [];
  if (filter.severityFilter && isSeverity(filter.severityFilter)) {
    sevAdjective.push(SEVERITY_LABELS[filter.severityFilter]!);
  }

  // KEV is a noun-modifier ("KEV findings"); compose with severity if present.
  const adjectives = [...sevAdjective];
  if (filter.kevOnly) adjectives.push('KEV');

  // Search shows as a trailing qualifier — distinct enough that we keep
  // it on its own clause for clarity ("findings matching 'log4j'").
  const trimmedSearch = filter.search.trim();
  const tail: string[] = [];
  if (filter.hasFixOnly) tail.push('with fixes available');
  if (trimmedSearch) tail.push(`matching '${trimmedSearch}'`);

  // Compose.
  const head =
    adjectives.length > 0
      ? `${capitalise(joinAdjectives(adjectives))} findings`
      : 'Findings';
  if (tail.length === 0 && adjectives.length === 0) {
    return 'all findings';
  }
  if (tail.length === 0) return head;
  parts.push(head, joinAnd(tail));
  return parts.join(' ');
}

function joinAdjectives(adjectives: readonly string[]): string {
  // "critical and high" but "critical KEV" (KEV is a modifier, not a
  // separate adjective). Severity adjectives are first; KEV slots in
  // last when present.
  if (adjectives.length <= 1) return adjectives.join(' ');
  // If KEV is present + a severity, render "critical KEV" not "critical
  // and KEV" — the former reads as "the critical CVEs that are KEV".
  const sevAdjs = adjectives.filter((a) => a !== 'KEV');
  const hasKev = adjectives.includes('KEV');
  const sevPart = sevAdjs.length === 0 ? '' : joinAnd(sevAdjs);
  if (hasKev && sevPart) return `${sevPart} KEV`;
  if (hasKev) return 'KEV';
  return sevPart;
}

function capitalise(s: string): string {
  if (!s) return s;
  return s[0]!.toUpperCase() + s.slice(1);
}

/**
 * Stable string key for memoizing per-scope queries (e.g. the
 * estimate's React Query cache key). Same scope → same key regardless
 * of input ordering.
 */
export function scopeCacheKey(scope: AiFixGenerationScope | null): string {
  if (!scope) return 'all';
  // Sort severities + finding_ids so two equivalent scopes hash the same.
  const sorted: AiFixGenerationScope = {
    ...scope,
    severities: scope.severities ? [...scope.severities].sort() : undefined,
    finding_ids: scope.finding_ids ? [...scope.finding_ids].sort((a, b) => a - b) : undefined,
  };
  // Drop falsy / undefined entries so JSON.stringify is stable.
  const cleaned: Record<string, unknown> = {};
  for (const [k, v] of Object.entries(sorted)) {
    if (v == null) continue;
    if (typeof v === 'string' && v.trim() === '') continue;
    if (Array.isArray(v) && v.length === 0) continue;
    if (v === false) continue;
    cleaned[k] = v;
  }
  return JSON.stringify(cleaned);
}

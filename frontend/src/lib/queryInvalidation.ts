/**
 * Centralized invalidation helpers — every mutation that creates, updates, or
 * deletes a server resource is expected to call one of these in onSuccess.
 *
 * Keeping the "which keys does this entity touch" mapping in one place
 * prevents new mutations from silently leaving sibling list views stale
 * (the classic "SBOM uploaded but main table doesn't update" bug class).
 *
 * Prefix-match note: TanStack invalidates by array-prefix, so
 * `invalidateQueries({ queryKey: ['sboms'] })` also catches
 * `['sboms', 'for-schedules']` and any future sub-keys.
 */

import type { QueryClient } from '@tanstack/react-query';

export function invalidateSbomLists(qc: QueryClient): void {
  qc.invalidateQueries({ queryKey: ['sboms'] });
  qc.invalidateQueries({ queryKey: ['sidebar-recent-sboms'] });
  qc.invalidateQueries({ queryKey: ['recent-sboms'] });
  qc.invalidateQueries({ queryKey: ['palette-recent-sboms'] });
}

export function invalidateProjectLists(qc: QueryClient): void {
  qc.invalidateQueries({ queryKey: ['projects'] });
}

export function invalidateProjectSurfaces(qc: QueryClient, projectId?: number | null): void {
  invalidateProjectLists(qc);
  if (projectId != null) {
    qc.invalidateQueries({ queryKey: ['project', projectId] });
    qc.invalidateQueries({ queryKey: ['project-detail', projectId] });
    qc.invalidateQueries({ queryKey: ['project-schedule', projectId] });
  }
}

/**
 * Narrow invalidation for SPDX→CycloneDX conversion — avoids dashboard/VEX/risk storms.
 */
export function invalidateSbomConversionSurfaces(
  qc: QueryClient,
  sourceSbomId: number,
  convertedSbomId?: number | null,
): void {
  qc.invalidateQueries({ queryKey: ['sbom', sourceSbomId] });
  qc.invalidateQueries({ queryKey: ['sbom-info', sourceSbomId] });
  qc.invalidateQueries({ queryKey: ['sbom-conversion-report', sourceSbomId] });
  qc.invalidateQueries({ queryKey: ['sboms'] });
  if (convertedSbomId != null) {
    qc.invalidateQueries({ queryKey: ['sbom', convertedSbomId] });
    qc.invalidateQueries({ queryKey: ['sbom-info', convertedSbomId] });
  }
}

export function invalidateSbomSurfaces(qc: QueryClient, sbomId?: number | null): void {
  invalidateSbomLists(qc);
  if (sbomId != null) {
    qc.invalidateQueries({ queryKey: ['sbom', sbomId] });
    qc.invalidateQueries({ queryKey: ['sbom-info', sbomId] });
    qc.invalidateQueries({ queryKey: ['sbom-risk', sbomId] });
    qc.invalidateQueries({ queryKey: ['sbom-components', sbomId] });
    qc.invalidateQueries({ queryKey: ['sbom-dedupe-report', sbomId] });
    qc.invalidateQueries({ queryKey: ['sbom-validation-report', sbomId] });
    qc.invalidateQueries({ queryKey: ['sbom-versions', sbomId] });
    qc.invalidateQueries({ queryKey: ['sbom-vex', sbomId] });
    qc.invalidateQueries({ queryKey: ['sbom-conversion-report', sbomId] });
  }
}

/**
 * Every cache that holds "a list of runs" or "a count derived from runs".
 *
 * Includes recent-run surfaces (sidebar, dashboard activity feed, ⌘K palette),
 * the runs aggregate, top-vulnerable tile, and the compare-picker recents.
 * Excludes per-run detail (`['run', id]`) and per-run findings — those are
 * keyed by a specific run that doesn't change when the run set changes.
 */
export function invalidateRunLists(qc: QueryClient): void {
  qc.invalidateQueries({ queryKey: ['runs'] });
  qc.invalidateQueries({ queryKey: ['runs-aggregate'] });
  qc.invalidateQueries({ queryKey: ['recent-runs'] });
  qc.invalidateQueries({ queryKey: ['sidebar-recent-runs'] });
  qc.invalidateQueries({ queryKey: ['palette-recent-runs'] });
  qc.invalidateQueries({ queryKey: ['top-vulnerable-runs'] });
  qc.invalidateQueries({ queryKey: ['compare', 'picker', 'recent'] });
  qc.invalidateQueries({ queryKey: ['compare', 'picker', 'search'] });
}

export function invalidateScheduleLists(qc: QueryClient): void {
  qc.invalidateQueries({ queryKey: ['schedules'] });
  qc.invalidateQueries({ queryKey: ['schedule'] });
}

/**
 * Dashboard rollup tiles — posture, 30-day trend, lifetime totals.
 *
 * Any event that changes the universe of findings or runs (analysis
 * completion, SBOM/project delete, schedule run-now enqueue) should
 * call this so the dashboard reflects the change without F5.
 */
export function invalidateDashboardTiles(qc: QueryClient): void {
  qc.invalidateQueries({ queryKey: ['dashboard-posture'] });
  qc.invalidateQueries({ queryKey: ['dashboard-trend'] });
  qc.invalidateQueries({ queryKey: ['dashboard-lifetime'] });
  // Dashboard v4 advanced tiles — all derived from the same run/finding
  // universe, so they bust together with the classic tiles.
  qc.invalidateQueries({ queryKey: ['dashboard-forecast'] });
  qc.invalidateQueries({ queryKey: ['dashboard-exploitation'] });
  qc.invalidateQueries({ queryKey: ['dashboard-remediation'] });
  qc.invalidateQueries({ queryKey: ['dashboard-remediation-stats'] });
  qc.invalidateQueries({ queryKey: ['dashboard-lifecycle'] });
  qc.invalidateQueries({ queryKey: ['dashboard-vex'] });
  qc.invalidateQueries({ queryKey: ['dashboard-health'] });
  qc.invalidateQueries({ queryKey: ['dashboard-risk-map'] });
  qc.invalidateQueries({ queryKey: ['dashboard-risk-matrix'] });
  // The Copilot briefing is grounded in those same numbers; the server
  // cache busts on new data, the client cache must follow.
  qc.invalidateQueries({ queryKey: ['copilot-briefing'] });
}

/**
 * Every cache that holds "the findings for a run".
 *
 * Findings are keyed `['findings-enriched', runId, severityFilter]`
 * (see `app/analysis/[id]/page.tsx`). Prefix-invalidating `['findings-
 * enriched']` catches every cached variant — cheap, and avoids stale
 * tags when a run is mutated in place (the AI fix flow + any future
 * re-run-on-same-id path). Roadmap #1 added `match_reason` /
 * `matched_range` to each finding; without this bust, re-scanning a
 * flag-on SBOM left the prior cache intact and the new trust badges
 * stayed invisible until F5.
 */
export function invalidateFindings(qc: QueryClient): void {
  qc.invalidateQueries({ queryKey: ['findings-enriched'] });
}

/**
 * Convenience for the "analysis just completed" event: covers run lists,
 * dashboard tiles, the per-SBOM detail caches whose findings/risk
 * numbers just changed, AND the per-run findings caches so newly-emitted
 * tags (e.g. roadmap #1's `match_reason`) become visible without F5.
 *
 * Pass `sbomId` whenever the caller knows which SBOM the run belongs to —
 * it scopes the per-SBOM cache busts so we don't over-invalidate.
 */
export function invalidateAnalysisCompletion(
  qc: QueryClient,
  args: { sbomId?: number } = {},
): void {
  invalidateRunLists(qc);
  invalidateDashboardTiles(qc);
  // SBOM analysis status badge surfaces in the main table — refresh.
  invalidateSbomLists(qc);
  // Findings caches keyed on runId — prefix-bust so re-runs surface new
  // per-finding fields (e.g. match_reason / matched_range) immediately.
  invalidateFindings(qc);
  if (args.sbomId != null) {
    qc.invalidateQueries({ queryKey: ['sbom-risk', args.sbomId] });
    qc.invalidateQueries({ queryKey: ['sbom-info', args.sbomId] });
    qc.invalidateQueries({ queryKey: ['compare', 'sparkline', args.sbomId] });
  }
}

/**
 * Every cache that derives state from the saved-credentials list.
 *
 * `['ai','credentials']` drives the providers list + status badges, but
 * `['ai-settings','providers']` is a parallel joined query the Settings
 * page composes — adding/removing/switching a credential must bust both,
 * otherwise the Settings page shows a stale provider name until its
 * 60-second staleTime expires.
 *
 * `['analysis-config']` is included because `AiConfigBanner`'s
 * configured-vs-empty branch ultimately depends on whether any
 * credential exists.
 */
export function invalidateAiCredentialSurfaces(qc: QueryClient): void {
  qc.invalidateQueries({ queryKey: ['ai', 'credentials'] });
  qc.invalidateQueries({ queryKey: ['ai-settings'] });
  qc.invalidateQueries({ queryKey: ['analysis-config'] });
}

/**
 * Drops every cached AI fix.
 *
 * Use after: deleting a provider (orphaned per-finding fixes still
 * reference the deleted provider's name), regenerating in bulk, or
 * cancelling a batch (partial fixes are now in a different state).
 */
export function invalidateAiFixCaches(qc: QueryClient): void {
  qc.invalidateQueries({ queryKey: ['ai-fix'] });
  qc.invalidateQueries({ queryKey: ['ai-fix-list'] });
  qc.invalidateQueries({ queryKey: ['ai-batch-progress'] });
}

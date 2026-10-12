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
import type { Project, SBOMSource, VexInvestigationListResponse } from '@/types';

/** Platform tenant mutations affect control-plane rollups and every list variant. */
export async function invalidatePlatformTenantSurfaces(qc: QueryClient, tenantId: number): Promise<void> {
  await Promise.all([
    qc.invalidateQueries({ queryKey: ['platform-summary'] }),
    qc.invalidateQueries({ queryKey: ['platform-tenants'] }),
    qc.invalidateQueries({ queryKey: ['platform-tenant', tenantId] }),
  ]);
}

/** Authority changes also change the active administrator count in the summary. */
export async function invalidatePlatformAdministratorSurfaces(qc: QueryClient): Promise<void> {
  await Promise.all([
    qc.invalidateQueries({ queryKey: ['platform-administrators'] }),
    qc.invalidateQueries({ queryKey: ['platform-summary'] }),
  ]);
}

/** Membership/role changes affect counts and effective administrator coverage. */
export function invalidateTenantMembershipSurfaces(
  qc: QueryClient, tenantId: number, options: { affectsMetrics?: boolean } = {},
): Promise<void> {
  return invalidateUserSurfaces(qc, { tenantIds: [tenantId], affectsMetrics: options.affectsMetrics ?? true });
}

/** Profile/evidence-only changes refresh labels without changing metric values. */
export function invalidateUserSurfaces(
  qc: QueryClient,
  options: { tenantIds: number[]; userId?: number; affectsMetrics?: boolean; accountChanged?: boolean },
): Promise<void> {
  const keys: Array<readonly unknown[]> = [['platform-tenants']];
  const tenants = new Set(options.tenantIds);
  // Tenant profile editors only know their own membership. Include other cached
  // memberships for that same global identity without refetching unrelated details.
  if (options.userId != null && options.accountChanged) {
    for (const [key, rows] of qc.getQueriesData<Array<{ user_id: number }>>({ queryKey: ['tenant-users'] })) {
      if (Array.isArray(rows) && rows.some(row => row.user_id === options.userId)) tenants.add(Number(key[1]));
    }
  }
  for (const id of tenants) {
    if (!Number.isFinite(id) || id <= 0) continue;
    keys.push(['tenant-users', id], ['tenant-roles', id], ['tenant-audit-history', id],
      ['platform-tenant', id], ['vex-assignees', String(id)], ['vex-investigations', String(id)]);
  }
  // Assignment labels/eligibility are projections of membership identity too.
  // Lists carry tenant keys; use their known rows to target unscoped detail keys.
  for (const [key, list] of qc.getQueriesData<VexInvestigationListResponse>({ queryKey: ['vex-investigations'] })) {
    if (!tenants.has(Number(key[1])) || !Array.isArray(list?.items)) continue;
    for (const row of list.items) keys.push(['vex-investigation', row.id], ['vex-investigation-by-triple', row.sbom_id]);
  }
  // Global identity edits can also change administrator display names/status.
  if (options.accountChanged) keys.push(['platform-administrators']);
  if (options.affectsMetrics) keys.push(['platform-summary']);
  return invalidateQueryKeys(qc, keys);
}

export function invalidateReportSurfaces(qc: QueryClient): void {
  qc.invalidateQueries({ queryKey: ['reports'] });
}

/** Inventory choices are mutable; delivery artifacts are not inventory projections. */
export function invalidateReportTargetChoices(qc: QueryClient): Promise<void> {
  return invalidateQueryKeys(qc, [['reports', 'targets']]);
}

export function invalidateSbomLists(qc: QueryClient): Promise<void> {
  return invalidateQueryKeys(qc, [
    'logical-sboms', 'logical-sbom', 'logical-sbom-versions', 'sboms', 'dashboard-sboms',
    'sidebar-recent-sboms', 'recent-sboms', 'palette-recent-sboms',
  ].map(family => [family]).concat([['reports', 'targets']]));
}

export function invalidateProjectLists(qc: QueryClient): Promise<void> {
  return invalidateQueryKeys(qc, [
    ['projects'], ['dashboard-projects'], ['dashboard-applications'], ['dashboard-scanned-projects'],
    ['reports', 'targets'],
  ]);
}

/** Name edits refresh projections; only creation/status changes refresh security rollups. */
export async function invalidateProjectMetadata(
  qc: QueryClient,
  project: Pick<Project, 'id' | 'project_status'>,
  previous?: Pick<Project, 'project_status'> | null,
): Promise<void> {
  const keys: Array<readonly unknown[]> = [
    ['project', project.id], ['project-detail', project.id], ['products', project.id],
    ['dashboard-summary'], ['dashboard-priority-findings'], ['dashboard-operational-runs'],
  ];
  for (const [key, sbom] of qc.getQueriesData<SBOMSource>({ queryKey: ['sbom'] })) {
    if (sbom && (sbom.projectid ?? sbom.project_id) === project.id) keys.push(key, ['sbom-info', sbom.id]);
  }
  await Promise.all([
    invalidateProjectLists(qc), invalidateSbomLists(qc), invalidateQueryKeys(qc, keys),
    !previous || previous.project_status !== project.project_status ? invalidateDashboardTiles(qc) : Promise.resolve(),
  ]);
}

export async function invalidateProjectSurfaces(qc: QueryClient, projectId?: number | null): Promise<void> {
  await Promise.all([invalidateProjectLists(qc), invalidateQueryKeys(qc, projectId == null ? [] : [
    ['project', projectId], ['project-detail', projectId], ['project-schedule', projectId],
  ])]);
}

/**
 * The product detail screen's own caches: the header card and its SBOM table.
 *
 * Omit `productId` to prefix-bust every product's caches — used by callers
 * (analysis completion) that know an SBOM changed but not which product owns it.
 */
export async function invalidateProductSurfaces(qc: QueryClient, productId?: number | null): Promise<void> {
  await Promise.all([
    invalidateVersionPosture(qc),
    invalidateQueryKeys(qc, [
      ['logical-sboms'], ['logical-sbom'], ['logical-sbom-versions'], ['dashboard-applications'],
      ['dashboard-sboms'], ['dashboard-summary'], ['reports', 'targets'],
      productId == null ? ['product'] : ['product', productId],
      productId == null ? ['product-sboms'] : ['product-sboms', productId],
    ]),
  ]);
}

export function invalidateDashboardSummary(qc: QueryClient): Promise<void> {
  return invalidateQueryKeys(qc, [
    ['dashboard-summary'], ['dashboard-posture'], ['dashboard-trend'], ['dashboard-lifetime'],
  ]);
}

export function invalidateLifecycleSummary(qc: QueryClient): void {
  qc.invalidateQueries({ queryKey: ['dashboard-lifecycle'] });
  qc.invalidateQueries({ queryKey: ['dashboard-health'] });
}

export async function invalidateUploadSurfaces(qc: QueryClient, projectId?: number | null, productId?: number | null): Promise<void> {
  await Promise.all([
    invalidateProductSurfaces(qc, productId), invalidateSbomLists(qc), invalidateDashboardSummary(qc),
    projectId == null ? Promise.resolve() : invalidateQueryKeys(qc, [['project', projectId], ['project-detail', projectId]]),
  ]);
}

export async function invalidateProjectAssignmentSurfaces(
  qc: QueryClient,
  args: { sbomId: number; previousProjectId?: number | null; nextProjectId?: number | null;
    previousProductId?: number | null; nextProductId?: number | null },
): Promise<void> {
  const keys: Array<readonly unknown[]> = [
    ['sbom', args.sbomId], ['sbom-info', args.sbomId], ['sbom-versions', args.sbomId],
    ['sbom-posture'], ['dashboard-summary'], ['dashboard-priority-findings'], ['dashboard-operational-runs'],
  ];
  for (const id of new Set([args.previousProjectId, args.nextProjectId])) {
    if (id != null) keys.push(['project', id], ['project-detail', id], ['products', id]);
  }
  for (const id of new Set([args.previousProductId, args.nextProductId])) {
    if (id != null) keys.push(['product', id], ['product-sboms', id]);
  }
  await Promise.all([
    invalidateSbomLists(qc), invalidateProjectLists(qc), invalidateQueryKeys(qc, keys),
    args.previousProjectId !== args.nextProjectId || args.previousProductId !== args.nextProductId
      ? invalidateDashboardTiles(qc) : Promise.resolve(),
  ]);
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
  if (convertedSbomId != null) {
    qc.invalidateQueries({ queryKey: ['sbom', convertedSbomId] });
    qc.invalidateQueries({ queryKey: ['sbom-info', convertedSbomId] });
  }
}

export function invalidateLifecycleOverrideSurfaces(qc: QueryClient, sbomId: number): Promise<void> {
  return invalidateQueryKeys(qc, [
    ['sbom-components', sbomId], ['sbom-components-canonical', sbomId],
    ['dashboard-lifecycle'], ['dashboard-health'], ['dashboard-summary'],
  ]);
}

/** VEX assignments change queue scope, but do not change security metric values. */
export async function invalidateVexSurfaces(
  qc: QueryClient,
  sbomId?: number,
  options: { change?: 'evidence' | 'assignment'; investigationId?: number } = {},
): Promise<void> {
  const keys: Array<readonly unknown[]> = [
    ['vex-investigations'],
    options.investigationId == null ? ['vex-investigation'] : ['vex-investigation', options.investigationId],
    sbomId == null ? ['vex-investigation-by-triple'] : ['vex-investigation-by-triple', sbomId],
  ];
  if (options.change !== 'assignment') {
    for (const family of ['sbom-vex', 'component-vulnerabilities', 'vex-pair-history']) {
      keys.push(sbomId == null ? [family] : [family, sbomId]);
    }
    keys.push(['findings'], ['findings-enriched'], ['dashboard-vex'], ['dashboard-summary']);
  }
  await invalidateQueryKeys(qc, keys);
}

/** Coalesce composed helpers in the same turn, while canceling pre-mutation reads. */
const queuedInvalidations = new WeakMap<QueryClient, Map<string, Promise<void>>>();
async function invalidateQueryKeys(qc: QueryClient, keys: Array<readonly unknown[]>): Promise<void> {
  let queue = queuedInvalidations.get(qc);
  if (!queue) {
    queue = new Map();
    queuedInvalidations.set(qc, queue);
  }
  const pending = queue;
  await Promise.all(keys.map(queryKey => {
    const key = JSON.stringify(queryKey);
    let refresh = pending.get(key);
    if (!refresh) {
      refresh = Promise.resolve().then(() => {
        pending.delete(key);
        return qc.invalidateQueries({ queryKey });
      });
      pending.set(key, refresh);
    }
    return refresh;
  }));
}

export function invalidateRemediationSurfaces(qc: QueryClient): void {
  qc.invalidateQueries({ queryKey: ['dashboard-remediation'] });
  qc.invalidateQueries({ queryKey: ['dashboard-remediation-stats'] });
}

export function invalidateSbomVersionSurfaces(qc: QueryClient, sbomId: number): void {
  qc.invalidateQueries({ queryKey: ['sbom', sbomId] });
  qc.invalidateQueries({ queryKey: ['sbom-components', sbomId] });
  qc.invalidateQueries({ queryKey: ['sbom-versions', sbomId] });
}

/** Restore creates a new revision; omitted ownership falls back to its known parent. */
export async function invalidateSbomRevisionCreated(qc: QueryClient, parent: SBOMSource, revision: SBOMSource): Promise<void> {
  const projectId = revision.projectid !== undefined ? revision.projectid
    : revision.project_id !== undefined ? revision.project_id : parent.projectid;
  const productId = revision.product_id !== undefined ? revision.product_id : parent.product_id;
  await Promise.all([
    invalidateProjectAssignmentSurfaces(qc, {
      sbomId: revision.id, previousProjectId: parent.projectid, nextProjectId: projectId,
      previousProductId: parent.product_id, nextProductId: productId,
    }),
    invalidateQueryKeys(qc, [
      ['sbom', parent.id], ['sbom-info', parent.id], ['sbom-versions', parent.id],
      ['sbom-versions', revision.id], ['sbom-components', revision.id], ['sbom-components-canonical', revision.id],
    ]),
    invalidateDashboardTiles(qc),
  ]);
}

export async function invalidateSbomSurfaces(qc: QueryClient, sbomId?: number | null): Promise<void> {
  const keys: Array<readonly unknown[]> = [];
  if (sbomId != null) {
    keys.push(...['sbom', 'sbom-info', 'sbom-risk', 'sbom-components', 'sbom-components-canonical',
      'sbom-dedupe-report', 'sbom-validation-report', 'sbom-versions', 'sbom-vex',
      'component-vulnerabilities', 'vex-pair-history', 'sbom-conversion-report'].map(family => [family, sbomId]));
    keys.push(['findings'], ['findings-enriched']);
  }
  await Promise.all([invalidateSbomLists(qc), invalidateQueryKeys(qc, keys)]);
}

/**
 * Every cache that holds "a list of runs" or "a count derived from runs".
 *
 * Includes recent-run surfaces (sidebar, dashboard activity feed, ⌘K palette),
 * the runs aggregate, top-vulnerable tile, and the compare-picker recents.
 * Excludes per-run detail (`['run', id]`) and per-run findings — those are
 * keyed by a specific run that doesn't change when the run set changes.
 */
export async function invalidateRunLists(qc: QueryClient): Promise<void> {
  await Promise.all([
    invalidateVersionPosture(qc),
    invalidateQueryKeys(qc, [
      ['runs'], ['runs-aggregate'], ['recent-runs'], ['sidebar-recent-runs'], ['palette-recent-runs'],
      ['top-vulnerable-runs'], ['compare', 'picker', 'recent'], ['compare', 'picker', 'search'],
    ]),
  ]);
}

export function invalidateScheduleLists(qc: QueryClient): Promise<void> {
  return invalidateQueryKeys(qc, [['schedules'], ['schedule'], ['schedule-targets']]);
}

/** Enqueue acknowledgement refreshes execution state, never final finding data. */
export async function invalidateAnalysisSubmission(qc: QueryClient): Promise<void> {
  await Promise.all([invalidateScheduleLists(qc), invalidateRunLists(qc), invalidateSbomLists(qc)]);
}

/**
 * Dashboard rollup tiles — posture, 30-day trend, lifetime totals.
 *
 * Any event that changes the universe of findings or runs (analysis
 * completion, SBOM/project delete, schedule run-now enqueue) should
 * call this so the dashboard reflects the change without F5.
 */
export async function invalidateDashboardTiles(qc: QueryClient): Promise<void> {
  await invalidateQueryKeys(qc, [
    'dashboard-summary', 'dashboard-scanned-projects', 'trend-explorer', 'vulnerabilities',
    'dashboard-posture', 'dashboard-trend', 'dashboard-lifetime',
    'dashboard-priority-findings', 'dashboard-operational-runs', 'portfolio-trend', 'vulnerability-age',
    'dashboard-forecast', 'dashboard-exploitation', 'dashboard-remediation', 'dashboard-remediation-stats',
    'dashboard-lifecycle', 'dashboard-vex', 'dashboard-health', 'dashboard-risk-map', 'dashboard-risk-matrix',
    'copilot-briefing',
  ].map(family => [family]));
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
export async function invalidateAnalysisCompletion(
  qc: QueryClient,
  args: { sbomId?: number; runId?: number } = {},
): Promise<void> {
  const keys: Array<readonly unknown[]> = [
    args.runId == null ? ['findings-enriched'] : ['findings-enriched', args.runId],
    args.runId == null ? ['findings'] : ['findings', args.runId],
    args.sbomId == null ? ['vex-investigation-by-triple'] : ['vex-investigation-by-triple', args.sbomId],
  ];
  if (args.runId != null) keys.push(['run', args.runId]);
  if (args.sbomId != null) keys.push(['sbom', args.sbomId], ['sbom-stats', args.sbomId], ['sbom-risk', args.sbomId],
    ['sbom-info', args.sbomId], ['compare', 'sparkline', args.sbomId]);
  await Promise.all([invalidateRunLists(qc), invalidateSbomLists(qc), invalidateProductSurfaces(qc), invalidateQueryKeys(qc, keys)]);
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
 * status is a projection of the effective execution configuration and
 * stored verification metadata.
 */
export function invalidateAiCredentialSurfaces(qc: QueryClient): void {
  qc.invalidateQueries({ queryKey: ['ai', 'effective-config'] });
  qc.invalidateQueries({ queryKey: ['ai', 'credentials'] });
  qc.invalidateQueries({ queryKey: ['ai', 'credential-settings'] });
  qc.invalidateQueries({ queryKey: ['ai-settings'] });
  qc.invalidateQueries({ queryKey: ['ai-usage'] });
  qc.invalidateQueries({ queryKey: ['analysis-config'] });
  qc.invalidateQueries({ queryKey: ['copilot-briefing'] });
  qc.invalidateQueries({ queryKey: ['validation-session'] });
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

/** Enqueue refreshes execution/history; terminal/cancel also refresh partial output and usage. */
export function invalidateAiBatchSurfaces(qc: QueryClient, runId: number, options: { results?: boolean } = {}): Promise<void> {
  const keys: Array<readonly unknown[]> = [['ai-batch-progress', runId], ['ai-batch-list', runId]];
  if (options.results) {
    // Progress contracts contain no finding IDs. The established per-finding
    // factory has no run dimension, so the safe fallback is its family prefix.
    keys.push(['ai-fix-list', runId], ['ai-fix'], ['ai-settings', 'usage'], ['ai-usage'], ['ai-usage-trend'], ['ai-top-cached']);
  }
  return invalidateQueryKeys(qc, keys);
}

/**
 * Secure Component Advisor surfaces. A recommendation create / evaluate /
 * decision changes the open-item badge on every component row and detail,
 * and the work item itself; tenant-scoped keys are invalidated unscoped so a
 * decision taken from any page refreshes every list (see CLAUDE.md).
 */
export function invalidateComponentAdvisorSurfaces(qc: QueryClient, recommendationId?: number): void {
  qc.invalidateQueries({ queryKey: ['component-advisor-summary'] });
  qc.invalidateQueries({ queryKey: ['component-advisor-components'] });
  qc.invalidateQueries({ queryKey: ['component-advisor-component'] });
  qc.invalidateQueries({ queryKey: ['component-advisor-search'] });
  if (recommendationId !== undefined) {
    qc.invalidateQueries({ queryKey: ['component-advisor-recommendation', recommendationId] });
    qc.invalidateQueries({ queryKey: ['component-advisor-candidate-evidence', recommendationId] });
  } else {
    qc.invalidateQueries({ queryKey: ['component-advisor-recommendation'] });
    qc.invalidateQueries({ queryKey: ['component-advisor-candidate-evidence'] });
  }
}

/** Lifecycle affects current metrics across inventory, advisor and reports. */
export async function invalidateSbomLifecycle(qc: QueryClient, sbom: { id: number; projectid: number | null; product_id?: number | null }): Promise<void> {
  await Promise.all([
    invalidateSbomSurfaces(qc, sbom.id), invalidateProjectSurfaces(qc, sbom.projectid),
    invalidateProductSurfaces(qc, sbom.product_id), invalidateRunLists(qc),
    invalidateScheduleLists(qc), invalidateDashboardTiles(qc), invalidateReportTargetChoices(qc),
    invalidateQueryKeys(qc, [['sbom-lifecycle-history', sbom.id], ['compare'],
      ['component-advisor-summary'], ['component-advisor-components']]),
  ]);
}


/** Version designation, upload and analysis completion share posture evidence. */
async function invalidateVersionPosture(qc: QueryClient): Promise<void> {
  await Promise.all([
    invalidateDashboardTiles(qc),
    invalidateQueryKeys(qc, [
      'sbom-posture', 'vex-version-comparison', 'vex-investigations', 'vex-investigation',
      'vex-run-history', 'component-advisor-summary', 'component-advisor-components', 'component-advisor-component',
    ].map(family => [family])),
  ]);
}

/** Readiness uses the active tenant context despite its legacy unscoped key.
 * Platform defaults also affect inherited tenant configurations. */
export function invalidateLifecycleProviderSurfaces(qc: QueryClient, scopeKey: string, options: { readiness?: boolean } = {}): Promise<void> {
  const keys: Array<readonly unknown[]> = [scopeKey === 'platform' ? ['lifecycle-providers'] : ['lifecycle-providers', scopeKey]];
  if (options.readiness !== false) keys.push(['lifecycle-provider-status']);
  return invalidateQueryKeys(qc, keys);
}
/** Catalog edits do not recalculate materialized SBOM evidence. */
export function invalidateLifecycleVendorRecords(qc: QueryClient): Promise<void> {
  return invalidateQueryKeys(qc, [['lifecycle-vendor-records']]);
}

/** Policy identities differ: list/detail tenant is at 1, recommendation at 2,
 * candidate evidence at its final position (with an optional checks segment).
 * Platform defaults may affect every inheriting tenant; tenant overrides cannot.
 */
export function invalidateAdvisorPolicySurfaces(qc: QueryClient, tenantId: number | null): Promise<void> {
  const keys: Array<readonly unknown[]> = [];
  for (const query of qc.getQueryCache().getAll()) {
    const key = query.queryKey;
    if (!String(key[0]).startsWith('component-advisor-')) continue;
    const owner = key[0] === 'component-advisor-recommendation' ? key[2]
      : key[0] === 'component-advisor-candidate-evidence' ? key[key.length - 1] : key[1];
    if (tenantId === null || String(owner) === String(tenantId)) keys.push(key);
  }
  return invalidateQueryKeys(qc, keys);
}

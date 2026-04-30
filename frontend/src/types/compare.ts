/**
 * Compare Runs v2 wire types — mirrors `app/schemas_compare.py`.
 *
 * Three structural simplifications match the backend (ADR-0008 §11):
 *   PB-1  No `risk_score` scalar. `PostureDelta` carries three count-based
 *         deltas anchored to public sources.
 *   PB-2  Both `severity_distribution_a/b` AND per-row `severity_changed`
 *         events ship — different regions of the UI consume each.
 *   PB-3  `kev_added` is intentionally absent from `FindingChangeKind`. KEV
 *         is surfaced as a row badge + filter chip + Region 2 tile.
 */

import type { CveSeverity } from './cve';

// =============================================================================
// Stable error codes — branch on these, not on free-text messages.
// =============================================================================

export const COMPARE_ERR_RUN_NOT_FOUND = 'COMPARE_E001_RUN_NOT_FOUND';
export const COMPARE_ERR_RUN_NOT_READY = 'COMPARE_E002_RUN_NOT_READY';
export const COMPARE_ERR_SAME_RUN = 'COMPARE_E003_SAME_RUN';
export const COMPARE_ERR_PERMISSION_DENIED = 'COMPARE_E004_PERMISSION_DENIED';
export const COMPARE_ERR_BAD_REQUEST = 'COMPARE_E005_BAD_REQUEST';
export const COMPARE_ERR_CACHE_MISS = 'COMPARE_E006_CACHE_MISS';
export const COMPARE_ERR_CACHE_CORRUPT = 'COMPARE_E007_CACHE_CORRUPT';

// =============================================================================
// Enumerations
// =============================================================================

export type FindingChangeKind =
  | 'added'
  | 'resolved'
  | 'severity_changed'
  | 'unchanged';

export type ComponentChangeKind =
  | 'added'
  | 'removed'
  | 'version_bumped'
  | 'license_changed' // stub today — gated by COMPARE_LICENSE_HASH_ENABLED
  | 'hash_changed' // stub today — gated by COMPARE_LICENSE_HASH_ENABLED
  | 'unchanged';

// =============================================================================
// Building blocks
// =============================================================================

export interface RunSummary {
  id: number;
  sbom_id: number | null;
  sbom_name: string | null;
  project_id: number | null;
  project_name: string | null;
  run_status: string;
  completed_on: string | null;
  started_on: string | null;
  total_findings: number;
  total_components: number;
}

export interface RunRelationship {
  same_project: boolean;
  same_sbom: boolean;
  days_between: number | null;
  /** Set when run B is older than run A — likely user picked the wrong order. */
  direction_warning: string | null;
}

export interface FindingDiffRow {
  change_kind: FindingChangeKind;
  vuln_id: string;
  severity_a: CveSeverity | null;
  severity_b: CveSeverity | null;
  /** Current KEV status (NOT at-scan-time). */
  kev_current: boolean;
  /** Current EPSS values (NOT at-scan-time). */
  epss_current: number | null;
  epss_percentile_current: number | null;
  component_name: string;
  component_version_a: string | null;
  component_version_b: string | null;
  component_purl: string | null;
  component_ecosystem: string | null;
  fix_available: boolean;
  attribution: string | null;
}

export interface ComponentDiffRow {
  change_kind: ComponentChangeKind;
  name: string;
  ecosystem: string;
  purl: string | null;
  version_a: string | null;
  version_b: string | null;
  /** Always null today — reserved for future migration. */
  license_a: string | null;
  license_b: string | null;
  hash_a: string | null;
  hash_b: string | null;
  findings_resolved: number;
  findings_added: number;
}

// =============================================================================
// Posture (ADR-0008 §6) — three deltas, no scalar
// =============================================================================

export interface PostureDelta {
  // KEV exposure
  kev_count_a: number;
  kev_count_b: number;
  kev_count_delta: number;

  // Fix-available coverage (percentage in [0, 100])
  fix_available_pct_a: number;
  fix_available_pct_b: number;
  fix_available_pct_delta: number;

  // High+Critical exposure
  high_critical_count_a: number;
  high_critical_count_b: number;
  high_critical_count_delta: number;

  // Distribution bar
  findings_added_count: number;
  findings_resolved_count: number;
  findings_severity_changed_count: number;
  findings_unchanged_count: number;

  // Component composition
  components_added_count: number;
  components_removed_count: number;
  components_version_bumped_count: number;
  components_unchanged_count: number;

  // Severity composition (Tab 3 side-by-side bar)
  severity_distribution_a: Record<string, number>;
  severity_distribution_b: Record<string, number>;

  // Top contributors (Tab 3) — ordinal rank, NOT a weighted score
  top_resolutions: FindingDiffRow[];
  top_regressions: FindingDiffRow[];
}

// =============================================================================
// Top-level result
// =============================================================================

export interface CompareResult {
  cache_key: string;
  run_a: RunSummary;
  run_b: RunSummary;
  relationship: RunRelationship;
  posture: PostureDelta;
  findings: FindingDiffRow[];
  components: ComponentDiffRow[];
  computed_at: string;
  schema_version: number;
}

export interface CompareRequest {
  run_a_id: number;
  run_b_id: number;
}

export type CompareExportFormat = 'markdown' | 'csv' | 'json';

// =============================================================================
// URL state — mirrors ADR-0008 §8
// =============================================================================

export type CompareTab = 'findings' | 'components' | 'delta';

export interface CompareUrlState {
  runA: number | null;
  runB: number | null;
  tab: CompareTab;
  /** Multi-select on FindingChangeKind (excludes "unchanged" by default). */
  changeKinds: Set<FindingChangeKind>;
  severities: Set<string>;
  kevOnly: boolean;
  fixAvailable: boolean;
  showUnchanged: boolean;
  q: string;
}

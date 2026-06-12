export interface Project {
  id: number;
  project_name: string;
  project_details: string | null;
  project_status: number;   // 1 = Active, 0 = Inactive
  created_by: string | null;
  created_on: string | null;
  modified_by: string | null;
  modified_on: string | null;
  sbom_count?: number;
}

export type SbomValidationStatus = 'validated' | 'failed' | 'quarantined' | 'pending';
export type ValidationRepairStatus = 'failed' | 'edited' | 'passed' | 'security_blocked' | 'imported';

export interface SBOMSource {
  id: number;
  sbom_name: string;
  sbom_type: number | null;       // FK integer to SBOMType
  sbom_version: string | null;
  parent_id?: number | null;
  change_summary?: string | null;
  completeness_score?: number | null;
  completeness_report?: Record<string, unknown> | null;
  projectid: number | null;
  project_id?: number | null;
  project_name?: string | null;
  component_count?: number;
  created_by: string | null;
  created_on: string | null;
  modified_by: string | null;
  modified_on: string | null;
  productver: string | null;
  sbom_data?: string | null;
  // 8-stage validation outcome — populated by POST /api/sboms.
  status?: SbomValidationStatus;
  failed_stage?: string | null;
  validation_errors?: ValidationErrorEntry[] | null;
  error_count?: number;
  warning_count?: number;
  validated_at?: string | null;
  // Client-side only — not from API. Set during optimistic updates.
  // ADR-0001: OK / FINDINGS are the canonical names. PASS / FAIL accepted as
  // legacy aliases during the deprecation window.
  _analysisStatus?:
    | 'ANALYSING'
    | 'OK'
    | 'FINDINGS'
    | 'PARTIAL'
    | 'ERROR'
    | 'NOT_ANALYSED'
    | 'PASS' // legacy alias for OK
    | 'FAIL'; // legacy alias for FINDINGS
  _findingsCount?: number;
}

export interface ValidationErrorEntry {
  code: string;
  severity: 'error' | 'warning' | 'info';
  stage: string;
  stage_number?: number;
  path?: string | null;
  json_pointer?: string | null;
  xpath?: string | null;
  line?: number | null;
  column?: number | null;
  message: string;
  remediation?: string | null;
  spec_reference: string | null;
  can_ai_fix?: boolean;
}

export interface ValidationReport {
  sbom_id: number;
  filename: string;
  status: SbomValidationStatus;
  failed_stage: string | null;
  error_count: number;
  warning_count: number;
  info_count: number;
  entries: ValidationErrorEntry[];
  validated_at: string | null;
  spec_detected: string | null;
  spec_version_detected: string | null;
  severity_summary: Record<string, number>;
  stage_summary: Record<string, number>;
  truncated: boolean;
}

/** Body of a 4xx response from POST /api/sboms when validation fails. */
export interface SbomValidationFailureDetail {
  code: 'sbom_validation_failed';
  status?: 'validation_failed' | SbomValidationStatus;
  message: string;
  sbom_id: number | null;
  session_id?: string | null;
  can_edit?: boolean;
  can_ai_fix?: boolean;
  reason?: string | null;
  failed_stage: string | null;
  error_count: number;
  warning_count: number;
  entries: ValidationErrorEntry[];
  truncated: boolean;
  error_report?: ValidationRepairReport;
}

export interface ValidationRepairReport {
  entries: ValidationErrorEntry[];
  truncated: boolean;
  failed_stage: string | null;
  error_count: number;
  warning_count: number;
  info_count: number;
  http_status?: number;
  status: 'failed' | 'passed';
}

export interface ValidationRepairSession {
  id: string;
  project_id: number | null;
  user_id: string | null;
  original_filename: string | null;
  sbom_name: string | null;
  sbom_type: number | null;
  detected_format: string | null;
  detected_version: string | null;
  current_content: string;
  validation_status: ValidationRepairStatus;
  latest_error_report: ValidationRepairReport;
  can_edit: boolean;
  can_ai_fix: boolean;
  security_blocked_reason: string | null;
  created_at: string;
  updated_at: string;
  expires_at: string;
  imported_sbom_id: number | null;
}

export interface ValidationRepairPatch {
  target: string;
  operation: 'add' | 'replace' | 'remove';
  before?: unknown;
  after?: unknown;
  reason: string;
  validation_error_codes: string[];
}

export interface AiRepairSuggestion {
  summary: string;
  risk: 'low' | 'medium' | 'high';
  patches: ValidationRepairPatch[];
  requires_user_review: boolean;
}

export interface ValidationRepairEvent {
  id: number;
  session_id: string;
  event_type: 'created' | 'manual_edit' | 'ai_suggestion_generated' | 'patch_applied' | 'validation_run' | 'imported' | string;
  actor_user_id: string | null;
  timestamp: string;
  summary: string | null;
  before_hash: string | null;
  after_hash: string | null;
  metadata: Record<string, unknown>;
}

export type ValidationSession = ValidationRepairSession;
export type ValidationSessionEvent = ValidationRepairEvent;
export type ValidationErrorReport = ValidationRepairReport;
export type AiPatch = ValidationRepairPatch;
export type AiFixSuggestion = AiRepairSuggestion;

export interface AiFixSuggestionRequest {
  user_instruction?: string | null;
}

export interface ApplyPatchRequest {
  patches: AiPatch[];
}

export type ApplyPatchResponse = ValidationSession;
export type ValidationSessionImportResponse = SBOMSource;

export interface SBOMComponent {
  id: number;
  sbom_id: number;
  bom_ref?: string | null;
  name: string;
  version: string | null;
  cpe: string | null;
  purl: string | null;
  component_type: string | null;
  component_group?: string | null;
  supplier?: string | null;
  scope: string | null;
  ecosystem?: string | null;
  license?: string | null;
  hashes?: string | null;
  lifecycle_status?: string | null;
  eos_date?: string | null;
  eol_date?: string | null;
  eof_date?: string | null;
  is_deprecated?: boolean | null;
  deprecated?: boolean | null;
  unsupported?: boolean | null;
  maintenance_status?: string | null;
  latest_version?: string | null;
  latest_supported_version?: string | null;
  recommended_version?: string | null;
  lifecycle_recommendation?: string | null;
  lifecycle_source?: string | null;
  lifecycle_source_url?: string | null;
  lifecycle_confidence?: string | null;
  lifecycle_checked_at?: string | null;
  lifecycle_evidence_json?: Record<string, unknown> | null;
  lifecycle_is_stale?: boolean | null;
  lifecycle_manual_override?: boolean | null;
  normalized_component_key?: string | null;
  is_duplicate?: boolean | null;
  duplicate_of_component_id?: number | null;
  created_on: string | null;
}

export type LifecycleStatus =
  | 'Supported'
  | 'EOL'
  | 'EOS'
  | 'EOF'
  | 'Deprecated'
  | 'Unsupported'
  | 'EOL Soon'
  | 'Unknown';

export interface LifecycleSummaryComponent {
  id: number;
  name: string;
  version: string | null;
  ecosystem?: string | null;
  lifecycle_status: LifecycleStatus | string;
  eos_date?: string | null;
  eol_date?: string | null;
  eof_date?: string | null;
  source_name?: string | null;
  source_url?: string | null;
  confidence?: string | null;
  latest_version?: string | null;
  recommended_version?: string | null;
  recommendation?: string | null;
  is_stale?: boolean;
  manual_override?: boolean;
}

export interface DashboardLifecycle {
  total_components: number;
  supported_count: number;
  eol_count: number;
  eos_count: number;
  eof_count: number;
  deprecated_count: number;
  unsupported_count: number;
  unknown_count: number;
  eol_soon_count: number;
  stale_lifecycle_count: number;
  stale_count?: number;
  top_risky_components: LifecycleSummaryComponent[];
  recommended_upgrades: LifecycleSummaryComponent[];
  eol_components: number;
  eos_upcoming: number;
  unsupported: number;
}

export interface LifecycleReport {
  sbom_id: number;
  sbom_name: string;
  generated_at: string;
  summary: DashboardLifecycle;
  components: LifecycleSummaryComponent[];
}

export interface LifecycleOverridePayload {
  lifecycle_status: LifecycleStatus | string;
  eos_date?: string | null;
  eol_date?: string | null;
  eof_date?: string | null;
  deprecated?: boolean | null;
  is_deprecated?: boolean | null;
  unsupported?: boolean | null;
  maintenance_status?: string | null;
  latest_version?: string | null;
  latest_supported_version?: string | null;
  recommended_version?: string | null;
  recommendation?: string | null;
  evidence_url?: string | null;
  reason?: string | null;
  updated_by?: string | null;
}

export type RemediationStatus = 'Open' | 'In Progress' | 'Fixed' | 'Accepted Risk' | 'Closed';

export interface VulnerabilityRemediation {
  id: number;
  project_id: number;
  vuln_id: string;
  component_name: string | null;
  component_version: string | null;
  fixed_version: string | null;
  status: RemediationStatus | string;
  owner: string | null;
  due_date: string | null;
  resolution_date: string | null;
  fix_notes: string | null;
  created_on: string | null;
  updated_on: string | null;
}

export interface AnalysisRun {
  id: number;
  sbom_id: number | null;
  sbom_name?: string | null;
  project_id: number | null;
  // ADR-0001: OK / FINDINGS are canonical. PASS / FAIL accepted as legacy
  // aliases during the deprecation window — see docs/terminology.md.
  run_status:
    | 'OK'
    | 'FINDINGS'
    | 'PARTIAL'
    | 'ERROR'
    | 'RUNNING'
    | 'PENDING'
    | 'NO_DATA'
    | 'PASS' // legacy alias for OK
    | 'FAIL'; // legacy alias for FINDINGS
  source: string | null;
  total_components: number | null;
  components_with_cpe: number | null;
  total_findings: number | null;
  critical_count: number | null;
  high_count: number | null;
  medium_count: number | null;
  low_count: number | null;
  unknown_count: number | null;
  query_error_count: number | null;
  duration_ms: number | null;       // milliseconds (backend field name)
  started_on: string | null;
  completed_on: string | null;
  error_message: string | null;
}

/**
 * NVD version-range match verdict (roadmap #1). Populated when the
 * backend flag NVD_VERSION_RANGE_FILTER_ENABLED is on; null on every
 * pre-filter row and every row produced by a flag-off scan. Only the
 * five values that survive the filter's drop step ever reach the UI —
 * `out_of_range` / `exact_version_mismatch` drop the finding entirely.
 *
 * Closed literal after PR-C resolved the audit's column-name collision:
 * roadmap #6's source-attribution values landed on the separate
 * ``match_strategy`` column, not here. PR-E tightens the type
 * accordingly — adding a sixth UI-visible reason now requires a
 * deliberate type edit, which the filter UI and the badge mapping
 * (see Badge.tsx::MATCH_REASON_DETAIL) need to follow.
 */
export type MatchReason =
  | 'matched'
  | 'version_unparseable'
  | 'and_node_ambiguous'
  | 'ecosystem_unsupported'
  | 'no_configurations';

/**
 * Search strategy that produced a finding (roadmap #6). Five spec
 * values; ``cpe_name`` / ``purl_direct`` / ``ghsa_alias`` are the only
 * three reachable from a live emit path today, but the type carries
 * all five so re-enabling the keyword/virtualMatch paths needs no
 * type churn. The strategy filter in FindingFilterPanel renders only
 * values actually present in the loaded findings (see PR-E note).
 */
export type MatchStrategy =
  | 'cpe_name'
  | 'virtual_match_string'
  | 'keyword_search'
  | 'purl_direct'
  | 'ghsa_alias';

export interface AnalysisFinding {
  id: number;
  analysis_run_id: number;          // backend field name
  component_id?: number | null;
  vuln_id: string | null;
  source: string | null;            // e.g. "NVD", "OSV", "NVD,OSV"
  title: string | null;
  description: string | null;
  severity: 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW' | 'UNKNOWN' | null;
  score: number | null;             // backend field name (not cvss_score)
  vector: string | null;
  cpe: string | null;
  component_name: string | null;
  component_version: string | null;
  published_on: string | null;
  reference_url: string | null;
  aliases: string | null;           // JSON string e.g. '["CVE-2022-31090"]'
  attack_vector: string | null;     // e.g. "NETWORK", "LOCAL"
  fixed_versions: string | null;    // JSON string e.g. '["1.2.3"]'
  cwe?: string | null;              // comma-separated, e.g. "CWE-79,CWE-89"
  cvss_version?: string | null;     // e.g. "3.1", "4.0"
  /** Roadmap #1 — see MatchReason. Optional; null on pre-filter rows. */
  match_reason?: MatchReason | null;
  /** Roadmap #1 — human-readable affected range, e.g. ">= 2.0.0, < 2.17.0". */
  matched_range?: string | null;
  /** Roadmap #6 — which search strategy produced this finding. */
  match_strategy?: MatchStrategy | null;
  /** Roadmap #3 — token-overlap confidence post strategy-floor, [0.0, 1.0]. */
  match_confidence?: number | null;
  /** Lifecycle-management remediation record, when one has been saved. */
  remediation?: VulnerabilityRemediation | null;
}

/**
 * Findings enriched with per-CVE KEV, EPSS, and composite risk score.
 * Returned by GET /api/runs/{id}/findings-enriched.
 */
export interface EnrichedFinding extends AnalysisFinding {
  in_kev: boolean;
  /** EPSS probability of exploitation (0..1). 0 = not in EPSS catalog. */
  epss: number;
  /** Percentile rank within EPSS catalog (0..1), null when uncached. */
  epss_percentile: number | null;
  /** Composite finding score: cvss * (1 + 5*epss) * (kev ? 2 : 1). 0..120. */
  risk_score: number;
  /** All CVE aliases discovered on the finding (vuln_id + parsed aliases). */
  cve_aliases: string[];
}

export interface DashboardStats {
  // ADR-0001 / docs/terminology.md — canonical fields:
  total_active_projects: number;
  total_sboms: number;
  /** Distinct CVE-equivalent identifiers in scope (latest successful run per SBOM). */
  total_distinct_vulnerabilities: number;
  /** Finding rows in scope (one CVE × N components × latest run = N findings). */
  total_findings: number;
  // Legacy aliases (one-release deprecation window). Older bundles keyed off
  // these names. Kept so optional chaining at the call-site keeps working.
  total_projects?: number;
  total_vulnerabilities?: number;
}

export interface HealthResponse {
  status: string;
  nvd_mirror?: {
    available?: boolean;
    enabled?: boolean;
    last_success_at?: string | null;
    watermark?: string | null;
    stale?: boolean;
    error?: string;
  };
}

/**
 * Six possible posture framings, computed server-side and returned on
 * `/dashboard/posture`. The frontend never derives this — it just renders
 * the matching copy from `headlineCopy.ts`. See `docs/dashboard-redesign.md` §2.
 */
export type HeadlineState =
  | 'no_data'
  | 'clean'
  | 'kev_present'
  | 'criticals_no_kev'
  | 'high_only'
  | 'low_volume';

/** Adaptive primary CTA — server-decided from the same payload. */
export type PrimaryAction =
  | 'upload'
  | 'review_kev'
  | 'review_critical'
  | 'view_top_sboms';

/**
 * Time-windowed delta with explicit first-period signaling.
 *
 * `is_first_period === true` means there is no prior comparison window
 * — the FE must render "first scan this week" copy instead of `+N / −0`.
 * See `docs/dashboard-metrics-spec.md` §3.7.
 */
export interface NetChange {
  added: number;
  resolved: number;
  is_first_period: boolean;
  window_days: number;
}

export interface DashboardPosture {
  severity: SeverityData;
  /**
   * Finding-rows in scope that are KEV-listed (matches the run-detail badge
   * "{N} KEV"). Membership = `vuln_id ∪ aliases ∩ kev_entry`. Same predicate
   * the run-detail page uses; spec §3.3 invariant I3 locks them equal.
   */
  kev_count: number;
  /** Distinct vulns in scope with a non-empty fixed_versions array. */
  fix_available_count: number;
  /** ISO timestamp of the most recent successful run, or null if none. */
  last_successful_run_at: string | null;
  total_sboms: number;
  total_active_projects: number;

  // Counter tiles (manager dashboard): "SBOMs Analysed" = distinct SBOMs with
  // a completed run; "Applications Scanned" = distinct projects with one.
  total_sboms_analysed?: number;
  total_applications_scanned?: number;

  // v2 additions — see `docs/dashboard-redesign.md` §9.3.
  total_findings?: number;
  distinct_vulnerabilities?: number;

  // Phase-2 exploitability/quality aggregates (dashboard redesign). OPTIONAL
  // and absent from the posture endpoint today — the FE feature-detects them:
  // the "likely-exploited" tile and "needs-review" chip render only when the
  // field is present, so they light up automatically when the backend
  // aggregates land (no flag, no fake data). See the redesign plan.
  /** Findings in scope whose CVE sits at/above the high-EPSS percentile
   *  ({@link HIGH_EPSS_PERCENTILE}) — "likely to be exploited". */
  high_epss_count?: number;
  /** Findings in scope that are low-confidence / not-verified matches and
   *  warrant manual review before action. */
  needs_review_count?: number;
  /** Canonical 7-day delta envelope; carries `is_first_period`. */
  net_7day?: NetChange;
  /** @deprecated use `net_7day.added` — kept for one-release back-compat. */
  net_7day_added?: number;
  /** @deprecated use `net_7day.resolved` — kept for one-release back-compat. */
  net_7day_resolved?: number;
  headline_state?: HeadlineState;
  primary_action?: PrimaryAction;
  schema_version?: number;
}

/**
 * Cumulative "Your Analyzer, So Far" panel. Numbers only go up — by design.
 * No deltas, no comparisons. See `docs/dashboard-redesign.md` §6.
 */
export interface LifetimeMetrics {
  sboms_scanned_total: number;
  projects_total: number;
  /** Every run, all statuses (incl. ERROR/RUNNING/PENDING). Spec §3.6. */
  runs_executed_total: number;
  /** Successful-only run count. Optional during back-compat window. */
  runs_completed_total?: number;
  /**
   * Distinct calendar dates with ≥1 successful run. Drives the trend chart's
   * empty-state condition — `< 7` → show empty. Spec §3.6.
   */
  runs_distinct_dates?: number;
  runs_executed_this_week: number;
  /** Distinct (vuln_id, component_name, component_version) tuples ever surfaced. */
  findings_surfaced_total: number;
  /** Findings present in run N but absent from run N+1, summed across pairs. */
  findings_resolved_total: number;
  /** ISO 8601 timestamp string. `null` until the first successful run. */
  first_run_at: string | null;
  /** Days since the first successful run; 0 when none. */
  days_monitoring: number;
  schema_version?: number;
}

export interface RecentSbom {
  id: number;
  sbom_name: string;
  created_on: string;
}

export interface ActivityData {
  active_30d: number;
  stale: number;
}

export interface SeverityData {
  critical: number;
  high: number;
  medium: number;
  low: number;
  unknown: number;
}

export interface SBOMType {
  id: number;
  typename: string;
}

export interface ApiError {
  detail: string;
}

export interface CreateProjectPayload {
  project_name: string;
  project_details?: string;
  project_status: number;   // 1 = Active, 0 = Inactive
  created_by?: string;
}

export interface UpdateProjectPayload {
  project_name?: string;
  project_details?: string;
  project_status?: number;
  modified_by?: string;
}

export interface CreateSBOMPayload {
  sbom_name: string;
  sbom_data: string;
  sbom_type?: number;       // integer FK to SBOMType
  projectid?: number;
  project_id?: number;
  sbom_version?: string;
  created_by?: string;
  productver?: string;
}

export interface UploadSBOMAcceptedResponse {
  sbom_id: number;
  sbom_name: string;
  project_id: number | null;
  project_name?: string | null;
  spec: string;
  spec_version: string;
  components: number;
  warnings: ValidationErrorEntry[];
  info: ValidationErrorEntry[];
}

export interface UpdateSBOMPayload {
  sbom_name?: string;
  sbom_version?: string;
  productver?: string;
  sbom_type?: number;
  modified_by?: string;
}

export interface AnalyzeSBOMPayload {
  sbom_id: number;
  sbom_name: string;
  nvd_api_key?: string;
  github_token?: string;
  vulndb_api_key?: string;
  osv_hydrate?: boolean;
}

export interface PDFReportPayload {
  runId: number;
  title?: string;
  filename?: string;
}

export interface SBOMInfo {
  sbom_id: number;
  format: string;
  spec_version: string | null;
  component_count: number;
  ecosystems: string[];
  has_purls: boolean;
  has_cpes: boolean;
  components_preview: string[];
}

export interface RiskComponent {
  name: string;
  version: string;
  critical: number;
  high: number;
  medium: number;
  low: number;
  // v2 scorer additions — present from /risk-summary v2 onward
  kev_count?: number;
  worst_finding_score?: number;
  component_score: number;
  highest_severity: 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW' | 'UNKNOWN';
}

export interface RiskWorstFinding {
  vuln_id: string | null;
  severity: 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW' | 'UNKNOWN';
  cvss: number;
  epss: number;
  in_kev: boolean;
  score: number;
  component_name: string;
  component_version: string;
}

export interface RiskMethodology {
  version: string;
  name: string;
  formula: string;
  aggregation: string;
  bands: Record<string, string>;
  sources: Record<string, string>;
}

export interface SBOMRiskSummary {
  sbom_id: number;
  run_id?: number;
  total_risk_score: number;
  risk_band: 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW';
  components: RiskComponent[];
  // v2 scorer additions
  worst_finding?: RiskWorstFinding | null;
  kev_count?: number;
  epss_avg?: number;
  methodology?: RiskMethodology;
}

export interface DashboardTrendPoint {
  date: string;
  critical: number;
  high: number;
  medium: number;
  low: number;
  /** v2 — first-class bucket. v1 silently dropped these. */
  unknown?: number;
  /** v2 — convenience aggregate; same as sum of severities. */
  total?: number;
  /** Manager trend overlays — present when the trend is requested with a
   *  granularity. Distinct active findings with a fix; findings resolved in
   *  the period. 0/absent on the legacy daily path. */
  fix_available?: number;
  resolved?: number;
}

export type TrendGranularity = 'day' | 'week' | 'month' | 'year';

export interface VulnerabilityAgeBuckets {
  le_30d: number;
  d31_90: number;
  d91_365: number;
  gt_365: number;
  unknown: number;
}

export type AgePeriod = 'all' | 'day' | 'week' | 'month' | 'year' | 'custom';

export interface VulnerabilityAgeResponse {
  buckets: VulnerabilityAgeBuckets;
  total: number;
  period: AgePeriod;
  date_from: string | null;
  date_to: string | null;
  schema_version?: number;
}

export type TrendAnnotationKind =
  | 'sbom_uploaded'
  | 'remediation'
  | 'kev_first_seen';

export interface TrendAnnotation {
  date: string;
  kind: TrendAnnotationKind;
  label: string;
  /** Number of underlying events; lets the chart stack same-day markers. */
  count?: number;
}

export interface DashboardTrend {
  days: number;
  /**
   * v1 alias — same shape as `points`. Kept for one release so the legacy
   * hero sparkline keeps working until the v1 dashboard is retired.
   */
  series: DashboardTrendPoint[];
  /** v2 canonical points array. */
  points?: DashboardTrendPoint[];
  /** v2 — event markers (uploads, remediations) overlaid on the chart. */
  annotations?: TrendAnnotation[];
  /** v2 — 30-day average of `point.total`, for the dashed reference line. */
  avg_total?: number;
  /** v2 — earliest successful run date; lets the UI pick the empty state. */
  earliest_run_date?: string | null;
  /**
   * Canonical run count — drives the empty-state copy ("{N} runs so far").
   * Replaces the FE-side `populatedDays` heuristic that mis-counted runs as
   * days when multiple runs happened on the same calendar date (Bug 2).
   */
  runs_total?: number;
  /**
   * Canonical distinct-dates-with-data count — drives the empty-state
   * condition (`< 7` → show empty). Bug 6 lock.
   */
  runs_distinct_dates?: number;
  /** Period bucketing of `points`: null on the legacy daily path, else
   *  day/week/month/year (manager trend). */
  granularity?: TrendGranularity | null;
  schema_version?: number;
}

export interface CompareRunsResult {
  run_a: { id: number; sbom_name: string | null; completed_on: string | null };
  run_b: { id: number; sbom_name: string | null; completed_on: string | null };
  new_findings: string[];
  resolved_findings: string[];
  common_findings: string[];
  severity_delta: { critical: number; high: number; medium: number; low: number };
}

// ─── Periodic analysis schedules ─────────────────────────────────────────────
export type ScheduleCadence =
  | 'DAILY'
  | 'WEEKLY'
  | 'BIWEEKLY'
  | 'MONTHLY'
  | 'QUARTERLY'
  | 'CUSTOM';

export type ScheduleScope = 'PROJECT' | 'SBOM';

export interface AnalysisSchedule {
  id: number;
  scope: ScheduleScope;
  project_id: number | null;
  sbom_id: number | null;
  cadence: ScheduleCadence;
  cron_expression: string | null;
  day_of_week: number | null;   // 0=Mon..6=Sun
  day_of_month: number | null;  // 1..28
  hour_utc: number;             // 0..23
  timezone: string;             // IANA, display only
  enabled: boolean;
  next_run_at: string | null;
  last_run_at: string | null;
  last_run_status: string | null;
  last_run_id: number | null;
  consecutive_failures: number;
  min_gap_minutes: number;
  created_on: string | null;
  created_by: string | null;
  modified_on: string | null;
  modified_by: string | null;
}

export interface SbomScheduleResolved {
  inherited: boolean;
  schedule: AnalysisSchedule | null;
}

export interface ScheduleUpsertPayload {
  cadence: ScheduleCadence;
  cron_expression?: string | null;
  day_of_week?: number | null;
  day_of_month?: number | null;
  hour_utc?: number;
  timezone?: string;
  enabled?: boolean;
  min_gap_minutes?: number;
  modified_by?: string;
}

export interface ConsolidatedAnalysisResult {
  runId: number;
  sbom_id?: number;
  sbom_name?: string;
  total_components?: number;
  components_with_cpe?: number;
  total_findings?: number;
  critical_count?: number;
  high_count?: number;
  medium_count?: number;
  low_count?: number;
  unknown_count?: number;
  status?: string;
  duration_ms?: number;
  [key: string]: unknown;
}

export type {
  CveSeverity,
  CveSourceName,
  CveReferenceType,
  CveResultStatus,
  CveUnrecognizedIdEnvelope,
  CveFixVersion,
  CveReference,
  CveExploitation,
  CveDetail,
  CveScanContext,
  CveCurrentVersionStatus,
  CveDetailWithContext,
} from './cve';

export type {
  FindingsForecast,
  ForecastHistoryPoint,
  ForecastProjectionPoint,
  VelocityAnomaly,
  ExploitationOutlook,
  ExploitationDriver,
  RemediationSummary,
  SlaOffender,
  SlaSeverity,
  RiskMapResponse,
  RiskMapItem,
  RiskMatrixResponse,
  RiskMatrixPoint,
  CopilotBriefing,
  CopilotAnswer,
} from './dashboardAdvanced';

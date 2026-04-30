export interface Project {
  id: number;
  project_name: string;
  project_details: string | null;
  project_status: number;   // 1 = Active, 0 = Inactive
  created_by: string | null;
  created_on: string | null;
  modified_by: string | null;
  modified_on: string | null;
}

export interface SBOMSource {
  id: number;
  sbom_name: string;
  sbom_type: number | null;       // FK integer to SBOMType
  sbom_version: string | null;
  projectid: number | null;
  project_name?: string | null;
  created_by: string | null;
  created_on: string | null;
  modified_by: string | null;
  modified_on: string | null;
  productver: string | null;
  sbom_data?: string | null;
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

export interface SBOMComponent {
  id: number;
  sbom_id: number;
  name: string;
  version: string | null;
  cpe: string | null;
  purl: string | null;
  component_type: string | null;
  scope: string | null;
  created_on: string | null;
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

export interface DashboardPosture {
  severity: SeverityData;
  /** Distinct vulns in scope that appear in the CISA KEV catalog. */
  kev_count: number;
  /** Distinct vulns in scope with a non-empty fixed_versions array. */
  fix_available_count: number;
  /** ISO timestamp of the most recent successful run, or null if none. */
  last_successful_run_at: string | null;
  total_sboms: number;
  total_active_projects: number;
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
  sbom_version?: string;
  created_by?: string;
  productver?: string;
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
}

export interface DashboardTrend {
  days: number;
  series: DashboardTrendPoint[];
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

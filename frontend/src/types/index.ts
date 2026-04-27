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
  _analysisStatus?: 'ANALYSING' | 'PASS' | 'FAIL' | 'PARTIAL' | 'ERROR' | 'NOT_ANALYSED';
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
  run_status: 'PASS' | 'FAIL' | 'PARTIAL' | 'ERROR' | 'RUNNING' | 'PENDING' | 'NO_DATA';
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
}

export interface DashboardStats {
  total_projects: number;
  total_sboms: number;
  total_vulnerabilities: number;
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
  component_score: number;
  highest_severity: 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW' | 'UNKNOWN';
}

export interface SBOMRiskSummary {
  sbom_id: number;
  total_risk_score: number;
  risk_band: 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW';
  components: RiskComponent[];
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

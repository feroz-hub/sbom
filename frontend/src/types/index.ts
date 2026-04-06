export interface Project {
  id: number;
  project_name: string;
  project_details: string | null;
  project_status: 'Active' | 'Inactive';
  created_by: string | null;
  created_on: string;
  updated_on: string | null;
}

export interface SBOMSource {
  id: number;
  sbom_name: string;
  sbom_type: string | null;
  sbom_version: string | null;
  projectid: number | null;
  project_name?: string | null;
  created_by: string | null;
  created_on: string;
  updated_on: string | null;
  productver: string | null;
  sbom_data?: string | null;
}

export interface SBOMComponent {
  id: number;
  sbom_id: number;
  name: string;
  version: string | null;
  cpe: string | null;
  purl: string | null;
  component_type: string | null;
  created_on: string;
}

export interface AnalysisRun {
  id: number;
  sbom_id: number | null;
  sbom_name?: string | null;
  project_id: number | null;
  run_status: 'PASS' | 'FAIL' | 'PARTIAL' | 'ERROR' | 'RUNNING' | 'PENDING';
  source: string | null;
  total_components: number | null;
  total_findings: number | null;
  critical_count: number | null;
  high_count: number | null;
  medium_count: number | null;
  low_count: number | null;
  unknown_count: number | null;
  started_on: string | null;
  completed_on: string | null;
  duration_seconds: number | null;
  error_message: string | null;
}

export interface AnalysisFinding {
  id: number;
  run_id: number;
  vuln_id: string | null;
  severity: 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW' | 'UNKNOWN';
  cvss_score: number | null;
  component_name: string | null;
  component_version: string | null;
  description: string | null;
  published_on: string | null;
  reference_url: string | null;
  fixed_version: string | null;
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

export interface PaginatedResponse<T> {
  items: T[];
  total: number;
  page: number;
  page_size: number;
}

export interface ApiError {
  detail: string;
}

export interface CreateProjectPayload {
  project_name: string;
  project_details?: string;
  project_status: 'Active' | 'Inactive';
  created_by?: string;
}

export interface UpdateProjectPayload {
  project_name?: string;
  project_details?: string;
  project_status?: 'Active' | 'Inactive';
}

export interface CreateSBOMPayload {
  sbom_name: string;
  sbom_data: string;
  sbom_type?: string;
  projectid?: number;
  sbom_version?: string;
  created_by?: string;
  productver?: string;
}

export interface AnalyzeSBOMPayload {
  sbom_id: number;
  sbom_name: string;
  nvd_api_key?: string;
  github_token?: string;
  osv_hydrate?: boolean;
}

export interface PDFReportPayload {
  runId: number;
  title?: string;
  filename?: string;
}

export type ReportScope = 'TENANT' | 'PROJECT' | 'PRODUCT' | 'SBOM';
export interface ReportPreferences {
  scope: ReportScope;
  project_id: number | null;
  product_id: number | null;
  sbom_id: number | null;
  cadence: 'ON_EVERY_RUN' | 'DAILY' | 'WEEKLY' | 'MONTHLY';
  parts: Array<'A' | 'B' | 'C' | 'D'>;
  formats: Array<'PDF' | 'XLSX'>;
  severity_floor: 'ALL' | 'LOW' | 'MEDIUM' | 'HIGH' | 'CRITICAL';
  baseline_mode: 'FIRST_RUN_OF_SBOM' | 'FIRST_RUN_OF_LINEAGE_ROOT';
  cross_version_target: 'PARENT' | 'ROOT';
  timezone: string;
  suppress_when_unchanged: boolean;
  enabled: boolean;
}
export interface ReportSubscription extends ReportPreferences {
  id: number; tenant_id: number; iam_user_id: number;
  created_on: string; modified_on: string | null; last_delivered_at: string | null;
}
export interface ReportDelivery {
  id: number; subscription_id: number; cycle_start: string; cycle_end: string;
  status: 'PENDING' | 'SENT' | 'FAILED' | 'SKIPPED' | 'SUPPRESSED';
  error_code: string | null; attempt_count: number; sbom_count: number; run_count: number;
  sent_at: string | null; created_on: string;
  artifacts: Array<{ id: number; filename: string; kind: string; size_bytes: number; expires_at: string }>;
}
export interface ReportConfig {
  enabled: boolean; delivery_enabled: boolean; diagnostics: string[]; max_sboms: number;
  retention_days: number; is_tenant_admin: boolean; tenant_scope_allowed: boolean;
  recipient_email: string | null; tenant_id: number;
}
export interface ReportPreview {
  subject: string; text_body: string; html_body: string;
  report: { summary: Record<string, unknown>; sboms: Array<{ id: number; name: string; A: { run_status: string } }> };
}

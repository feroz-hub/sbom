export interface RepairCapabilities {
  can_repair: boolean;
  can_approve: boolean;
  can_reject: boolean;
  can_download: boolean;
}
export interface DeterministicRepairChange {
  repair_id: string;
  error_code: string;
  path: string;
  old_value: unknown;
  new_value: unknown;
  operation: string;
  rule_name: string;
  reason: string;
  confidence: number;
  method: 'DETERMINISTIC';
}
export interface RepairAnalysis {
  enabled: boolean;
  source_sha256?: string;
  validation_status: 'FAILED' | 'PASSED';
  total_errors: number;
  auto_fixable: number;
  suggested: number;
  manual_only: number;
  truncated: boolean;
  repair_supported?: boolean;
  manual_review_reason?: string | null;
  capabilities: RepairCapabilities;
  issues: { code: string; path: string; message: string; classification: 'AUTO_FIX' | 'SUGGEST_FIX' | 'MANUAL_ONLY' }[];
}
export interface DeterministicRepairJob {
  repair_job_id: string;
  status: string;
  candidate_sha256: string;
  source_sha256?: string;
  limit_reached?: boolean;
  manual_review_reason?: string | null;
  analysis?: Omit<RepairAnalysis, 'enabled' | 'capabilities'>;
  source_project_id?: number | null;
  source_product_id?: number | null;
  manual_errors?: number;
  suggested_repairs?: number;
  approval_status: 'PENDING' | 'APPROVED' | 'REJECTED';
  errors_before: number;
  errors_after: number;
  repairs_applied: number;
  validation_status: 'FAILED' | 'PASSED';
  changes: DeterministicRepairChange[];
  imported_sbom_id: number | null;
  capabilities: RepairCapabilities;
}

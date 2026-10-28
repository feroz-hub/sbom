export interface QualityFinding {
  code: string; dimension: string; severity: 'BLOCKING' | 'MAJOR' | 'MINOR' | 'INFORMATIONAL';
  path: string | null; message: string; remediation: string | null; repairable: boolean;
  repairability_assessed: boolean; repair_classification: string; quality_impact: number;
}
export interface QualityDimension {
  code: string; name: string; score: number; weight: number; finding_count: number;
  metrics: Record<string, number | boolean>;
}
export interface QualityAssessment {
  overall_score: number; grade: string; dimensions: QualityDimension[]; findings: QualityFinding[];
  calculated_at: string; engine_version: string; artifact_hash: string; configuration_hash: string; configuration?: Record<string, unknown>;
  format?: 'CYCLONEDX_JSON' | 'SPDX_JSON';
  spec_version: string | null; validation_status: string; validation_report_truncated?: boolean; supported: boolean; reason: string | null;
  findings_truncated: boolean;
}
export interface QualityComparison {
  before: QualityAssessment; after: QualityAssessment; comparable: boolean; improvement: number | null;
  dimensions: { code: string; name: string; before: number; after: number; improvement: number }[];
}
export interface QualityResponse {
  enabled: boolean; assessment: QualityAssessment | null;
  history?: { id: number; artifact_role: string; artifact_hash: string; assessment: QualityAssessment }[];
}

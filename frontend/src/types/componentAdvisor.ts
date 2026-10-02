/**
 * Secure Component Advisor API types (hand-written, mirrors
 * app/routers/component_advisor.py and app/metrics/component_advisor.py).
 *
 * Vocabulary is the spec's: never "safe" / "secure" / "vulnerability free" —
 * the best bucket is "No Known Actionable Vulnerabilities", and the score
 * only orders candidates.
 */

export type AdvisorRiskClassification =
  | 'NO_KNOWN_ACTIONABLE_VULNERABILITIES'
  | 'INFORMATIONAL'
  | 'LOW'
  | 'MEDIUM'
  | 'HIGH'
  | 'CRITICAL'
  | 'ACCEPTED_RISK'
  | 'REVIEW_REQUIRED'
  | 'UNKNOWN';

export type AdvisorLifecycleBucket = 'SUPPORTED' | 'MAINTENANCE' | 'EOS' | 'EOL' | 'UNKNOWN';
export type AdvisorConfidence = 'HIGH' | 'MEDIUM' | 'LOW' | 'INSUFFICIENT_EVIDENCE' | 'NOT_EVALUATED';
export type AdvisorCheckResult = 'PASS' | 'FAIL' | 'REVIEW_REQUIRED' | 'UNKNOWN';
export type AdvisorFacet = 'all' | 'name' | 'purl' | 'supplier' | 'ecosystem' | 'category' | 'purpose';
export type AdvisorSortField = 'name' | 'risk' | 'occurrences' | 'products' | 'actionable' | 'latest_analysis';
export type RecommendationStatus =
  | 'OPEN' | 'EVALUATING' | 'REVIEW_REQUIRED' | 'RECOMMENDED' | 'ACCEPTED' | 'REJECTED' | 'DEFERRED' | 'CLOSED';
export type RecommendationTrigger = 'CRITICAL_FINDING' | 'HIGH_FINDING' | 'EOL' | 'EOS' | 'POLICY_VIOLATION' | 'MANUAL';
export type RecommendationDecision = 'RECOMMEND' | 'ACCEPT' | 'REJECT' | 'DEFER' | 'REQUEST_MORE_EVIDENCE' | 'CLOSE';

export interface AdvisorAppliedFilters {
  risk: AdvisorRiskClassification[];
  lifecycle: AdvisorLifecycleBucket[];
  needs_review: boolean | null;
  frequently_adopted: boolean | null;
  trusted: boolean | null;
  q: string | null;
  facet: AdvisorFacet;
}

export interface AdvisorScopeMeta {
  level: 'TENANT' | 'PROJECT' | 'APPLICATION' | 'SBOM';
  tenant: { id: number; name: string | null };
  project: { id: number; name: string | null } | null;
  application: { id: number; name: string | null } | null;
  sbom: { id: number; name: string | null; version: string | null } | null;
}

export interface AdvisorMeta {
  applied_filters: AdvisorAppliedFilters;
  unsupported_filters: string[];
  scope: AdvisorScopeMeta;
  as_of: string;
  generated_at: string;
  historical_view: boolean;
  freshness: {
    latest_analysis_at: string | null;
    lifecycle_checked_at: string | null;
    vulnerability_source_refreshed_at: string | null;
    package_metadata_refreshed_at: string | null;
    coverage: { eligible_sboms: number; analysed_sboms: number; unattributed_actionable_findings: number };
    stale_flags: string[];
  };
  policy_versions: {
    accepted_risk: { policy_version_id: number; version: number; scope: string } | null;
    trust: { policy_version_id: number; version: number; scope: string } | null;
  };
  thresholds: { frequently_adopted_min_products: number };
  capabilities: { informational_severity_supported: boolean };
}

export interface AdvisorKpi {
  key: string;
  label: string;
  value: number | null;
  status: 'OK' | 'POLICY_NOT_CONFIGURED';
  render: boolean;
  filter: Partial<{
    risk: AdvisorRiskClassification[];
    lifecycle: AdvisorLifecycleBucket[];
    needs_review: boolean;
    frequently_adopted: boolean;
    trusted: boolean;
  }>;
}

export interface AdvisorSummary {
  kpis: AdvisorKpi[];
  by_classification: Record<AdvisorRiskClassification, number>;
  by_lifecycle: Record<AdvisorLifecycleBucket, number>;
  meta: AdvisorMeta;
}

export interface AdvisorPurposeField {
  value: string;
  source: 'SBOM' | 'PACKAGE' | 'CURATED' | 'AI';
  confidence: string;
  ai_assisted: boolean;
  provenance: Record<string, unknown>;
}

export interface AdvisorPurpose {
  status: 'AVAILABLE' | 'NOT_AVAILABLE';
  ai_assisted: boolean;
  functional_description: AdvisorPurposeField | null;
  primary_use_case: AdvisorPurposeField | null;
  technology_category: AdvisorPurposeField | null;
}

export interface AdvisorPolicyCriterion {
  criterion: string;
  passed: boolean;
  detail: string;
}

export interface AdvisorComponent {
  canonical_key: string;
  identity: { basis: string; confidence: string };
  family_key: string | null;
  name: string;
  version: string | null;
  purl: string | null;
  cpe: string | null;
  supplier: string | null;
  component_type: string | null;
  ecosystem: string | null;
  licenses: string[];
  purpose: AdvisorPurpose;
  trust: { status: 'POLICY_NOT_CONFIGURED' | 'TRUSTED_BY_POLICY' | 'NOT_TRUSTED'; policy_version_id: number | null; criteria: AdvisorPolicyCriterion[] };
  usage: {
    active_sbom_occurrences: number;
    sbom_count: number;
    project_count: number;
    product_count: number;
    references: Array<{ component_id: number; sbom_id: number; sbom_name: string | null; project_id: number | null; product_id: number | null }>;
  };
  risk: {
    classification: AdvisorRiskClassification;
    review_reasons: string[];
    accepted_risk_policy_version_id: number | null;
    accepted_risk: { policy_version_id: number | null; satisfied: boolean; criteria: AdvisorPolicyCriterion[] } | null;
    actionable_vulnerability_count: number;
    non_actionable_vulnerability_count: number;
    actionable_severity_counts: Record<'critical' | 'high' | 'medium' | 'low' | 'unknown', number>;
    highest_actionable_severity: string | null;
    cvss: { max_score: number | null; vector: string | null; version: string | null; scored_vulnerability_count: number };
    vex_only_context_count: number;
  };
  lifecycle: { bucket: AdvisorLifecycleBucket; status: string; effective_date: string | null; source: string | null; manual_override: boolean };
  freshness: { latest_analysis_at: string | null; analysed_occurrences: number; total_occurrences: number; lifecycle_checked_at: string | null; lifecycle_is_stale: boolean };
  evidence: Array<{ sbom_id: number; analysis_run_id: number }>;
  recommendation: { status: RecommendationStatus | 'NOT_EVALUATED'; id?: number; trigger_type?: RecommendationTrigger };
}

export interface AdvisorComponentDetail extends AdvisorComponent {
  eligible_triggers: RecommendationTrigger[];
  adoption: {
    interpretation: string;
    active_sbom_occurrences: number;
    projects: Array<{ id: number; name: string | null }>;
    products: Array<{ id: number; name: string | null }>;
    observed_versions: Array<{
      canonical_key: string; version: string | null; classification: AdvisorRiskClassification;
      lifecycle_bucket: AdvisorLifecycleBucket; licenses: string[]; active_sbom_occurrences: number;
      product_count: number; latest_analysis_at: string | null; is_this_version: boolean;
    }>;
    latest_evidence_at: string | null;
  };
  meta: AdvisorMeta;
}

export interface AdvisorComponentList {
  total: number;
  limit: number;
  offset: number;
  sort_by: AdvisorSortField;
  sort_order: 'asc' | 'desc';
  items: AdvisorComponent[];
  meta: AdvisorMeta;
}

export interface AdvisorSearchResult {
  search_status: 'OK' | 'NO_MATCHING_COMPONENTS' | 'INSUFFICIENT_PURPOSE_EVIDENCE';
  total: number;
  limit: number;
  offset: number;
  items: Array<{
    family_key: string | null;
    name: string;
    ecosystem: string | null;
    suppliers: string[];
    purpose: AdvisorPurpose;
    version_count: number;
    versions: Array<{
      canonical_key: string; version: string | null; classification: AdvisorRiskClassification;
      highest_actionable_severity: string | null; actionable_vulnerability_count: number;
      lifecycle_bucket: AdvisorLifecycleBucket; active_sbom_occurrences: number; product_count: number;
      latest_analysis_at: string | null;
    }>;
  }>;
  meta: AdvisorMeta;
}

export interface AdvisorFilterParams {
  risk?: AdvisorRiskClassification[];
  lifecycle?: AdvisorLifecycleBucket[];
  needs_review?: boolean;
  frequently_adopted?: boolean;
  trusted?: boolean;
  q?: string;
  facet?: AdvisorFacet;
  project_id?: number | null;
  product_id?: number | null;
  sbom_id?: number | null;
  sort_by?: AdvisorSortField;
  sort_order?: 'asc' | 'desc';
  limit?: number;
  offset?: number;
}

export interface AdvisorReason { code: string; detail?: string; count?: number; vulnerabilities?: string[] }
export interface AdvisorLimitation { code: string; detail?: string }

export interface AdvisorCompatibilitySummary {
  status: 'PASS' | 'REVIEW_REQUIRED' | 'BLOCKED' | 'NOT_EVALUATED';
  counts?: Record<AdvisorCheckResult, number>;
  blocking_checks?: string[];
  blocked?: boolean;
  drop_in_representable?: boolean;
}

export interface AdvisorHistory {
  status: 'AVAILABLE' | 'NO_VULNERABILITIES_IN_COVERED_WINDOW' | 'NO_HISTORY_COVERAGE';
  window_months: number;
  window_start: string;
  window_end: string;
  disclosed_vulnerability_count: number;
  severity_distribution: Record<string, number>;
  critical_high_count: number;
  first_observed: string | null;
  last_observed: string | null;
  exposure_days: number | null;
  coverage: { covered_months: number; sources: Array<{ source: string; status: string }>; gaps: string[] };
  note: string | null;
}

export interface AdvisorFreshnessView {
  latest_sbom_analysis_at: string | null;
  tenant_observation_at: string | null;
  vulnerability_source_refreshed_at: string | null;
  package_metadata_refreshed_at: string | null;
  lifecycle_refreshed_at: string | null;
  observation_window: { months: number | null; start: string | null; end: string | null; covered_months: number | null };
  stale_after_days: number;
  stale_flags: string[];
}

export interface AdvisorCandidate {
  id: number;
  candidate_kind: 'SAME_FAMILY_VERSION' | 'ALTERNATIVE';
  source_type: 'TENANT_OBSERVED' | 'EXTERNAL' | 'MANUAL';
  canonical_key: string | null;
  name: string;
  version: string | null;
  purl: string | null;
  ecosystem: string | null;
  rank: number;
  evidence_sources: string[];
  reasons: AdvisorReason[];
  limitations: AdvisorLimitation[];
  evaluation: {
    current_posture?: { status: string; classification?: AdvisorRiskClassification; highest_actionable_severity?: string | null; actionable_vulnerability_count?: number };
    lifecycle?: { bucket: AdvisorLifecycleBucket; status?: string; effective_date?: string | null };
    license?: { source: string[]; candidate: string[] | null; changed?: boolean | null };
    adoption?: { active_sbom_occurrences: number; product_count: number };
    [key: string]: unknown;
  };
  score: number | null;
  confidence: AdvisorConfidence;
  explanation: { summary: string; reasons: string[]; limitations: string[]; confidence: string } | null;
  history: AdvisorHistory | null;
  freshness: AdvisorFreshnessView | null;
  blocked: boolean;
  compatibility: AdvisorCompatibilitySummary;
  approved_replacement: boolean;
  recommended: boolean;
}

export interface AdvisorCapabilities {
  can_evaluate: boolean;
  can_recommend: boolean;
  can_accept: boolean;
  can_reject: boolean;
  can_defer: boolean;
  can_request_evidence: boolean;
  can_close: boolean;
  can_add_candidate: boolean;
  can_view_audit: boolean;
  can_decide: boolean;
  read_only_reason: string | null;
}

export interface AdvisorRecommendation {
  id: number;
  status: RecommendationStatus;
  trigger_type: RecommendationTrigger;
  trigger_evidence: Record<string, unknown>;
  source: { canonical_key: string; family_key: string | null; name: string; version: string | null; ecosystem: string | null; component_id: number | null };
  context: { project_id: number | null; product_id: number | null; sbom_id: number | null; level: 'SBOM' | 'TENANT' };
  discovery: {
    status: string;
    same_family_candidates?: number;
    alternative_candidates?: number;
    alternatives_status?: string;
    alternative_category?: string | null;
    external_sources?: Array<{ source: string; outcome: string; error: string | null }>;
    blocked_candidates?: number;
    source_history?: AdvisorHistory;
    source_posture?: { classification: AdvisorRiskClassification; highest_actionable_severity: string | null; lifecycle_bucket: AdvisorLifecycleBucket; actionable_vulnerability_ids: string[] };
    [key: string]: unknown;
  };
  evaluation_error: string | null;
  correlation_id: string | null;
  created_by: string | null;
  created_at: string | null;
  updated_at: string | null;
  evaluated_at: string | null;
  row_version: number;
  review: {
    recommended_candidate_id: number | null;
    accepted_candidate_id: number | null;
    last_decision: RecommendationDecision | null;
    last_decision_reason: string | null;
    decided_by: string | null;
    decided_at: string | null;
  };
  advisory_only: true;
  candidates?: AdvisorCandidate[];
  capabilities?: AdvisorCapabilities;
  created?: boolean;
}

export interface AdvisorCandidateEvidence {
  candidate_id: number;
  name: string;
  version: string | null;
  score: number | null;
  score_semantics: 'ORDERS_CANDIDATES_ONLY';
  confidence: AdvisorConfidence;
  confidence_basis: { level: AdvisorConfidence; completeness: number; unknown_material_checks: string[]; stale_flags: string[]; reasons: string[]; drop_in_representable: boolean } | null;
  scoring_policy: { policy_version_id: number | null; label: string } | null;
  factors: Array<{ factor: string; raw_value: unknown; normalized_value: number | null; weight: number; contribution: number; missing_data_treatment: string | null; evidence_source: string; evidence_at: string | null; policy_version_label: string }>;
  reasons: AdvisorReason[];
  limitations: AdvisorLimitation[];
  history: AdvisorHistory | null;
  freshness: AdvisorFreshnessView | null;
  compatibility: AdvisorCompatibilitySummary | null;
  explanation: AdvisorCandidate['explanation'];
  blocked: boolean;
  approved_replacement: boolean;
}

export interface AdvisorCompatibilityChecks {
  candidate_id: number;
  summary: AdvisorCompatibilitySummary;
  items: Array<{ id: number; check_type: string; result: AdvisorCheckResult; blocking: boolean; reason: string; limitation: string | null; evidence: Record<string, unknown>; evaluated_at: string | null }>;
}

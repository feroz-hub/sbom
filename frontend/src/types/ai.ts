/**
 * AI fix generator types.
 *
 * Mirror of the Pydantic schemas in ``app/ai/schemas.py``,
 * ``app/ai/progress.py``, and the responses defined in
 * ``app/routers/ai_fixes.py`` / ``app/routers/ai_usage.py``. Kept in a
 * dedicated module so feature-specific types don't bloat the global
 * ``index.ts`` namespace.
 */

export type AiExploitationLikelihood =
  | 'actively_exploited'
  | 'high'
  | 'moderate'
  | 'low'
  | 'theoretical';

export type AiConfidenceTier = 'high' | 'medium' | 'low';

export type AiBreakingChangeRisk = 'none' | 'minor' | 'major' | 'unknown';

export type AiPriorityTier = 'urgent' | 'soon' | 'scheduled' | 'defer';

export type AiCitationSource =
  | 'osv'
  | 'ghsa'
  | 'nvd'
  | 'epss'
  | 'kev'
  | 'fix_version_data';

export interface AiRemediationProse {
  summary_in_context: string;
  exploitation_likelihood: AiExploitationLikelihood;
  recommended_path: string;
  confidence: AiConfidenceTier;
}

export interface AiUpgradeCommand {
  ecosystem: string;
  command: string;
  target_version: string;
  rationale: string;
  breaking_change_risk: AiBreakingChangeRisk;
  tested_against_data: boolean;
}

export interface AiDecisionRecommendation {
  priority: AiPriorityTier;
  reasoning: string[];
  citations: AiCitationSource[];
  confidence: AiConfidenceTier;
  caveats: string[];
}

export interface AiFixBundle {
  remediation_prose: AiRemediationProse;
  upgrade_command: AiUpgradeCommand;
  decision_recommendation: AiDecisionRecommendation;
}

export interface AiFixMetadata {
  cache_key: string;
  cache_hit: boolean;
  provider_used: string;
  model_used: string;
  prompt_version: string;
  schema_version: number;
  total_cost_usd: number;
  generated_at: string;
  expires_at: string;
  age_seconds: number;
}

export interface AiFixResult {
  finding_id: number | null;
  vuln_id: string;
  component_name: string;
  component_version: string;
  bundle: AiFixBundle;
  metadata: AiFixMetadata;
}

export type AiFixErrorCode =
  | 'schema_parse_failed'
  | 'provider_unavailable'
  | 'circuit_breaker_open'
  | 'budget_exceeded'
  | 'grounding_missing'
  | 'internal_error';

export interface AiFixError {
  finding_id: number | null;
  vuln_id: string;
  component_name: string;
  component_version: string;
  error_code: AiFixErrorCode;
  message: string;
}

/** Response envelope used by ``GET /findings/{id}/ai-fix`` and the regenerate endpoint. */
export interface AiFindingFixEnvelope {
  result: AiFixResult | null;
  error: AiFixError | null;
}

export type AiBatchStatus =
  | 'pending'
  | 'in_progress'
  | 'paused_budget'
  | 'complete'
  | 'failed'
  | 'cancelled';

export interface AiBatchProgress {
  run_id: number;
  status: AiBatchStatus;
  total: number;
  from_cache: number;
  generated: number;
  failed: number;
  remaining: number;
  cost_so_far_usd: number;
  estimated_remaining_seconds: number | null;
  estimated_remaining_cost_usd: number | null;
  started_at: string | null;
  finished_at: string | null;
  last_error: string | null;
  cancel_requested: boolean;
  provider_used: string | null;
  model_used: string | null;
}

export interface AiTriggerBatchRequest {
  provider_name?: string | null;
  force_refresh?: boolean;
  budget_usd?: number | null;
}

export interface AiTriggerBatchResponse {
  progress: AiBatchProgress;
  enqueued: boolean;
}

export interface AiFindingFixListItem {
  cache_key: string;
  vuln_id: string;
  component_name: string;
  component_version: string;
  provider_used: string;
  model_used: string;
  total_cost_usd: number;
  generated_at: string;
  expires_at: string;
}

export interface AiFindingFixListResponse {
  run_id: number;
  items: AiFindingFixListItem[];
  total: number;
}

/** Provider info exposed to the Settings page. */
export interface AiProviderInfo {
  name: string;
  available: boolean;
  default_model: string;
  supports_structured_output: boolean;
  is_local: boolean;
  notes: string;
}

export interface AiPricingEntry {
  provider: string;
  model: string;
  input_per_1k_usd: number;
  output_per_1k_usd: number;
}

/** Aggregate of usage telemetry returned by ``GET /api/v1/ai/usage``. */
export interface AiUsageTotals {
  window_days: number;
  total_calls: number;
  total_cache_hits: number;
  cache_hit_ratio: number;
  total_cost_usd: number;
  total_input_tokens: number;
  total_output_tokens: number;
}

export interface AiUsageBucket {
  label: string;
  calls: number;
  cost_usd: number;
}

export interface AiUsageSummary {
  today: AiUsageTotals;
  last_30_days: AiUsageTotals;
  by_purpose: AiUsageBucket[];
  by_provider: AiUsageBucket[];
  budget_caps_usd: {
    per_request_usd: number | null;
    per_scan_usd: number | null;
    per_day_org_usd: number | null;
  };
  spent_today_usd: number;
  daily_remaining_usd: number | null;
}

/** One day in the cost-trend sparkline. */
export interface AiUsageTrendPoint {
  day: string;
  calls: number;
  cost_usd: number;
  cache_hits: number;
}

export interface AiUsageTrendResponse {
  days: number;
  points: AiUsageTrendPoint[];
}

/** Row of the "most expensive cached fixes" leaderboard. */
export interface AiTopCachedItem {
  cache_key: string;
  vuln_id: string;
  component_name: string;
  component_version: string;
  provider_used: string;
  model_used: string;
  total_cost_usd: number;
  generated_at: string;
}

// ─── Phase 3 — credential + settings shapes ────────────────────────────────

export type AiTier = 'free' | 'paid';

export type AiConnectionErrorKind =
  | 'network'
  | 'auth'
  | 'rate_limit'
  | 'model_not_found'
  | 'invalid_response'
  | 'unknown';

export interface AiConnectionTestResult {
  success: boolean;
  latency_ms: number | null;
  detected_models: string[];
  error_message: string | null;
  error_kind: AiConnectionErrorKind | null;
  provider: string;
  model_tested: string | null;
}

export interface AiCredential {
  id: number;
  provider_name: string;
  label: string;
  api_key_present: boolean;
  api_key_preview: string | null;
  base_url: string | null;
  default_model: string | null;
  tier: string;
  is_default: boolean;
  is_fallback: boolean;
  enabled: boolean;
  cost_per_1k_input_usd: number;
  cost_per_1k_output_usd: number;
  is_local: boolean;
  max_concurrent: number | null;
  rate_per_minute: number | null;
  created_at: string;
  updated_at: string;
  last_test_at: string | null;
  last_test_success: boolean | null;
  last_test_error: string | null;
}

export interface AiCredentialCreateRequest {
  provider_name: string;
  label?: string;
  api_key?: string | null;
  base_url?: string | null;
  default_model?: string | null;
  tier?: AiTier;
  enabled?: boolean;
  is_default?: boolean;
  is_fallback?: boolean;
  cost_per_1k_input_usd?: number;
  cost_per_1k_output_usd?: number;
  is_local?: boolean;
  max_concurrent?: number | null;
  rate_per_minute?: number | null;
}

export interface AiCredentialUpdateRequest {
  label?: string;
  api_key?: string;
  base_url?: string | null;
  default_model?: string;
  tier?: AiTier;
  enabled?: boolean;
  cost_per_1k_input_usd?: number;
  cost_per_1k_output_usd?: number;
  is_local?: boolean;
  max_concurrent?: number | null;
  rate_per_minute?: number | null;
}

export interface AiTestConnectionRequest {
  provider_name: string;
  api_key?: string | null;
  base_url?: string | null;
  default_model?: string | null;
  tier?: AiTier;
  cost_per_1k_input_usd?: number;
  cost_per_1k_output_usd?: number;
  is_local?: boolean;
}

/** Singleton settings — DB-backed. */
export interface AiCredentialSettings {
  feature_enabled: boolean;
  kill_switch_active: boolean;
  budget_per_request_usd: number;
  budget_per_scan_usd: number;
  budget_daily_usd: number;
  updated_at: string;
  updated_by_user_id: string | null;
  source: string;
}

export interface AiCredentialSettingsUpdateRequest {
  feature_enabled?: boolean;
  kill_switch_active?: boolean;
  budget_per_request_usd?: number;
  budget_per_scan_usd?: number;
  budget_daily_usd?: number;
}

// Catalog (Phase 1 endpoint, consumed by Phase 3 UI for form rendering).

export interface AiCatalogModel {
  name: string;
  display_name: string;
  default_tier: AiTier;
  notes: string;
}

export interface AiProviderCatalogEntry {
  name: string;
  display_name: string;
  requires_api_key: boolean;
  requires_base_url: boolean;
  is_local: boolean;
  supports_free_tier: boolean;
  free_tier_rate_limit_rpm: number | null;
  free_tier_daily_token_limit: number | null;
  available_models: AiCatalogModel[];
  docs_url: string;
  api_key_url: string;
  notes: string;
}

// Free-tier batch-duration estimate.

export interface AiBatchDurationEstimate {
  run_id: number;
  findings_total: number;
  findings_to_generate: number;
  cached_count: number;
  provider: string;
  tier: string;
  is_local: boolean;
  concurrency: number;
  requests_per_minute: number;
  estimated_seconds: number;
  estimated_cost_usd: number;
  bottleneck: string;
  warning_recommended: boolean;
}

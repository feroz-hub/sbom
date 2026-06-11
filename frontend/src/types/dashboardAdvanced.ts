/**
 * Dashboard v4 — advanced analytics payloads.
 *
 * Wire shapes for /dashboard/forecast, /dashboard/exploitation,
 * /dashboard/remediation, /dashboard/risk-map, /dashboard/risk-matrix and
 * the AI Copilot endpoints. Mirrors the metric envelopes in
 * `app/metrics/{forecast,exploitation,remediation,riskmap}.py` — keep in
 * sync with `schema_version`.
 */

// ─── Forecast ────────────────────────────────────────────────────────────────

export interface ForecastHistoryPoint {
  date: string; // YYYY-MM-DD
  total: number;
}

export interface ForecastProjectionPoint {
  date: string;
  projected: number;
  lo: number;
  hi: number;
}

export interface VelocityAnomaly {
  detected: boolean;
  zscore: number | null;
  delta: number;
  baseline_mean: number;
  baseline_std: number;
}

export interface FindingsForecast {
  history: ForecastHistoryPoint[];
  history_days: number;
  horizon_days: number;
  insufficient_history: boolean;
  projection: ForecastProjectionPoint[];
  slope_per_day: number;
  r_squared: number;
  current_total: number;
  projected_total: number | null;
  days_to_zero: number | null;
  anomaly: VelocityAnomaly;
  schema_version: number;
}

// ─── Exploitation outlook ────────────────────────────────────────────────────

export interface ExploitationDriver {
  cve: string;
  epss: number; // 0..1
  percentile: number | null; // 0..1
  kev: boolean;
}

export interface ExploitationOutlook {
  probability_30d: number; // 0..1
  distinct_cves: number;
  scored_cves: number;
  coverage: number; // 0..1
  kev_cves: number;
  top_drivers: ExploitationDriver[];
  assumption: 'independent';
  schema_version: number;
}

// ─── Remediation / SLA ───────────────────────────────────────────────────────

export type SlaSeverity = 'critical' | 'high' | 'medium' | 'low' | 'unknown';

export interface SlaOffender {
  vuln_id: string;
  component_name: string;
  component_version: string;
  severity: SlaSeverity;
  sbom_name: string;
  age_days: number;
  sla_days: number;
  days_over: number;
  first_seen: string; // YYYY-MM-DD
}

export interface RemediationSummary {
  mttr_days: Partial<Record<SlaSeverity | 'overall', number | null>>;
  resolved_total: number;
  reopened_total: number;
  sla: {
    budgets_days: Record<SlaSeverity, number>;
    overdue: number;
    due_soon: number;
    ok: number;
    by_severity_overdue: Partial<Record<SlaSeverity, number>>;
    worst_offenders: SlaOffender[];
  };
  velocity: {
    window_days: number;
    new_findings: number;
    resolved_findings: number;
    net: number;
  };
  schema_version: number;
}

// ─── Risk map (treemap) + risk matrix (scatter) ──────────────────────────────

export interface RiskMapItem {
  sbom_id: number;
  run_id: number;
  name: string;
  project: string | null;
  findings_total: number;
  critical: number;
  high: number;
  medium: number;
  low: number;
  unknown: number;
  dominant: SlaSeverity | 'none';
  last_analysed: string | null;
}

export interface RiskMapResponse {
  items: RiskMapItem[];
  schema_version: number;
}

export interface RiskMatrixPoint {
  vuln_id: string;
  component: string;
  severity: SlaSeverity;
  cvss: number; // 0..10
  epss: number; // 0..1
  kev: boolean;
  has_fix: boolean;
}

export interface RiskMatrixResponse {
  points: RiskMatrixPoint[];
  total_distinct: number;
  unplotted_no_cvss: number;
  limit: number;
  schema_version: number;
}

// ─── AI Security Copilot ─────────────────────────────────────────────────────

export interface CopilotBriefing {
  briefing: string; // markdown
  generated_at: string;
  provider: string;
  model: string;
  cost_usd: number;
  cached: boolean;
  schema_version: number;
}

export interface CopilotAnswer {
  answer: string; // markdown
  question: string;
  generated_at: string;
  provider: string;
  model: string;
  cost_usd: number;
  schema_version: number;
}

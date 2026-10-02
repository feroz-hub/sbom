/**
 * Display labels for Secure Component Advisor codes.
 *
 * Spec §1.2 terminology: the best bucket is "No Known Actionable
 * Vulnerabilities" — never "Safe", "Secure" or "Vulnerability Free" — and the
 * score is a ranking aid, never a "Safety Score". A test scans these maps.
 */

import type {
  AdvisorCheckResult,
  AdvisorConfidence,
  AdvisorLifecycleBucket,
  AdvisorRiskClassification,
  RecommendationDecision,
  RecommendationStatus,
  RecommendationTrigger,
} from '@/types/componentAdvisor';

export const RISK_LABELS: Record<AdvisorRiskClassification, string> = {
  NO_KNOWN_ACTIONABLE_VULNERABILITIES: 'No Known Actionable Vulnerabilities',
  INFORMATIONAL: 'Informational',
  LOW: 'Low',
  MEDIUM: 'Medium',
  HIGH: 'High',
  CRITICAL: 'Critical',
  ACCEPTED_RISK: 'Accepted Risk',
  REVIEW_REQUIRED: 'Review Required',
  UNKNOWN: 'Unknown',
};

/** Filter order shown in the UI (spec FR-SCA-007). */
export const RISK_FILTERS: AdvisorRiskClassification[] = [
  'NO_KNOWN_ACTIONABLE_VULNERABILITIES', 'INFORMATIONAL', 'LOW', 'MEDIUM', 'HIGH', 'CRITICAL',
  'ACCEPTED_RISK', 'REVIEW_REQUIRED', 'UNKNOWN',
];

export const LIFECYCLE_LABELS: Record<AdvisorLifecycleBucket, string> = {
  SUPPORTED: 'Supported',
  MAINTENANCE: 'Maintenance',
  EOS: 'End of support',
  EOL: 'End of life',
  UNKNOWN: 'Lifecycle unknown',
};

export const CONFIDENCE_LABELS: Record<AdvisorConfidence, string> = {
  HIGH: 'High confidence',
  MEDIUM: 'Medium confidence',
  LOW: 'Low confidence',
  INSUFFICIENT_EVIDENCE: 'Insufficient evidence',
  NOT_EVALUATED: 'Not evaluated',
};

export const CHECK_LABELS: Record<AdvisorCheckResult, string> = {
  PASS: 'Pass',
  FAIL: 'Fail',
  REVIEW_REQUIRED: 'Review required',
  UNKNOWN: 'Unknown',
};

export const TRIGGER_LABELS: Record<RecommendationTrigger, string> = {
  CRITICAL_FINDING: 'Critical finding',
  HIGH_FINDING: 'High finding',
  EOL: 'End of life',
  EOS: 'End of support',
  POLICY_VIOLATION: 'Policy violation',
  MANUAL: 'Manual request',
};

export const STATUS_LABELS: Record<RecommendationStatus | 'NOT_EVALUATED', string> = {
  NOT_EVALUATED: 'No recommendation',
  OPEN: 'Open',
  EVALUATING: 'Evaluating',
  REVIEW_REQUIRED: 'Review required',
  RECOMMENDED: 'Recommended',
  ACCEPTED: 'Accepted',
  REJECTED: 'Rejected',
  DEFERRED: 'Deferred',
  CLOSED: 'Closed',
};

export const DECISION_LABELS: Record<RecommendationDecision, string> = {
  RECOMMEND: 'Recommend candidate',
  ACCEPT: 'Accept',
  REJECT: 'Reject',
  DEFER: 'Defer',
  REQUEST_MORE_EVIDENCE: 'Request more evidence',
  CLOSE: 'Close',
};

export const FACET_LABELS = {
  all: 'All fields',
  name: 'Component name',
  purl: 'Package / PURL',
  supplier: 'Supplier',
  ecosystem: 'Ecosystem',
  category: 'Technology category',
  purpose: 'Purpose / use case',
} as const;

/** "SAME_ECOSYSTEM" → "Same ecosystem". Codes stay visible as the authoritative evidence. */
export function readableCode(code: string): string {
  return code.toLowerCase().replaceAll('_', ' ').replace(/^./, (first) => first.toUpperCase());
}

export function formatTimestamp(value: string | null | undefined): string {
  if (!value) return 'Not available';
  const date = new Date(value);
  return Number.isNaN(date.getTime()) ? value : date.toLocaleString();
}

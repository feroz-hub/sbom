import type { AdvisorPolicyKind } from '@/lib/advisorPolicyApi';

export const lifecycleBuckets = [
  'SUPPORTED',
  'MAINTENANCE',
  'EOS',
  'EOL',
  'UNKNOWN',
] as const;
export const actionableVex = ['AFFECTED', 'UNDER_INVESTIGATION'] as const;
export const scoringWeights = {
  current_risk: 0.3,
  lifecycle: 0.2,
  vulnerability_trend: 0.15,
  compatibility: 0.15,
  maintenance: 0.08,
  license: 0.05,
  tenant_adoption: 0.05,
  evidence_freshness: 0.02,
};
export const definitions: {
  kind: AdvisorPolicyKind;
  title: string;
  label: string;
  description: string;
  example: Record<string, unknown>;
}[] = [
  {
    kind: 'accepted-risk',
    title: 'Accepted Risk',
    label: 'Accepted risk',
    description:
      'Define when Low or Medium actionable risk may be accepted. High, Critical, unknown severity and evidence requiring review cannot qualify.',
    example: {
      max_actionable_severity: 'MEDIUM',
      max_cvss_score: 6.9,
      max_actionable_vulnerabilities: 3,
      allowed_actionable_vex_statuses: [...actionableVex],
      allowed_lifecycle: null,
      max_analysis_age_days: 30,
    },
  },
  {
    kind: 'trust',
    title: 'Trust',
    label: 'Trust',
    description:
      'Trust requires an allowed risk classification and lifecycle state. License lists, evidence freshness, review reasons and product adoption can add criteria; adoption alone never grants trust.',
    example: {
      allowed_classifications: ['NO_KNOWN_ACTIONABLE_VULNERABILITIES', 'LOW'],
      allowed_lifecycle: ['SUPPORTED'],
      allowed_licenses: ['MIT', 'Apache-2.0'],
      max_evidence_age_days: 90,
      require_no_review_reasons: true,
    },
  },
  {
    kind: 'scoring',
    title: 'Recommendation Scoring',
    label: 'Recommendation scoring',
    description:
      'Weights order recommendation candidates; they do not override security or compatibility gates. Non-negative weights need a positive total and are normalized during scoring.',
    example: {
      weights: scoringWeights,
      missing_data: 'PENALIZE',
      history_window_months: 24,
      stale_after_days: 90,
    },
  },
];
export type PolicyDefinition = (typeof definitions)[number];
export type RuleErrors = Record<string, string>;

export function parseRules(text: string): {
  rules: Record<string, unknown> | null;
  error: string | null;
} {
  try {
    const value: unknown = JSON.parse(text);
    if (!value || typeof value !== 'object' || Array.isArray(value))
      return { rules: null, error: 'Rules must be a JSON object.' };
    return { rules: value as Record<string, unknown>, error: null };
  } catch {
    return {
      rules: null,
      error: 'Invalid JSON. Check quotes, commas and brackets.',
    };
  }
}

/** Display validation mirrors policy.py and recommendations/scoring.py; the server remains authoritative. */
export function validateRules(
  kind: AdvisorPolicyKind,
  rules: Record<string, unknown>,
): RuleErrors {
  const errors: RuleErrors = {};
  const keys =
    kind === 'accepted-risk'
      ? [
          'max_actionable_severity',
          'max_cvss_score',
          'max_actionable_vulnerabilities',
          'allowed_actionable_vex_statuses',
          'allowed_lifecycle',
          'max_analysis_age_days',
        ]
      : kind === 'trust'
        ? [
            'allowed_classifications',
            'allowed_lifecycle',
            'allowed_licenses',
            'denied_licenses',
            'max_evidence_age_days',
            'min_tenant_products',
            'require_no_review_reasons',
          ]
        : [
            'weights',
            'missing_data',
            'history_window_months',
            'stale_after_days',
          ];
  const unknown = Object.keys(rules).filter((key) => !keys.includes(key));
  if (unknown.length)
    errors.rules = `Unknown ${kind} rule(s): ${unknown.join(', ')}. Remove or correct these fields before publishing.`;
  function number(
    key: string,
    minimum: number,
    integer = false,
    maximum = Infinity,
    defaultValue?: number,
  ) {
    const value = key in rules ? rules[key] : defaultValue;
    if (value == null && defaultValue === undefined) return;
    if (
      typeof value !== 'number' ||
      !Number.isFinite(value) ||
      (integer && !Number.isInteger(value)) ||
      value < minimum ||
      value > maximum
    )
      errors[key] =
        `${key} must be ${integer ? 'an integer' : 'a number'} from ${minimum}${Number.isFinite(maximum) ? ` to ${maximum}` : ' or greater'}.`;
  }
  function list(
    key: string,
    allowed: readonly string[],
    required = false,
    trim = true,
    defaultValue?: readonly string[],
  ) {
    const value = key in rules ? rules[key] : defaultValue;
    if (value == null && !required) return;
    if (
      !Array.isArray(value) ||
      (required && !value.length) ||
      value.some(
        (item) =>
          !allowed.includes(
            trim
              ? String(item).trim().toUpperCase()
              : String(item).toUpperCase(),
          ),
      )
    )
      errors[key] =
        `${key} must be ${required ? 'a non-empty selection' : 'a list'} of ${allowed.join(', ')}.`;
  }
  if (kind === 'accepted-risk') {
    if (
      !['LOW', 'MEDIUM'].includes(
        String(rules.max_actionable_severity ?? '')
          .trim()
          .toUpperCase(),
      )
    )
      errors.max_actionable_severity =
        'Maximum actionable severity must be LOW or MEDIUM.';
    number('max_cvss_score', 0, false, 10);
    number('max_actionable_vulnerabilities', 0, true);
    number('max_analysis_age_days', 1, true);
    list(
      'allowed_actionable_vex_statuses',
      actionableVex,
      true,
      false,
      actionableVex,
    );
    list('allowed_lifecycle', lifecycleBuckets);
  } else if (kind === 'trust') {
    list(
      'allowed_classifications',
      ['NO_KNOWN_ACTIONABLE_VULNERABILITIES', 'ACCEPTED_RISK', 'LOW', 'MEDIUM'],
      true,
    );
    list('allowed_lifecycle', lifecycleBuckets, true);
    for (const key of ['allowed_licenses', 'denied_licenses']) {
      const value = rules[key];
      if (
        value != null &&
        (!Array.isArray(value) ||
          value.some((item) => typeof item !== 'string' || !item.trim()))
      )
        errors[key] = `${key} must be a list of non-empty strings.`;
    }
    number('max_evidence_age_days', 1, true);
    number('min_tenant_products', 1, true);
    if (
      'require_no_review_reasons' in rules &&
      typeof rules.require_no_review_reasons !== 'boolean'
    )
      errors.require_no_review_reasons =
        'require_no_review_reasons must be true or false.';
  } else {
    const weights = 'weights' in rules ? rules.weights : scoringWeights;
    if (
      !weights ||
      typeof weights !== 'object' ||
      Array.isArray(weights) ||
      Object.entries(weights).some(
        ([key, value]) =>
          !Object.prototype.hasOwnProperty.call(scoringWeights, key) ||
          typeof value !== 'number' ||
          !Number.isFinite(value) ||
          value < 0,
      ) ||
      Object.values(weights).reduce<number>(
        (sum, value) => sum + (typeof value === 'number' ? value : 0),
        0,
      ) <= 0
    )
      errors.weights =
        'weights must contain only known scoring factors with non-negative numbers and a positive total.';
    if (
      !['PENALIZE', 'EXCLUDE'].includes(
        String(
          'missing_data' in rules ? rules.missing_data : 'PENALIZE',
        ).toUpperCase(),
      )
    )
      errors.missing_data = 'missing_data must be PENALIZE or EXCLUDE.';
    // Explicit null is invalid for these settings; an omitted field uses its backend default.
    number('history_window_months', 6, true, 120, 24);
    number('stale_after_days', 1, true, 3650, 90);
  }
  return errors;
}

export function summarizeRules(
  kind: AdvisorPolicyKind,
  rules: Record<string, unknown>,
): string {
  if (kind === 'accepted-risk')
    return `Maximum severity: ${rules.max_actionable_severity ?? 'not set'} · CVSS: ${rules.max_cvss_score ?? 'no limit'} · Actionable vulnerabilities: ${rules.max_actionable_vulnerabilities ?? 'no limit'}`;
  if (kind === 'trust')
    return `Risk classifications: ${Array.isArray(rules.allowed_classifications) ? rules.allowed_classifications.join(', ') : 'not set'}. Lifecycle: ${Array.isArray(rules.allowed_lifecycle) ? rules.allowed_lifecycle.join(', ') : 'not set'}.`;
  return `Missing data: ${rules.missing_data ?? 'PENALIZE'} · History: ${rules.history_window_months ?? 24} months · Stale after: ${rules.stale_after_days ?? 90} days. Weights are normalized; EXCLUDE renormalizes over factors with data.`;
}

import { describe, expect, it } from 'vitest';
import { definitions, parseRules, validateRules } from './policyRules';

describe('Policy rule presentation validation', () => {
  it.each(definitions)(
    'accepts the existing $kind rule template',
    (definition) => {
      expect(validateRules(definition.kind, definition.example)).toEqual({});
    },
  );
  it.each(['HIGH', 'CRITICAL', 'UNKNOWN', ''])(
    'rejects %s as an accepted-risk threshold',
    (severity) => {
      expect(
        validateRules('accepted-risk', { max_actionable_severity: severity }),
      ).toHaveProperty('max_actionable_severity');
    },
  );
  it('accepts backend normalization and optional nulls', () => {
    expect(
      validateRules('accepted-risk', {
        max_actionable_severity: ' low ',
        max_cvss_score: null,
        max_actionable_vulnerabilities: null,
        max_analysis_age_days: null,
        allowed_actionable_vex_statuses: ['affected'],
        allowed_lifecycle: [' maintenance '],
      }),
    ).toEqual({});
  });
  it.each([[], {}, null, ['HIGH'], [' AFFECTED ']])(
    'rejects invalid actionable VEX selections %s',
    (value) => {
      expect(
        validateRules('accepted-risk', {
          max_actionable_severity: 'LOW',
          allowed_actionable_vex_statuses: value,
        }),
      ).toHaveProperty('allowed_actionable_vex_statuses');
    },
  );
  it('accepts an empty lifecycle list as unrestricted and rejects unknown buckets', () => {
    expect(
      validateRules('accepted-risk', {
        max_actionable_severity: 'LOW',
        allowed_lifecycle: [],
      }),
    ).toEqual({});
    expect(
      validateRules('accepted-risk', {
        max_actionable_severity: 'LOW',
        allowed_lifecycle: ['UNSUPPORTED'],
      }),
    ).toHaveProperty('allowed_lifecycle');
  });
  it('keeps review-reason checks optional for Trust and rejects disallowed classifications', () => {
    const rules = {
      allowed_classifications: ['MEDIUM'],
      allowed_lifecycle: ['EOL'],
      require_no_review_reasons: false,
    };
    expect(validateRules('trust', rules)).toEqual({});
    expect(
      validateRules('trust', { ...rules, allowed_classifications: ['HIGH'] }),
    ).toHaveProperty('allowed_classifications');
  });
  it('allows scoring weights that do not sum to one, including omitted factors', () => {
    expect(
      validateRules('scoring', {
        weights: { current_risk: 2, lifecycle: 3 },
        missing_data: 'exclude',
      }),
    ).toEqual({});
    expect(validateRules('scoring', {})).toEqual({});
  });
  it.each<Record<string, unknown>>([
    { weights: {} },
    { weights: { current_risk: -1 } },
    { weights: { constructor: 1 } },
    { weights: { current_risk: true } },
    { missing_data: null },
    { history_window_months: null },
    { history_window_months: 5 },
    { stale_after_days: 3651 },
  ])('rejects invalid scoring settings %s', (rules) => {
    expect(Object.keys(validateRules('scoring', rules)).length).toBeGreaterThan(
      0,
    );
  });
  it.each(['null', '[]', 'false', 'invalid'])(
    'rejects non-object JSON: %s',
    (text) => {
      expect(parseRules(text).error).toBeTruthy();
    },
  );
  it('rejects unknown fields without mutating or dropping them', () => {
    const rules = { max_actionable_severity: 'LOW', future_field: 42 };
    expect(validateRules('accepted-risk', rules)).toHaveProperty('rules');
    expect(rules.future_field).toBe(42);
  });
});

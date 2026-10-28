/**
 * The shared VEX decision validator.
 *
 * These rules previously existed twice — `validateVexOverride` on the SBOM
 * page and `validate()` in the investigation panel — worded differently
 * against different status vocabularies. Testing the single implementation
 * directly is what stops them re-diverging.
 *
 * Mirrors the backend (`_validate_vex_result`, spec VEX-VAL-001/002).
 */

import { describe, expect, it } from 'vitest';
import {
  EMPTY_DRAFT,
  FIELD_GUIDANCE,
  firstError,
  hasErrors,
  validateVexDecision,
  type VexDecisionDraft,
} from './vexDecisionValidation';

function draft(overrides: Partial<VexDecisionDraft> = {}): VexDecisionDraft {
  return { ...EMPTY_DRAFT, reason: 'reviewed by security', ...overrides };
}

describe('reason', () => {
  it('is required for every status__VEX_AUD_001', () => {
    for (const status of ['AFFECTED', 'NOT_AFFECTED', 'FIXED', 'UNDER_INVESTIGATION'] as const) {
      const errors = validateVexDecision(draft({ status, reason: '   ', justification: 'x', fixedVersion: '1' }));
      expect(errors.reason, `${status} must still require a reason`).toBe('A reason is required.');
    }
  });

  it('accepts a non-blank reason', () => {
    expect(hasErrors(validateVexDecision(draft()))).toBe(false);
  });
});

describe('NOT_AFFECTED__VEX_VAL_001', () => {
  it('requires a justification or an impact statement', () => {
    const errors = validateVexDecision(draft({ status: 'NOT_AFFECTED' }));
    expect(errors.justification).toMatch(/justification or an impact statement/);
    // Flagged on both fields, since either one satisfies the rule.
    expect(errors.impactStatement).toBe(errors.justification);
  });

  it('is satisfied by a justification alone', () => {
    expect(
      hasErrors(validateVexDecision(draft({ status: 'NOT_AFFECTED', justification: 'code not reachable' }))),
    ).toBe(false);
  });

  it('is satisfied by an impact statement alone', () => {
    expect(
      hasErrors(validateVexDecision(draft({ status: 'NOT_AFFECTED', impactStatement: 'not exploitable here' }))),
    ).toBe(false);
  });

  it('treats whitespace as absent', () => {
    expect(
      hasErrors(validateVexDecision(draft({ status: 'NOT_AFFECTED', justification: '   ' }))),
    ).toBe(true);
  });
});

describe('FIXED__VEX_VAL_002', () => {
  it('requires a fixed version or evidence', () => {
    const errors = validateVexDecision(draft({ status: 'FIXED' }));
    expect(errors.fixedVersion).toMatch(/fixed version or evidence/);
    expect(errors.evidenceUrl).toBe(errors.fixedVersion);
  });

  it('is satisfied by a fixed version alone', () => {
    expect(hasErrors(validateVexDecision(draft({ status: 'FIXED', fixedVersion: '3.0.9' })))).toBe(false);
  });

  it('is satisfied by evidence alone', () => {
    expect(
      hasErrors(validateVexDecision(draft({ status: 'FIXED', evidenceUrl: 'https://example.test/fix' }))),
    ).toBe(false);
  });
});

describe('AFFECTED and UNDER_INVESTIGATION', () => {
  it('need nothing beyond a reason', () => {
    expect(hasErrors(validateVexDecision(draft({ status: 'AFFECTED' })))).toBe(false);
    expect(hasErrors(validateVexDecision(draft({ status: 'UNDER_INVESTIGATION' })))).toBe(false);
  });
});

describe('field guidance', () => {
  it('covers all four canonical statuses and no fifth__VEX_STAT_001', () => {
    expect(Object.keys(FIELD_GUIDANCE).sort()).toEqual([
      'AFFECTED',
      'FIXED',
      'NOT_AFFECTED',
      'UNDER_INVESTIGATION',
    ]);
  });

  it('emphasises the fields each status actually needs', () => {
    expect(FIELD_GUIDANCE.NOT_AFFECTED.emphasised).toContain('justification');
    expect(FIELD_GUIDANCE.FIXED.emphasised).toContain('fixedVersion');
    expect(FIELD_GUIDANCE.AFFECTED.emphasised).toContain('actionStatement');
  });
});

describe('firstError', () => {
  it('returns null when the draft is valid', () => {
    expect(firstError(validateVexDecision(draft()))).toBeNull();
  });

  it('returns a message when it is not', () => {
    expect(firstError(validateVexDecision(draft({ reason: '' })))).toBe('A reason is required.');
  });
});

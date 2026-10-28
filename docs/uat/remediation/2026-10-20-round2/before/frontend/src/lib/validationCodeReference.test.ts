import { describe, expect, it } from 'vitest';
import {
  VALIDATION_CODE_REFERENCE,
  lookupValidationCode,
  validationCodeAnchor,
} from './validationCodeReference';

describe('VALIDATION_CODE_REFERENCE', () => {
  it('covers every pipeline stage at least once', () => {
    const stages = new Set(VALIDATION_CODE_REFERENCE.map((r) => r.stage_number));
    // We expect every stage from ingress (1) through signature (8) to be
    // represented so the in-app docs surface a worked example for any code
    // a user might encounter.
    [1, 2, 3, 4, 5, 6, 7, 8].forEach((n) => expect(stages).toContain(n));
  });

  it('anchors are lowercased canonical codes', () => {
    for (const ref of VALIDATION_CODE_REFERENCE) {
      expect(ref.anchor).toBe(ref.code.toLowerCase());
      expect(ref.anchor).toMatch(/^sbom_val_[ewi][0-9]{3}_[a-z0-9_]+$/);
    }
  });

  it('codes are unique', () => {
    const seen = new Set<string>();
    for (const ref of VALIDATION_CODE_REFERENCE) {
      expect(seen.has(ref.code)).toBe(false);
      seen.add(ref.code);
    }
  });
});

describe('lookupValidationCode / validationCodeAnchor', () => {
  it('looks up a known code', () => {
    const ref = lookupValidationCode('SBOM_VAL_E052_PURL_INVALID');
    expect(ref).toBeDefined();
    expect(ref!.stage).toBe('semantic');
    expect(ref!.stage_number).toBe(4);
  });

  it('returns undefined for unknown codes (chip should still link)', () => {
    expect(lookupValidationCode('SBOM_VAL_E999_BOGUS')).toBeUndefined();
  });

  it('builds a stable anchor URL even for codes not in the reference', () => {
    expect(validationCodeAnchor('SBOM_VAL_E999_BOGUS')).toBe(
      '/docs/sbom-validation-errors#sbom_val_e999_bogus',
    );
  });
});

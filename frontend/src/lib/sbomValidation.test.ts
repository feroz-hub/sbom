import { describe, expect, it } from 'vitest';
import {
  groupEntriesByStage,
  severityChipClasses,
  stageLabel,
  stageNumber,
  validationStatusMeta,
} from './sbomValidation';
import type { ValidationErrorEntry } from '@/types';

const e = (overrides: Partial<ValidationErrorEntry>): ValidationErrorEntry => ({
  code: 'X',
  severity: 'error',
  stage: 'semantic',
  path: '',
  message: 'm',
  remediation: 'r',
  spec_reference: null,
  ...overrides,
});

describe('stageLabel / stageNumber', () => {
  it('maps known stages to canonical labels and numbers', () => {
    expect(stageLabel('semantic')).toBe('Semantic');
    expect(stageNumber('semantic')).toBe(4);
    expect(stageLabel('ntia')).toBe('NTIA minimum elements');
    expect(stageNumber('ntia')).toBe(7);
  });

  it('falls back gracefully for unknown stages', () => {
    expect(stageLabel('made-up')).toBe('made-up');
    expect(stageNumber('made-up')).toBe(0);
    expect(stageLabel(null)).toBe('Unknown stage');
    expect(stageNumber(null)).toBe(0);
  });
});

describe('groupEntriesByStage', () => {
  it('preserves stage encounter order and orders by severity within a stage', () => {
    const entries = [
      e({ stage: 'semantic', severity: 'warning', code: 'A' }),
      e({ stage: 'ntia', severity: 'warning', code: 'N1' }),
      e({ stage: 'semantic', severity: 'error', code: 'B' }),
      e({ stage: 'semantic', severity: 'info', code: 'C' }),
    ];
    const result = groupEntriesByStage(entries);
    expect(result.map((g) => g.stage)).toEqual(['semantic', 'ntia']);
    const semantic = result[0]!;
    expect(semantic.entries.map((x) => x.code)).toEqual(['B', 'A', 'C']);
  });
});

describe('validationStatusMeta', () => {
  it('shows the warnings variant when validated with warnings', () => {
    expect(validationStatusMeta('validated', 2).label).toMatch(/warnings/);
    expect(validationStatusMeta('validated', 0).label).toBe('Validated');
  });

  it('failed and quarantined are visually distinct', () => {
    expect(validationStatusMeta('failed', 0).classes).not.toBe(
      validationStatusMeta('quarantined', 0).classes,
    );
  });
});

describe('severityChipClasses', () => {
  it('returns distinct class strings per severity', () => {
    const set = new Set([
      severityChipClasses('error'),
      severityChipClasses('warning'),
      severityChipClasses('info'),
    ]);
    expect(set.size).toBe(3);
  });
});

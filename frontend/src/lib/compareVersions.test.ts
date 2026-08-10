import { describe, expect, it } from 'vitest';
import { compareVersions } from './compareVersions';

describe('compareVersions', () => {
  it('detects forward upgrades that disagree with string compare', () => {
    expect(compareVersions('1.10.0', '1.9.0')).toBe(1);
    expect(compareVersions('2.10.3', '2.9.99')).toBe(1);
  });

  it('returns 0 for identical versions', () => {
    expect(compareVersions('1.2.3', '1.2.3')).toBe(0);
    expect(compareVersions('', '')).toBe(0);
  });

  it('returns -1 for downgrades', () => {
    expect(compareVersions('1.9.0', '1.10.0')).toBe(-1);
    expect(compareVersions('1.0.0', '1.0.1')).toBe(-1);
  });

  it('treats shorter prefix-equal version as older', () => {
    expect(compareVersions('1.2', '1.2.0')).toBe(-1);
    expect(compareVersions('1.2.1', '1.2')).toBe(1);
  });

  it('falls back to lexicographic compare for non-numeric segments', () => {
    expect(compareVersions('1.0.0-rc1', '1.0.0-rc2')).toBe(-1);
    expect(compareVersions('1.0.0-rc2', '1.0.0-rc1')).toBe(1);
  });
});

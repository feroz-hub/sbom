import { describe, expect, it } from 'vitest';
import { cveQueryKey } from './queryKey';

describe('cveQueryKey', () => {
  it('partitions by scan id when present', () => {
    expect(cveQueryKey(42, 'CVE-2024-12345')).toEqual(['cve', 42, 'CVE-2024-12345']);
  });

  it('falls back to the global bucket when scan id is null/undefined', () => {
    expect(cveQueryKey(null, 'CVE-2024-12345')).toEqual(['cve', 'global', 'CVE-2024-12345']);
    expect(cveQueryKey(undefined, 'CVE-2024-12345')).toEqual(['cve', 'global', 'CVE-2024-12345']);
  });

  it('canonicalises CVE id (uppercase + trim)', () => {
    expect(cveQueryKey(1, '  cve-2024-99999  ')).toEqual(['cve', 1, 'CVE-2024-99999']);
  });

  it('does not collapse different scans into the same key', () => {
    const a = cveQueryKey(1, 'CVE-2024-1');
    const b = cveQueryKey(2, 'CVE-2024-1');
    const global = cveQueryKey(null, 'CVE-2024-1');
    expect(a).not.toEqual(b);
    expect(a).not.toEqual(global);
  });
});

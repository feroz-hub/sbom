import { describe, expect, it } from 'vitest';
import { cveQueryKey } from './queryKey';

describe('cveQueryKey', () => {
  it('partitions by scan id when present', () => {
    expect(cveQueryKey("00000000-0000-4000-8000-00000000002a", 'CVE-2024-12345')).toEqual(['cve', '00000000-0000-4000-8000-00000000002a', 'CVE-2024-12345']);
  });

  it('falls back to the global bucket when scan id is null/undefined', () => {
    expect(cveQueryKey(null, 'CVE-2024-12345')).toEqual(['cve', 'global', 'CVE-2024-12345']);
    expect(cveQueryKey(undefined, 'CVE-2024-12345')).toEqual(['cve', 'global', 'CVE-2024-12345']);
  });

  it('canonicalises CVE id (uppercase + trim)', () => {
    expect(cveQueryKey("00000000-0000-4000-8000-000000000001", '  cve-2024-99999  ')).toEqual(['cve', '00000000-0000-4000-8000-000000000001', 'CVE-2024-99999']);
  });

  it('does not collapse different scans into the same key', () => {
    const a = cveQueryKey("00000000-0000-4000-8000-000000000001", 'CVE-2024-1');
    const b = cveQueryKey("00000000-0000-4000-8000-000000000002", 'CVE-2024-1');
    const global = cveQueryKey(null, 'CVE-2024-1');
    expect(a).not.toEqual(b);
    expect(a).not.toEqual(global);
  });
});

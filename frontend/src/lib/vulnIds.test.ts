import { describe, expect, it } from 'vitest';
import { classifyVulnId, SUPPORTED_VULN_FORMATS } from './vulnIds';

describe('classifyVulnId — parity with backend identifier classifier', () => {
  // Mirrors the parametrize block in tests/test_cve_identifiers.py. When
  // the backend regex changes, update both files in lockstep — the parity
  // failure here is the canary.
  it.each([
    // CVE — uppercased.
    ['CVE-2021-44228', 'cve', 'CVE-2021-44228'],
    ['cve-2021-44228', 'cve', 'CVE-2021-44228'],
    ['CVE-2024-12345', 'cve', 'CVE-2024-12345'],
    ['Cve-2024-1', 'unknown', 'Cve-2024-1'], // too short — must NOT match CVE
    // GHSA — head upper, body lower.
    ['GHSA-jfh8-c2jp-5v3q', 'ghsa', 'GHSA-jfh8-c2jp-5v3q'],
    ['ghsa-JFH8-C2JP-5V3Q', 'ghsa', 'GHSA-jfh8-c2jp-5v3q'],
    ['GHSA-JFH8-C2JP-5V3Q', 'ghsa', 'GHSA-jfh8-c2jp-5v3q'],
    // PYSEC.
    ['PYSEC-2024-1', 'pysec', 'PYSEC-2024-1'],
    ['pysec-2024-99999', 'pysec', 'PYSEC-2024-99999'],
    // RUSTSEC.
    ['RUSTSEC-2023-0044', 'rustsec', 'RUSTSEC-2023-0044'],
    // GO.
    ['GO-2023-1234', 'go', 'GO-2023-1234'],
    // Whitespace tolerated at the edges.
    ['  CVE-2024-12345  ', 'cve', 'CVE-2024-12345'],
    // Garbage.
    ['FOOBAR-123', 'unknown', 'FOOBAR-123'],
    ['GHSA-too-short', 'unknown', 'GHSA-too-short'],
    ['GHSA-1234-5678', 'unknown', 'GHSA-1234-5678'],
    ['', 'unknown', ''],
    ['   ', 'unknown', ''],
  ])('classify(%j) → kind=%s, normalized=%s', (raw, kind, normalized) => {
    const v = classifyVulnId(raw);
    expect(v.kind).toBe(kind);
    expect(v.normalized).toBe(normalized);
  });

  it('SUPPORTED_VULN_FORMATS is non-empty and includes both CVE and GHSA', () => {
    // The banner uses this list as the authoritative copy. Empty would
    // ship the wrong message; missing CVE/GHSA would mislead the user.
    expect(SUPPORTED_VULN_FORMATS.length).toBeGreaterThan(0);
    expect(SUPPORTED_VULN_FORMATS.some((f) => f.startsWith('CVE'))).toBe(true);
    expect(SUPPORTED_VULN_FORMATS.some((f) => f.startsWith('GHSA'))).toBe(true);
  });
});

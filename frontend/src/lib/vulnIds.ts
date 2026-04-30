/**
 * Frontend mirror of ``app/integrations/cve/identifiers.py``.
 *
 * Lets the table short-circuit malformed IDs into the modal's
 * ``unrecognized`` state without burning a network round-trip. The backend
 * remains the single source of truth — this file is a hand-translation
 * kept in sync via the parity test in ``vulnIds.test.ts``.
 */

export type VulnIdKind = 'cve' | 'ghsa' | 'pysec' | 'rustsec' | 'go' | 'unknown';

export interface VulnId {
  raw: string;
  normalized: string;
  kind: VulnIdKind;
}

/**
 * Stable user-facing list of supported formats. Kept here (and in the
 * Python ``SUPPORTED_FORMATS`` tuple) as the source of truth for the
 * banner copy and the Phase-2 unrecognised-id error envelope.
 */
export const SUPPORTED_VULN_FORMATS = [
  'CVE-YYYY-NNNN',
  'GHSA-xxxx-xxxx-xxxx',
  'PYSEC-YYYY-N',
  'RUSTSEC-YYYY-NNNN',
  'GO-YYYY-NNNN',
] as const;

const PATTERNS: ReadonlyArray<readonly [VulnIdKind, RegExp]> = [
  ['cve', /^CVE-\d{4}-\d{4,7}$/i],
  ['ghsa', /^GHSA-[a-z0-9]{4}-[a-z0-9]{4}-[a-z0-9]{4}$/i],
  ['pysec', /^PYSEC-\d{4}-\d+$/i],
  ['rustsec', /^RUSTSEC-\d{4}-\d{4}$/i],
  ['go', /^GO-\d{4}-\d{4,}$/i],
];

export function classifyVulnId(raw: string): VulnId {
  if (typeof raw !== 'string') {
    return { raw: String(raw), normalized: String(raw), kind: 'unknown' };
  }
  const s = raw.trim();
  if (!s) return { raw, normalized: '', kind: 'unknown' };
  for (const [kind, pat] of PATTERNS) {
    if (pat.test(s)) {
      return { raw, normalized: canonicalize(s, kind), kind };
    }
  }
  return { raw, normalized: s, kind: 'unknown' };
}

function canonicalize(s: string, kind: VulnIdKind): string {
  if (kind === 'cve') return s.toUpperCase();
  if (kind === 'ghsa') {
    const parts = s.split('-');
    const [head, ...rest] = parts;
    return [head.toUpperCase(), ...rest.map((seg) => seg.toLowerCase())].join('-');
  }
  // pysec / rustsec / go: prefix uppercased; numeric tail unaffected.
  return s.toUpperCase();
}

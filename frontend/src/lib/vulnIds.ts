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

/**
 * A source-specific advisory alias that wraps a canonical CVE, e.g. the
 * Debian Security Tracker's ``DEBIAN-CVE-2011-3374`` (also ``UBUNTU-CVE-…``).
 * Mirror of ``_SOURCE_PREFIXED_CVE`` in the backend classifier — kept in sync
 * by the parity test. ``resolveVulnId`` strips the prefix to the embedded CVE.
 */
const SOURCE_PREFIXED_CVE = /^[A-Za-z][A-Za-z0-9]*-(CVE-\d{4}-\d{4,7})$/i;

/**
 * Output of {@link resolveVulnId}: the canonical id every consumer keys on
 * (fetch, cache, upstream lookup) plus the original id preserved for display.
 */
export interface ResolvedVulnId {
  /** Original input, preserved for display / provenance. */
  raw: string;
  /** Canonical id for lookup + cache key; `''` when unsupported. */
  canonical: string;
  kind: VulnIdKind;
  /** `false` → render the "unrecognized" banner (no fetch). */
  supported: boolean;
}

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

/** First alias that classifies as a supported kind, preferring CVE. */
function firstSupportedAlias(aliases: readonly string[]): VulnId | null {
  let fallback: VulnId | null = null;
  for (const alias of aliases) {
    const v = classifyVulnId(alias);
    if (v.kind === 'cve') return v;
    if (v.kind !== 'unknown' && fallback === null) fallback = v;
  }
  return fallback;
}

/**
 * Resolve a raw vulnerability id to the canonical id every consumer keys on.
 *
 * Mirror of ``resolve`` in ``app/integrations/cve/identifiers.py``. Where
 * {@link classifyVulnId} is pure format detection, this also maps a
 * source-specific advisory alias to its canonical CVE so the modal fetch, the
 * TanStack cache key and the backend lookup all agree. Precedence:
 *
 *   1. an explicit `canonicalId` when itself supported;
 *   2. `rawId` when already a supported canonical id (CVE / GHSA / PYSEC /
 *      RUSTSEC / GO — preserved unchanged);
 *   3. a supported id in `aliases` (preferring CVE) — reuses the CVE the
 *      dedup/merge step already stored, not just string surgery;
 *   4. a CVE embedded in a source prefix (`DEBIAN-CVE-… → CVE-…`);
 *   5. otherwise an unsupported result (never throws).
 *
 * `raw` is always preserved for display/provenance.
 */
export function resolveVulnId(
  rawId: string | null | undefined,
  opts?: { aliases?: readonly string[] | null; canonicalId?: string | null },
): ResolvedVulnId {
  const raw = typeof rawId === 'string' ? rawId : rawId == null ? '' : String(rawId);
  const aliases = opts?.aliases ?? [];
  const canonicalId = opts?.canonicalId ?? null;

  // 1. Explicit canonical id wins when provided and valid.
  if (canonicalId) {
    const cv = classifyVulnId(canonicalId);
    if (cv.kind !== 'unknown') {
      return { raw, canonical: cv.normalized, kind: cv.kind, supported: true };
    }
  }

  // 2. rawId is already a supported canonical id — keep it as-is.
  const direct = classifyVulnId(raw);
  if (direct.kind !== 'unknown') {
    return { raw, canonical: direct.normalized, kind: direct.kind, supported: true };
  }

  // 3. Reuse a CVE (or other supported id) already merged into aliases.
  const aliasHit = firstSupportedAlias(aliases);
  if (aliasHit) {
    return { raw, canonical: aliasHit.normalized, kind: aliasHit.kind, supported: true };
  }

  // 4. Strip a source prefix wrapping a canonical CVE.
  const m = raw.trim().match(SOURCE_PREFIXED_CVE);
  if (m) {
    return { raw, canonical: m[1].toUpperCase(), kind: 'cve', supported: true };
  }

  // 5. Controlled unsupported result.
  return { raw, canonical: '', kind: 'unknown', supported: false };
}

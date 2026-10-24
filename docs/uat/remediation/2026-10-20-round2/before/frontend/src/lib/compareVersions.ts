/**
 * Best-effort numeric-segment version comparator for the compare UI's
 * version-bump arrow. Splits on `.`, compares numerically segment-by-segment.
 * Falls back to lexicographic compare when both sides have non-numeric tail
 * tokens that don't parse cleanly.
 *
 * Deliberately NOT a full semver / PEP 440 / Maven comparator — the only
 * caller is a directional arrow, so misclassifying an exotic version pair as
 * "down" instead of "up" is a visual annoyance, not a correctness bug.
 */

export type VersionDirection = -1 | 0 | 1;

const NUMERIC_SEGMENT = /^\d+$/;

export function compareVersions(a: string, b: string): VersionDirection {
  if (a === b) return 0;
  const segA = a.split('.');
  const segB = b.split('.');
  const len = Math.max(segA.length, segB.length);
  for (let i = 0; i < len; i += 1) {
    const ra = segA[i];
    const rb = segB[i];
    if (ra === rb) continue;
    if (ra === undefined) return -1; // shorter side is older when prefixes match
    if (rb === undefined) return 1;
    if (NUMERIC_SEGMENT.test(ra) && NUMERIC_SEGMENT.test(rb)) {
      const na = Number(ra);
      const nb = Number(rb);
      if (na !== nb) return na < nb ? -1 : 1;
      continue;
    }
    // Non-numeric segment on either side — fall back to lexicographic for
    // this segment (e.g. "1.0.0-rc1" vs "1.0.0-rc2") and stop.
    return ra < rb ? -1 : 1;
  }
  return 0;
}

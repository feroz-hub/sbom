/**
 * Stable TanStack Query key for the CVE detail modal.
 *
 * Lives in its own module so unit tests can import it without dragging the
 * API client (which throws at module-init time when ``NEXT_PUBLIC_API_URL``
 * is unset, e.g. inside vitest).
 *
 * Partitioning rule: scan-aware queries are bucketed by ``scanId`` so the
 * scan-context payload doesn't bleed across runs; the global bucket is the
 * fallback for plain ``GET /api/v1/cves/{id}`` calls.
 */
export function cveQueryKey(
  scanId: number | null | undefined,
  cveId: string,
): readonly ['cve', number | 'global', string] {
  return ['cve', scanId ?? 'global', cveId.trim().toUpperCase()] as const;
}

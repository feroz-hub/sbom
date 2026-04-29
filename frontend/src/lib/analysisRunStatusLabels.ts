/**
 * Display copy for analysis run / SBOM scan outcomes.
 *
 * ADR-0001 renamed the run-status enum:
 *   PASS -> OK
 *   FAIL -> FINDINGS  (a successful scan that produced security findings —
 *                       NOT a pipeline failure; should NOT paint red).
 *
 * Both legacy values (PASS / FAIL) are still accepted here for one
 * deprecation cycle so any cached payloads or stale frontends still render.
 *
 * The display tone for FINDINGS is amber, not red, to break the visual
 * conflation with ERROR (which is the only "real" failure).
 */

/** Short label shown in badges and dropdowns */
export const runStatusShortLabel = (code: string | null | undefined): string => {
  const k = (code ?? '').toUpperCase();
  switch (k) {
    case 'OK':
    case 'PASS':
      return 'No issues';
    case 'FINDINGS':
    case 'FAIL':
      return 'Vulnerabilities found';
    case 'PARTIAL':
      return 'Source errors';
    case 'ERROR':
      return 'Run error';
    case 'RUNNING':
      return 'Running';
    case 'PENDING':
      return 'Pending';
    case 'NO_DATA':
      return 'No SBOM data';
    default:
      return code || 'Unknown';
  }
};

/** Explains what the status means (tooltips, aria-label, help text) */
export const runStatusDescription = (code: string | null | undefined): string => {
  const k = (code ?? '').toUpperCase();
  switch (k) {
    case 'OK':
    case 'PASS':
      return 'The scan finished successfully and reported no vulnerabilities.';
    case 'FINDINGS':
    case 'FAIL':
      return 'The scan finished successfully and reported one or more vulnerabilities. This is not a system or pipeline failure.';
    case 'PARTIAL':
      return 'The scan finished but some vulnerability lookups failed (e.g. API errors). Fewer findings than expected may be shown.';
    case 'ERROR':
      return 'The analysis run failed with an error. Check the run details for a message.';
    case 'RUNNING':
      return 'Analysis is still in progress.';
    case 'PENDING':
      return 'The run is queued or not started yet.';
    case 'NO_DATA':
      return 'There was no SBOM content to analyze.';
    default:
      return `Status code: ${code || 'unknown'}`;
  }
};

/** SBOM list "analysis" column (same codes as runs, plus workflow states) */
export const sbomAnalysisShortLabel = (code: string | null | undefined): string => {
  const k = (code ?? '').toUpperCase();
  switch (k) {
    case 'ANALYSING':
      return 'Scanning…';
    case 'OK':
    case 'PASS':
      return 'No issues';
    case 'FINDINGS':
    case 'FAIL':
      return 'Vulnerabilities found';
    case 'PARTIAL':
      return 'Source errors';
    case 'ERROR':
      return 'Scan error';
    case 'NOT_ANALYSED':
      return 'Not scanned';
    default:
      return runStatusShortLabel(code);
  }
};

export const sbomAnalysisDescription = (code: string | null | undefined): string => {
  const k = (code ?? '').toUpperCase();
  if (k === 'ANALYSING') return 'Vulnerability scan is in progress.';
  if (k === 'NOT_ANALYSED') return 'This SBOM has not been analysed yet.';
  if (k === 'ERROR') return 'The scan ended with an error. Check notifications or run details.';
  return runStatusDescription(code);
};

/**
 * Map a status code to its canonical-name equivalent. PASS → OK, FAIL →
 * FINDINGS; anything else (including unknown codes) is returned uppercase.
 * Use this when comparing or filtering — never hard-code 'FAIL' / 'PASS'.
 */
export function canonicalRunStatus(code: string | null | undefined): string {
  const k = (code ?? '').toUpperCase();
  if (k === 'PASS') return 'OK';
  if (k === 'FAIL') return 'FINDINGS';
  return k;
}

/**
 * Local type re-exports + the EnrichedFinding subset we use to seed the
 * modal header on first paint (so the user sees something useful before
 * the enrichment fetch resolves).
 */

export type {
  CveDetail,
  CveDetailWithContext,
  CveExploitation,
  CveFixVersion,
  CveReference,
  CveScanContext,
  CveSeverity,
  CveSourceName,
} from '@/types';

import type { EnrichedFinding } from '@/types';

/**
 * The minimum the row already knows about a CVE — used to render the
 * header instantly while the modal fetches the rest.
 */
export type CveRowSeed = Pick<
  EnrichedFinding,
  | 'vuln_id'
  | 'severity'
  | 'score'
  | 'cvss_version'
  | 'in_kev'
  | 'epss'
  | 'epss_percentile'
  | 'component_name'
  | 'component_version'
  | 'source'
> & {
  /**
   * CVE aliases discovered on the row (`vuln_id` + parsed aliases). Lets the
   * modal resolve a source-specific advisory id (e.g. `DEBIAN-CVE-2011-3374`)
   * to its canonical CVE for lookup while the original id stays on screen.
   * Optional so callers that don't have it (older seeds, tests) still type-check.
   */
  cve_aliases?: readonly string[] | null;
};

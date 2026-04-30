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
>;

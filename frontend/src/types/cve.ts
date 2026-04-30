/**
 * TypeScript mirrors of the backend CVE detail payload
 * (see app/schemas_cve.py — CveDetail / CveDetailWithContext).
 *
 * Every field is intentionally typed end-to-end to satisfy the project's
 * "no `any`" rule. When the backend schema changes, update this file.
 */

export type CveSeverity =
  | 'critical'
  | 'high'
  | 'medium'
  | 'low'
  | 'none'
  | 'unknown';

export type CveSourceName = 'osv' | 'ghsa' | 'nvd' | 'epss' | 'kev';

/**
 * Outcome discriminator the dialog reads to pick its banner. Mirrors
 * ``app.schemas_cve.CveResultStatus``. The HTTP response is always 200
 * for these — they describe how rich the payload is, not whether the
 * request was malformed (that's the 400 envelope below).
 */
export type CveResultStatus = 'ok' | 'partial' | 'not_found' | 'unreachable';

/**
 * 400 envelope returned when the server can't classify the advisory id.
 * Mirrors ``app/routers/cves.py::_unrecognized_response``. The
 * ``error_code`` is the stable contract the frontend branches on; the
 * human ``message`` is for telemetry, not the user-facing copy.
 */
export interface CveUnrecognizedIdEnvelope {
  error_code: 'CVE_VAL_E001_UNRECOGNIZED_ID';
  message: string;
  raw_id: string;
  supported_formats: string[];
  retryable: false;
}

export type CveReferenceType =
  | 'advisory'
  | 'patch'
  | 'exploit'
  | 'report'
  | 'fix'
  | 'web';

export interface CveFixVersion {
  ecosystem: string;
  package: string;
  fixed_in: string | null;
  introduced_in: string | null;
  range: string | null;
}

export interface CveReference {
  label: string;
  url: string;
  type: CveReferenceType;
}

export interface CveExploitation {
  epss_score: number | null;
  epss_percentile: number | null;
  cisa_kev_listed: boolean;
  cisa_kev_due_date: string | null; // YYYY-MM-DD
  attack_vector: string | null;
  attack_complexity: string | null;
  privileges_required: string | null;
  user_interaction: string | null;
  impact_summary: string | null;
}

export interface CveDetail {
  cve_id: string;
  aliases: string[];
  title: string | null;
  summary: string;
  severity: CveSeverity;
  cvss_v3_score: number | null;
  cvss_v3_vector: string | null;
  cvss_v4_score: number | null;
  cvss_v4_vector: string | null;
  cwe_ids: string[];
  published_at: string | null;
  modified_at: string | null;
  exploitation: CveExploitation;
  fix_versions: CveFixVersion[];
  workaround: string | null;
  references: CveReference[];
  sources_used: CveSourceName[];
  is_partial: boolean;
  status: CveResultStatus;
  fetched_at: string;
}

export interface CveScanContext {
  name: string;
  version: string | null;
  ecosystem: string | null;
  purl: string | null;
}

export type CveCurrentVersionStatus = 'vulnerable' | 'fixed' | 'unknown';

export interface CveDetailWithContext extends CveDetail {
  component: CveScanContext | null;
  current_version_status: CveCurrentVersionStatus;
  recommended_upgrade: string | null;
}

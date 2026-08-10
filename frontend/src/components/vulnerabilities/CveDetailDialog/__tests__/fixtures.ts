/**
 * Shared test fixtures for the CVE detail modal component suite.
 *
 * Two flavours: a fully-populated payload to exercise the happy path and
 * a partial payload (sources_used = [osv], is_partial = true) to exercise
 * the partial-data UI cues. The seed mirrors the row data the modal opens
 * with — the part the user sees in <16 ms.
 */

import type {
  CveDetail,
  CveDetailWithContext,
  CveRowSeed,
} from '../types';

export const SEED: CveRowSeed = {
  vuln_id: 'CVE-2099-9001',
  severity: 'CRITICAL',
  score: 9.8,
  cvss_version: '3.1',
  in_kev: true,
  epss: 0.42,
  epss_percentile: 0.91,
  component_name: 'left-pad',
  component_version: '1.2.0',
  source: 'OSV',
};

export const FULL_DETAIL: CveDetail = {
  cve_id: 'CVE-2099-9001',
  aliases: ['GHSA-fake-osv', 'CVE-2099-9001'],
  title: 'Remote code execution in left-pad',
  summary: 'A long-form description of the vulnerability.',
  severity: 'critical',
  cvss_v3_score: 9.8,
  cvss_v3_vector: 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H',
  cvss_v4_score: 9.3,
  cvss_v4_vector: 'CVSS:4.0/AV:N/AC:L',
  cwe_ids: ['CWE-79', 'CWE-89'],
  published_at: '2024-01-15T00:00:00Z',
  modified_at: '2024-01-22T00:00:00Z',
  exploitation: {
    epss_score: 0.42,
    epss_percentile: 0.91,
    cisa_kev_listed: true,
    cisa_kev_due_date: '2024-02-15',
    attack_vector: 'NETWORK',
    attack_complexity: 'LOW',
    privileges_required: 'NONE',
    user_interaction: 'NONE',
    impact_summary: 'Full remote code execution; no user interaction.',
  },
  fix_versions: [
    {
      ecosystem: 'npm',
      package: 'left-pad',
      fixed_in: '1.3.1',
      introduced_in: '0.0.1',
      range: null,
    },
    {
      ecosystem: 'npm',
      package: 'left-pad',
      fixed_in: '2.0.0',
      introduced_in: null,
      range: null,
    },
  ],
  workaround: null,
  references: [
    { label: 'GHSA', url: 'https://github.com/advisories/GHSA-fake-osv', type: 'advisory' },
    { label: 'NVD', url: 'https://nvd.nist.gov/vuln/detail/CVE-2099-9001', type: 'advisory' },
    { label: 'NVD', url: 'https://example.com/patch', type: 'patch' },
  ],
  sources_used: ['osv', 'ghsa', 'nvd', 'epss', 'kev'],
  is_partial: false,
  status: 'ok',
  fetched_at: '2026-04-30T12:00:00Z',
};

export const PARTIAL_DETAIL: CveDetail = {
  ...FULL_DETAIL,
  is_partial: true,
  status: 'partial',
  sources_used: ['osv'],
  cvss_v3_score: null,
  cvss_v4_score: null,
  cwe_ids: [],
  exploitation: {
    ...FULL_DETAIL.exploitation,
    cisa_kev_listed: false,
    cisa_kev_due_date: null,
    attack_vector: null,
    attack_complexity: null,
    privileges_required: null,
    user_interaction: null,
    impact_summary: null,
  },
};

export const NO_FIX_DETAIL: CveDetail = {
  ...FULL_DETAIL,
  fix_versions: [],
};

export const NOT_FOUND_DETAIL: CveDetail = {
  ...FULL_DETAIL,
  status: 'not_found',
  is_partial: false,
  sources_used: [],
  summary: '',
  cvss_v3_score: null,
  cvss_v4_score: null,
  cwe_ids: [],
  fix_versions: [],
  references: [],
};

export const UNREACHABLE_DETAIL: CveDetail = {
  ...NOT_FOUND_DETAIL,
  status: 'unreachable',
};

export const SCAN_DETAIL: CveDetailWithContext = {
  ...FULL_DETAIL,
  component: {
    name: 'left-pad',
    version: '1.2.0',
    ecosystem: 'npm',
    purl: 'pkg:npm/left-pad@1.2.0',
  },
  current_version_status: 'vulnerable',
  recommended_upgrade: '1.3.1',
};

/**
 * Explicit empty and degraded states (spec Step 9, NFR-SCA-008).
 *
 * The advisor never fabricates a recommendation when evidence is missing; it
 * says so. Each state renders as a polite live region with a text title, so
 * screen readers announce it and nothing relies on colour.
 */

import type { ReactNode } from 'react';
import { Alert } from '@/components/ui/Alert';

export type AdvisorNoticeKind =
  | 'NO_MATCHING_COMPONENTS'
  | 'NO_CANDIDATES_FOUND'
  | 'INSUFFICIENT_PURPOSE_EVIDENCE'
  | 'INSUFFICIENT_COMPATIBILITY_EVIDENCE'
  | 'LIFECYCLE_EVIDENCE_UNAVAILABLE'
  | 'STALE_VULNERABILITY_DATA'
  | 'EXTERNAL_SOURCE_UNAVAILABLE'
  | 'NO_ACTIVE_SBOM_OCCURRENCES'
  | 'RECOMMENDATION_ALREADY_OPEN'
  | 'UNAUTHORIZED_SCOPE'
  | 'POLICY_NOT_CONFIGURED';

const NOTICES: Record<AdvisorNoticeKind, { title: string; description: string; variant: 'info' | 'warning' | 'error' }> = {
  NO_MATCHING_COMPONENTS: {
    title: 'No matching components',
    description: 'No component version in this scope matches the selected filters or search.',
    variant: 'info',
  },
  NO_CANDIDATES_FOUND: {
    title: 'No candidates found',
    description: 'No safer version or suitable alternative could be established from the available evidence.',
    variant: 'info',
  },
  INSUFFICIENT_PURPOSE_EVIDENCE: {
    title: 'Insufficient purpose evidence',
    description: 'There is no evidenced functional purpose or category, so purpose search and alternatives are unavailable. Purpose is never guessed from a name.',
    variant: 'info',
  },
  INSUFFICIENT_COMPATIBILITY_EVIDENCE: {
    title: 'Insufficient compatibility evidence',
    description: 'Some compatibility checks could not be evaluated. This candidate cannot be treated as a drop-in replacement.',
    variant: 'warning',
  },
  LIFECYCLE_EVIDENCE_UNAVAILABLE: {
    title: 'Lifecycle evidence unavailable',
    description: 'No lifecycle status is recorded for this version.',
    variant: 'info',
  },
  STALE_VULNERABILITY_DATA: {
    title: 'Stale evidence',
    description: 'Some analysis or lifecycle evidence is older than the freshness threshold or unavailable. Confidence is reduced.',
    variant: 'warning',
  },
  EXTERNAL_SOURCE_UNAVAILABLE: {
    title: 'External data source unavailable',
    description: 'An external package-metadata source failed. Results are based on tenant evidence only.',
    variant: 'warning',
  },
  NO_ACTIVE_SBOM_OCCURRENCES: {
    title: 'No active SBOM occurrences',
    description: 'There are no active, analysed SBOMs in this scope yet.',
    variant: 'info',
  },
  RECOMMENDATION_ALREADY_OPEN: {
    title: 'Recommendation already open',
    description: 'An open recommendation already exists for this component; it was not duplicated.',
    variant: 'info',
  },
  UNAUTHORIZED_SCOPE: {
    title: 'Scope not available',
    description: 'This project, application, SBOM or item is not available to you.',
    variant: 'error',
  },
  POLICY_NOT_CONFIGURED: {
    title: 'Policy not configured',
    description: 'No accepted-risk or trust policy is configured for this tenant.',
    variant: 'info',
  },
};

export function AdvisorNotice({ kind, children }: { kind: AdvisorNoticeKind; children?: ReactNode }) {
  const notice = NOTICES[kind];
  return (
    // Alert supplies the live region (role="status", or "alert" for errors).
    <div data-notice={kind}>
      <Alert variant={notice.variant} title={notice.title}>
        {notice.description}
        {children ? <div className="mt-2">{children}</div> : null}
      </Alert>
    </div>
  );
}

export const ADVISOR_NOTICE_KINDS = Object.keys(NOTICES) as AdvisorNoticeKind[];

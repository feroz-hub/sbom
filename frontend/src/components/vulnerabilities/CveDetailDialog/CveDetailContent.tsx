'use client';

import { AiFixSection } from '@/components/ai-fixes/AiFixSection';
import { CveExploitSection } from './CveExploitSection';
import { CveFixSection } from './CveFixSection';
import { CveWhatSection } from './CveWhatSection';
import type { CveDetail, CveDetailWithContext, CveRowSeed } from './types';

interface CveDetailContentProps {
  seed: CveRowSeed;
  detail: CveDetail | CveDetailWithContext;
  scanName?: string | null;
  describedById?: string;
  /** When provided, the AI remediation section renders for this finding. */
  findingId?: number | null;
  aiFixesEnabled?: boolean;
  aiProviderLabel?: string;
}

/**
 * Composes the three body sections plus the optional AI remediation.
 *
 * Lazy-loaded by the parent dialog (``next/dynamic``) so the dialog
 * *shell* (header + skeleton + close) ships in the main bundle and this
 * body lazy-loads on first open. References live in the parent dialog's
 * sticky ``footer`` slot — they are not part of the scrollable body.
 *
 * The AI remediation section is rendered last (so the deterministic CVE
 * data sits above the LLM-generated content) and only when both the
 * feature flag is on AND a ``findingId`` is supplied. Without a
 * findingId there is no scan-aware finding to ground the request.
 */
export default function CveDetailContent({
  seed,
  detail,
  scanName,
  describedById,
  findingId,
  aiFixesEnabled = false,
  aiProviderLabel,
}: CveDetailContentProps) {
  return (
    <div>
      <CveWhatSection seed={seed} detail={detail} scanName={scanName} describedById={describedById} />
      <CveExploitSection detail={detail} />
      <CveFixSection detail={detail} />
      {aiFixesEnabled && findingId != null ? (
        <AiFixSection findingId={findingId} providerLabel={aiProviderLabel} />
      ) : null}
    </div>
  );
}

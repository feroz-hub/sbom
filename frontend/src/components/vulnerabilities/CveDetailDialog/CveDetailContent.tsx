'use client';

import { CveExploitSection } from './CveExploitSection';
import { CveFixSection } from './CveFixSection';
import { CveWhatSection } from './CveWhatSection';
import type { CveDetail, CveDetailWithContext, CveRowSeed } from './types';

interface CveDetailContentProps {
  seed: CveRowSeed;
  detail: CveDetail | CveDetailWithContext;
  scanName?: string | null;
  describedById?: string;
}

/**
 * Composes the three body sections.
 *
 * Lazy-loaded by the parent dialog (``next/dynamic``) so the dialog
 * *shell* (header + skeleton + close) ships in the main bundle and this
 * body lazy-loads on first open. References live in the parent dialog's
 * sticky ``footer`` slot — they are not part of the scrollable body.
 */
export default function CveDetailContent({
  seed,
  detail,
  scanName,
  describedById,
}: CveDetailContentProps) {
  return (
    <div>
      <CveWhatSection seed={seed} detail={detail} scanName={scanName} describedById={describedById} />
      <CveExploitSection detail={detail} />
      <CveFixSection detail={detail} />
    </div>
  );
}

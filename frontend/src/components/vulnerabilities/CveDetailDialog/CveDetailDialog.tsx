'use client';

import { useEffect, useId, useMemo, useRef, useState, type ReactNode } from 'react';
import { resolveVulnId } from '@/lib/vulnIds';
import { Dialog } from '@/components/ui/Dialog';
import { CveBanner } from './CveBanner';
import CveDetailContent from './CveDetailContent';
import { CveHeader } from './CveHeader';
import { CveReferences } from './CveReferences';
import { CveSkeleton } from './CveSkeleton';
import { useCveDetail } from './hooks';
import { selectDialogState } from './states';
import type { CveDetail, CveDetailWithContext, CveRowSeed } from './types';

export interface CveDetailDialogProps {
  /**
   * The CVE the dialog is showing right now. ``null`` closes the dialog.
   * The public consumer (typically a vulnerabilities table) holds the
   * active-CVE state and switches it; the dialog itself is stateless.
   */
  cveId: string | null;
  /**
   * Analysis run id. When present, the dialog fetches the scan-aware
   * variant (``/api/v1/scans/{scanId}/cves/{cveId}``) which adds the
   * detected component context and the recommended-upgrade callout. When
   * absent, the global variant (``/api/v1/cves/{cveId}``) is used.
   */
  scanId?: number | null;
  /** Constrain scan enrichment to the selected component, never the first CVE match. */
  componentId?: number | null;
  /** Wait for the host to resolve the precise scan/component context. */
  detailsEnabled?: boolean;
  /** Optional contextual workflow, sharing this dialog's enrichment and accessibility. */
  investigationPanel?: ReactNode;
  contextPanel?: ReactNode;
  initialTab?: 'details' | 'investigation';
  /**
   * Human-friendly scan label (typically the SBOM name) shown in the
   * "Component: X via Y" component-context line of section 1.
   */
  scanName?: string | null;
  /**
   * Row data already in hand at the moment of the click. Used to paint
   * the header in <16 ms — CVE id, severity, CVSS, KEV, EPSS chips —
   * while the enriched body fetch is in flight. ``null`` when the dialog
   * is closed.
   */
  seed: CveRowSeed | null;
  /** Controlled-open flag. */
  open: boolean;
  /**
   * Called whenever the dialog wants to change open state — e.g. when
   * the user hits ESC, clicks the backdrop, or the close button. The
   * consumer is expected to clear its active-CVE state on ``false``.
   */
  onOpenChange: (open: boolean) => void;
  /**
   * Optional callback fired when the user clicks an alias chip in the
   * header. The consumer should swap its active-CVE state to the new id;
   * the dialog stays open and the query re-runs under a new key (the
   * previous query stays cached, so flipping back is instant).
   */
  onSwitchCve?: (newCveId: string) => void;
  /**
   * Optional URL the "Report this issue" link in the unrecognized /
   * fatal banners points at — typically a GitHub Issues URL or mailto.
   */
  reportIssueHref?: string;
  /**
   * Finding row id this dialog represents within the active scan. When
   * present alongside ``aiFixesEnabled``, the body renders the AI
   * remediation section (Phase 4 §4.1, Integration 1).
   */
  findingId?: number | null;
  /** Master flag for the AI remediation section. Sourced from server config. */
  aiFixesEnabled?: boolean;
  /** Provider name shown on the empty-state CTA. */
  aiProviderLabel?: string;
}

/**
 * In-app CVE detail dialog.
 *
 * Shows the merged ``CveDetail`` payload (OSV + GHSA + NVD + EPSS + KEV)
 * for a single CVE, organised into three sections:
 *   1. **What is this CVE?** — title, summary, dates, CWEs, component context
 *   2. **How is it exploited?** — attack vector grid, EPSS, KEV
 *   3. **How do I fix it?** — recommended upgrade, fix-version table,
 *      copy-to-clipboard install command (scan-aware only)
 *
 * The header paints from ``seed`` immediately so the user sees something
 * useful in <16 ms; the heavy section bodies are code-split via
 * ``next/dynamic``. The data fetch goes through TanStack Query keyed by
 * ``[scanId, cveId]`` with a 5-minute client-side staleTime backed by the
 * server-side ``cve_cache`` table — clicking the same CVE twice is a
 * sub-150 ms warm hit.
 *
 * Failure modes:
 *   - Network entirely unreachable → seed-only header + retry button.
 *   - Some sources failed (``is_partial: true``) → renders normally with
 *     a small "partial data" chip in the footer.
 *   - Invalid CVE ID → shouldn't happen post-validation; guarded upstream.
 *
 * Accessibility:
 *   - WAI-ARIA dialog pattern (``aria-modal``, ``aria-labelledby``,
 *     ``aria-describedby``, focus trap, ESC closes, backdrop closes).
 *   - All severity / KEV / EPSS chips carry text labels (not colour-only).
 *   - All interactive elements ≥ 36 px hit target.
 *
 * Usage:
 * ```tsx
 * const [active, setActive] = useState<{id: string; seed: CveRowSeed} | null>(null);
 * <CveDetailDialog
 *   cveId={active?.id ?? null}
 *   seed={active?.seed ?? null}
 *   scanId={runId}
 *   scanName={sbomName}
 *   open={active !== null}
 *   onOpenChange={(open) => { if (!open) setActive(null); }}
 * />
 * ```
 */
export function CveDetailDialog({
  cveId,
  scanId,
  componentId,
  detailsEnabled = true,
  investigationPanel,
  contextPanel,
  initialTab = 'details',
  scanName,
  seed,
  open,
  onOpenChange,
  onSwitchCve,
  reportIssueHref,
  findingId,
  aiFixesEnabled = false,
  aiProviderLabel,
}: CveDetailDialogProps) {
  const summaryId = useId();
  const [activeTab, setActiveTab] = useState(initialTab);
  const tabRefs = useRef<Array<HTMLButtonElement | null>>([]);
  const hasInvestigation = investigationPanel !== undefined;
  useEffect(() => { setActiveTab(initialTab); }, [open, cveId, initialTab]);

  // Resolve the clicked id to its canonical form for the fetch/cache key — a
  // source-specific advisory alias (e.g. DEBIAN-CVE-2011-3374) resolves to its
  // CVE (reusing the row's aliases where present) so NVD/OSV/EPSS/KEV all key
  // on one id. The original id is preserved below for display / provenance.
  const resolved = useMemo(
    () => resolveVulnId(cveId, { aliases: seed?.cve_aliases ?? null }),
    [cveId, seed?.cve_aliases],
  );
  const lookupId = resolved.supported ? resolved.canonical : null;

  const query = useCveDetail({ cveId: lookupId, scanId, componentId, enabled: open && detailsEnabled });

  const detail = query.data as CveDetail | CveDetailWithContext | undefined;

  // The user-supplied id stays as the primary surface (no silent rewrite to a
  // canonical alias) — this preserves the source-specific Debian id the user
  // clicked. Falls back to the server's canonical id, then a generic label.
  const dialogTitle = useMemo(
    () => cveId ?? detail?.cve_id ?? 'CVE detail',
    [cveId, detail?.cve_id],
  );

  const dialogState = selectDialogState({
    rawId: cveId,
    aliases: seed?.cve_aliases ?? null,
    query: { data: detail, error: query.error, isLoading: open && (!detailsEnabled || query.isLoading) },
  });

  const onRetry = () => {
    void query.refetch();
  };

  // The references panel is rendered as a sticky footer when we have a
  // payload — it surfaces "Open in upstream" links + sources used + the
  // partial-data chip. It stays visible no matter how far the user has
  // scrolled the section bodies.
  const footer = detail && (!hasInvestigation || activeTab === 'details')
    ? <CveReferences detail={detail} />
    : null;

  return (
    <Dialog
      open={open}
      onClose={() => onOpenChange(false)}
      title={dialogTitle}
      maxWidth={hasInvestigation ? "3xl" : "xl"}
      describedBy={summaryId}
      footer={footer}
    >
      {seed && dialogState.kind !== 'unrecognized' ? (
        <CveHeader
          seed={seed}
          detail={detail}
          isLoading={dialogState.kind === 'loading'}
          onSwitchCve={onSwitchCve}
        />
      ) : null}

      {contextPanel}
      {hasInvestigation ? <>
        <p id={summaryId} className="sr-only">Vulnerability details and VEX investigation for the selected SBOM and component.</p>
        <div role="tablist" aria-label="Vulnerability workflow" className="flex border-b border-border px-6">
          {(['details', 'investigation'] as const).map((tab, index) => (
            <button
              key={tab}
              ref={(element) => { tabRefs.current[index] = element; }}
              type="button"
              role="tab"
              id={`${summaryId}-${tab}-tab`}
              aria-controls={`${summaryId}-${tab}-panel`}
              aria-selected={activeTab === tab}
              tabIndex={activeTab === tab ? 0 : -1}
              className={`min-h-11 border-b-2 px-3 text-sm font-medium focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-hcl-blue ${activeTab === tab ? 'border-hcl-blue text-hcl-blue' : 'border-transparent text-hcl-muted'}`}
              onClick={() => setActiveTab(tab)}
              onKeyDown={(event) => {
                if (!['ArrowLeft', 'ArrowRight', 'Home', 'End'].includes(event.key)) return;
                event.preventDefault();
                const next = event.key === 'Home' ? 0 : event.key === 'End' ? 1 : 1 - index;
                setActiveTab(next === 0 ? 'details' : 'investigation');
                tabRefs.current[next]?.focus();
              }}
            >{tab === 'details' ? 'Vulnerability Details' : 'VEX Investigation'}</button>
          ))}
        </div>
      </> : null}
      <div
        role={hasInvestigation ? 'tabpanel' : undefined}
        id={`${summaryId}-details-panel`}
        aria-labelledby={hasInvestigation ? `${summaryId}-details-tab` : undefined}
        hidden={hasInvestigation && activeTab !== 'details'}
        tabIndex={hasInvestigation ? 0 : undefined}
        className="min-w-0 break-words"
      >
      {dialogState.kind !== 'ok' && dialogState.kind !== 'loading' ? (
        <div className="px-6 pt-3">
          <CveBanner state={dialogState} onRetry={onRetry} reportIssueHref={reportIssueHref} />
        </div>
      ) : null}

      {/* Body — render content only when we have a detail payload. The
          unrecognized state renders banner-only (no body); loading falls
          back to the skeleton. */}
      {dialogState.kind === 'loading' ? (
        <CveSkeleton />
      ) : dialogState.kind === 'unrecognized' || dialogState.kind === 'fatal' ? null : seed && detail ? (
        <CveDetailContent
          seed={seed}
          detail={detail}
          scanName={scanName}
          describedById={hasInvestigation ? undefined : summaryId}
          findingId={findingId ?? null}
          aiFixesEnabled={aiFixesEnabled}
          aiProviderLabel={aiProviderLabel}
        />
      ) : null}
      </div>
      {hasInvestigation ? <div
        role="tabpanel"
        id={`${summaryId}-investigation-panel`}
        aria-labelledby={`${summaryId}-investigation-tab`}
        hidden={activeTab !== 'investigation'}
        tabIndex={0}
        className="min-w-0 break-words px-6 py-4"
      >{investigationPanel}</div> : null}
    </Dialog>
  );
}

'use client';

import { Copy, Check } from 'lucide-react';
import { useState, useCallback } from 'react';
import { SeverityBadge } from '@/components/ui/Badge';
import { CvssMeter } from '@/components/ui/CvssMeter';
import { EpssChip } from '@/components/ui/EpssChip';
import { KevBadge } from '@/components/ui/KevBadge';
import { useToast } from '@/hooks/useToast';
import { cn } from '@/lib/utils';
import type { CveDetail, CveRowSeed } from './types';

interface CveHeaderProps {
  /** The row data we already have — drives the instant-render path. */
  seed: CveRowSeed;
  /** Enriched payload. When undefined we render only the seed. */
  detail: CveDetail | undefined;
  isLoading: boolean;
  /**
   * Optional handler — when present, alias chips become buttons. Clicking
   * one calls back with the alias's canonical id so the consumer can swap
   * active state and the dialog re-fetches under a new query key.
   */
  onSwitchCve?: (newCveId: string) => void;
}

/**
 * Header. Renders immediately from the row seed; merges in the enriched
 * payload as it arrives. CVSS chips display both v3 and v4 when present.
 * EPSS / KEV chips remain visible even when the fetch is in flight.
 */
export function CveHeader({ seed, detail, isLoading: _isLoading, onSwitchCve }: CveHeaderProps) {
  const { showToast } = useToast();
  const [copied, setCopied] = useState(false);

  const cveId = (detail?.cve_id ?? seed.vuln_id ?? '').toUpperCase();
  const severity = detail?.severity ?? (seed.severity ?? 'unknown').toLowerCase();
  const cvssV3 = detail?.cvss_v3_score ?? (seed.cvss_version?.startsWith('3') ? seed.score : null);
  const cvssV4 = detail?.cvss_v4_score ?? (seed.cvss_version?.startsWith('4') ? seed.score : null);
  const kevListed = detail?.exploitation.cisa_kev_listed ?? seed.in_kev;
  const epssScore = detail?.exploitation.epss_score ?? seed.epss;
  const epssPercentile = detail?.exploitation.epss_percentile ?? seed.epss_percentile;

  const onCopy = useCallback(async () => {
    if (!cveId || typeof navigator === 'undefined' || !navigator.clipboard) return;
    try {
      await navigator.clipboard.writeText(cveId);
      setCopied(true);
      showToast(`Copied ${cveId} to clipboard`, 'success', { duration: 2000 });
      setTimeout(() => setCopied(false), 1500);
    } catch {
      showToast('Could not copy CVE ID', 'error');
    }
  }, [cveId, showToast]);

  return (
    <div className="space-y-2 px-6 py-3 border-b border-border-subtle bg-surface-muted/40">
      <div className="flex flex-wrap items-center gap-3">
        <button
          type="button"
          onClick={onCopy}
          className={cn(
            'group inline-flex items-center gap-1.5 rounded-md border border-border-subtle bg-surface px-2.5 py-1 font-mono text-sm font-semibold text-hcl-navy',
            'min-h-[36px] hover:bg-surface-muted',
            'focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-hcl-blue/40',
          )}
          aria-label={`Copy CVE ID ${cveId} to clipboard`}
        >
          {cveId || '—'}
          {copied ? (
            <Check className="h-3.5 w-3.5 text-emerald-600" aria-hidden />
          ) : (
            <Copy className="h-3.5 w-3.5 text-hcl-muted group-hover:text-hcl-navy" aria-hidden />
          )}
        </button>

        <SeverityBadge severity={severity.toUpperCase()} />

        {kevListed ? <KevBadge /> : null}

        {cvssV3 != null ? (
          <span title="CVSS v3 base score">
            <CvssMeter score={cvssV3} version="3.1" />
          </span>
        ) : null}
        {cvssV4 != null ? (
          <span title="CVSS v4 base score">
            <CvssMeter score={cvssV4} version="4.0" />
          </span>
        ) : null}

        <EpssChip epss={epssScore ?? 0} percentile={epssPercentile ?? null} />
      </div>

      {detail && detail.aliases.length > 0 ? (
        <div className="flex flex-wrap items-center gap-1.5 text-[11px]">
          <span className="text-[10px] font-semibold uppercase tracking-wider text-hcl-muted">
            Also known as
          </span>
          {detail.aliases
            .filter((a) => a.toUpperCase() !== detail.cve_id.toUpperCase())
            .map((alias) =>
              onSwitchCve ? (
                <button
                  key={alias}
                  type="button"
                  onClick={() => onSwitchCve(alias)}
                  className="font-mono inline-flex min-h-[28px] items-center rounded border border-border-subtle bg-surface px-1.5 py-0.5 text-hcl-blue hover:bg-surface-muted hover:underline focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-hcl-blue/40"
                  aria-label={`Switch to alias ${alias}`}
                >
                  {alias}
                </button>
              ) : (
                <span
                  key={alias}
                  className="font-mono inline-flex items-center rounded border border-border-subtle bg-surface px-1.5 py-0.5 text-foreground/80"
                >
                  {alias}
                </span>
              ),
            )}
        </div>
      ) : null}

      {detail?.title ? (
        <p className="text-sm font-medium text-hcl-navy">{detail.title}</p>
      ) : null}
    </div>
  );
}

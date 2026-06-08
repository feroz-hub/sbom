'use client';

import { AlertTriangle, ShieldAlert, Wrench, Zap } from 'lucide-react';
import { cn } from '@/lib/utils';
import { HIGH_EPSS_PERCENTILE } from '@/lib/findingFilters';
import { HeroMetric } from './HeroMetric';

interface KeySignalsRowProps {
  kevCount: number;
  /** "Likely exploited" — high-EPSS count. `undefined` ⇒ tile is feature-gated
   *  OFF (the posture endpoint doesn't expose it yet; Phase 2 lights it up). */
  highEpssCount?: number;
  criticalCount: number;
  fixCount: number;
  onKevClick?: () => void;
  onEpssClick?: () => void;
  onCriticalClick?: () => void;
  onFixClick?: () => void;
}

/**
 * The hero's key-signals row — the four counts that change a triage decision,
 * ordered by how an analyst scans: exploitability first (actively-exploited
 * KEV → likely-exploited EPSS), then severity (Critical), then actionability
 * (Fix available). Replaces the v2 metric row (KEV/Fix/Net-7day/sparkline):
 * Net-7day moved to the What's-new strip, the sparkline to the trend section.
 *
 * Every tile with a non-zero count is one click to those findings (reuses the
 * dashboard drill-down). A tile only becomes a button when its count > 0 and a
 * handler is wired — no dead buttons. The EPSS tile is omitted entirely until
 * `highEpssCount` is provided, so Phase 1 ships three live tiles and the
 * fourth appears automatically when the backend aggregate lands.
 */
export function KeySignalsRow({
  kevCount,
  highEpssCount,
  criticalCount,
  fixCount,
  onKevClick,
  onEpssClick,
  onCriticalClick,
  onFixClick,
}: KeySignalsRowProps) {
  const epssVisible = highEpssCount != null;
  // Static class literals (Tailwind can't see interpolated ones).
  const colsClass = epssVisible ? 'sm:grid-cols-4' : 'sm:grid-cols-3';

  return (
    <div className={cn('grid grid-cols-2 gap-3', colsClass)}>
      <HeroMetric
        label="Known Exploited Vulnerabilities"
        icon={<ShieldAlert className="h-3.5 w-3.5" aria-hidden />}
        tone={(kevCount > 0 ? 'red' : 'neutral')}
        tooltip="Findings whose CVE is on CISA's Known Exploited Vulnerabilities (KEV) catalog — actively exploited in the wild."
        caption="Actively exploited (CISA KEV)"
        onClick={kevCount > 0 ? onKevClick : undefined}
      >
        {kevCount.toLocaleString()}
      </HeroMetric>

      {epssVisible && (
        <HeroMetric
          label="Likely exploited"
          icon={<Zap className="h-3.5 w-3.5" aria-hidden />}
          tone={(highEpssCount! > 0 ? 'red' : 'neutral')}
          tooltip={`Findings whose CVE sits at or above the ${HIGH_EPSS_PERCENTILE}th EPSS percentile — high modelled probability of exploitation.`}
          caption={`EPSS ≥ ${HIGH_EPSS_PERCENTILE}th pct`}
          onClick={highEpssCount! > 0 ? onEpssClick : undefined}
        >
          {highEpssCount!.toLocaleString()}
        </HeroMetric>
      )}

      <HeroMetric
        label="Critical"
        icon={<AlertTriangle className="h-3.5 w-3.5" aria-hidden />}
        tone={(criticalCount > 0 ? 'red' : 'neutral')}
        tooltip="Critical-severity findings in scope (latest successful run per SBOM)."
        caption="By CVSS severity"
        onClick={criticalCount > 0 ? onCriticalClick : undefined}
      >
        {criticalCount.toLocaleString()}
      </HeroMetric>

      <HeroMetric
        label="Fix available"
        icon={<Wrench className="h-3.5 w-3.5" aria-hidden />}
        tone={(fixCount > 0 ? 'sky' : 'neutral')}
        tooltip="Distinct vulnerabilities whose upstream advisory provides at least one fixed version."
        caption="Actionable now"
        onClick={fixCount > 0 ? onFixClick : undefined}
      >
        {fixCount.toLocaleString()}
      </HeroMetric>
    </div>
  );
}

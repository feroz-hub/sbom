'use client';

import { ArrowDown, ArrowUp, Minus, ShieldAlert, Wrench } from 'lucide-react';
import { HeroMetric, type HeroMetricTone } from './HeroMetric';
import { HeroMiniTrend } from './HeroMiniTrend';
import type { DashboardPosture, DashboardTrend } from '@/types';

interface HeroMetricRowProps {
  posture?: DashboardPosture;
  trend?: DashboardTrend;
}

/**
 * Four-tile metric row: KEV exposed · Fix available · Net 7-day · Mini trend.
 *
 * Replaces the v1 floating right-aligned KEV/Fix-available pills. The
 * tiles read as one row, not as decoration — same width, same height, same
 * vertical rhythm. Tones turn on only when the value is meaningful, which
 * means the row stays visually quiet on a calm posture.
 *
 * Order matches `docs/dashboard-redesign.md` §3.1 — left to right is the
 * order users tend to scan: most-urgent (KEV) → most-actionable (fix) →
 * change-this-week (net) → context (sparkline).
 */
export function HeroMetricRow({ posture, trend }: HeroMetricRowProps) {
  const kev = posture?.kev_count ?? 0;
  const fix = posture?.fix_available_count ?? 0;
  const distinct = posture?.distinct_vulnerabilities ?? 0;
  const added = posture?.net_7day_added ?? 0;
  const resolved = posture?.net_7day_resolved ?? 0;

  const kevTone: HeroMetricTone = kev > 0 ? 'red' : 'neutral';
  const fixTone: HeroMetricTone = fix > 0 ? 'sky' : 'neutral';

  // Net 7d colour: green when net negative (we're shrinking the backlog),
  // red when net positive (it's growing), neutral when zero.
  const net = added - resolved;
  const netTone: HeroMetricTone =
    net > 0 ? 'red' : net < 0 ? 'emerald' : 'neutral';

  const points = trend?.points ?? trend?.series ?? [];

  return (
    <div className="grid grid-cols-2 gap-3 sm:grid-cols-4">
      <HeroMetric
        label="KEV exposed"
        icon={<ShieldAlert className="h-3.5 w-3.5" aria-hidden />}
        tone={kevTone}
        tooltip="Distinct vulnerabilities (in scope of the latest successful run per SBOM) listed in CISA's Known Exploited Vulnerabilities catalog."
        caption="On CISA KEV"
      >
        {kev.toLocaleString()}
      </HeroMetric>

      <HeroMetric
        label="Fix available"
        icon={<Wrench className="h-3.5 w-3.5" aria-hidden />}
        tone={fixTone}
        tooltip="Distinct vulnerabilities (same scope) whose upstream advisory provides at least one fixed version."
        caption={
          distinct > 0 ? `of ${distinct.toLocaleString()} distinct` : 'Actionable now'
        }
      >
        {fix.toLocaleString()}
      </HeroMetric>

      <HeroMetric
        label="Net 7-day change"
        icon={
          net > 0 ? (
            <ArrowUp className="h-3.5 w-3.5" aria-hidden />
          ) : net < 0 ? (
            <ArrowDown className="h-3.5 w-3.5" aria-hidden />
          ) : (
            <Minus className="h-3.5 w-3.5" aria-hidden />
          )
        }
        tone={netTone}
        tooltip="Distinct vuln_ids new to scope minus those resolved out of scope, vs 7 days ago."
        caption="vs prior 7 days"
      >
        +{added.toLocaleString()}
        <span className="px-1 text-hcl-muted">/</span>
        −{resolved.toLocaleString()}
      </HeroMetric>

      <HeroMiniTrend points={points} daysLabel={trend?.days ?? 30} />
    </div>
  );
}

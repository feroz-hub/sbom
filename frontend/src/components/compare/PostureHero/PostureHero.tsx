'use client';

import dynamic from 'next/dynamic';
import { Surface, SurfaceContent } from '@/components/ui/Surface';
import type { PostureDelta, RunRelationship } from '@/types/compare';
import { HeroHeadline } from '../HeroHeadline/HeroHeadline';
import { BigNumbersColumn } from './BigNumbersColumn';
import { DistributionBarLarge } from './DistributionBarLarge';
import { PostureTile } from './PostureTile';

// Sparkline lazy-loads so it doesn't block hero LCP. The hero renders in
// <16ms; the sparkline appears 100-300ms later when /api/runs?sbom_id=…
// resolves.
const Sparkline = dynamic(
  () => import('../Sparkline/Sparkline').then((m) => m.Sparkline),
  { ssr: false, loading: () => null },
);

interface Props {
  posture: PostureDelta;
  relationship: RunRelationship | null;
  /** SBOM id for the sparkline; null when cross-SBOM (sparkline hides). */
  sharedSbomId: number | null;
  /** Run B id — the "current" data point on the sparkline. */
  currentRunId?: number;
  /** Optional sbom name used in the sparkline aria-label. */
  sharedSbomName?: string | null;
}

/**
 * Region 2 — the dominant visual element on the page.
 *
 * Layout (desktop, ≥640px):
 *   ┌─ HeroHeadline (full width) ────────────────────────────────────┐
 *   ├─ BigNumbersColumn ─┬─ DistributionBarLarge ────────────────────┤
 *   ├─ Sparkline strip (full width, lazy-loaded) ───────────────────┤
 *   └─ Three PostureTiles (3-col grid) ──────────────────────────────┘
 *
 * Layout (mobile, <640px):
 *   Stacks vertically. BigNumbersColumn flips to inline pills. Tiles
 *   stack one per row. Total height target <320px.
 */
export function PostureHero({
  posture,
  relationship,
  sharedSbomId,
  currentRunId,
  sharedSbomName,
}: Props) {
  return (
    <Surface variant="gradient" elevation={2}>
      <SurfaceContent className="space-y-4">
        <HeroHeadline posture={posture} relationship={relationship} />

        <div className="grid grid-cols-1 gap-4 sm:grid-cols-[minmax(0,30%)_minmax(0,1fr)] sm:gap-6">
          <div className="flex flex-row flex-wrap gap-3 sm:flex-col sm:gap-4">
            <BigNumbersColumn
              added={posture.findings_added_count}
              resolved={posture.findings_resolved_count}
              severityChanged={posture.findings_severity_changed_count}
            />
          </div>
          <DistributionBarLarge
            added={posture.findings_added_count}
            severityChanged={posture.findings_severity_changed_count}
            unchanged={posture.findings_unchanged_count}
            resolved={posture.findings_resolved_count}
          />
        </div>

        {sharedSbomId != null && (
          <div className="border-t border-border-subtle pt-3">
            <Sparkline
              sbomId={sharedSbomId}
              currentRunId={currentRunId}
              contextLabel={sharedSbomName ?? undefined}
            />
          </div>
        )}

        <div className="grid grid-cols-1 gap-3 sm:grid-cols-3">
          <PostureTile
            label="KEV exposure"
            valueA={posture.kev_count_a.toLocaleString()}
            valueB={posture.kev_count_b.toLocaleString()}
            delta={posture.kev_count_delta}
            direction="down-good"
            tooltip="Findings whose CVE is currently in the CISA KEV catalog. Reflects current catalog state, not at-scan-time."
          />
          <PostureTile
            label="Fix-available coverage"
            valueA={`${posture.fix_available_pct_a.toFixed(1)}%`}
            valueB={`${posture.fix_available_pct_b.toFixed(1)}%`}
            delta={posture.fix_available_pct_delta}
            direction="up-good"
            deltaSuffix="pp"
            tooltip="Percentage of findings whose 'fixed_versions' is non-empty — the operationally remediable subset."
          />
          <PostureTile
            label="High+Critical exposure"
            valueA={posture.high_critical_count_a.toLocaleString()}
            valueB={posture.high_critical_count_b.toLocaleString()}
            delta={posture.high_critical_count_delta}
            direction="down-good"
            tooltip="Findings at HIGH or CRITICAL severity, denormalised onto the finding row at scan time."
          />
        </div>
      </SurfaceContent>
    </Surface>
  );
}

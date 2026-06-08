'use client';

import { Surface } from '@/components/ui/Surface';
import { Skeleton } from '@/components/ui/Spinner';
import { cn } from '@/lib/utils';
import {
  computeHeadlineCopy,
  toneToAmbientClass,
} from '@/lib/headlineCopy';
import type { SeverityKey } from '@/lib/severityParam';
import type { DashboardPosture, HeadlineState } from '@/types';
import { AdaptiveHeadline } from './AdaptiveHeadline';
import { SeverityDistributionBar } from './SeverityDistributionBar';
import { KeySignalsRow } from './KeySignalsRow';
import { LatestRunIndicator } from './LatestRunIndicator';

interface HeroPostureCardProps {
  posture: DashboardPosture | undefined;
  isLoading: boolean;
  /** Drill-down wiring (optional — the hero renders read-only without it). */
  onSegmentClick?: (key: SeverityKey) => void;
  interactiveSeverities?: ReadonlySet<SeverityKey>;
  onKevClick?: () => void;
  onEpssClick?: () => void;
  onCriticalClick?: () => void;
  onFixClick?: () => void;
}

/**
 * The v3 hero — exploitability-led, decision-first.
 *
 * Composition (top to bottom): adaptive headline (KEV-led posture statement)
 * → latest-run freshness line → key-signals row (the four counts that change
 * a triage decision: KEV · likely-exploited EPSS · Critical · Fix) → severity
 * distribution bar, demoted to *supporting* context below the signals.
 *
 * Net-7day moved to the What's-new strip and the mini-trend to the trend
 * section — the hero now answers "what do I act on right now?" without a wall
 * of tiles. The headline tone still drives the ambient glow (decorative).
 */
export function HeroPostureCard({
  posture,
  isLoading,
  onSegmentClick,
  interactiveSeverities,
  onKevClick,
  onEpssClick,
  onCriticalClick,
  onFixClick,
}: HeroPostureCardProps) {
  const state: HeadlineState = posture?.headline_state ?? 'no_data';
  const tone = computeHeadlineCopy(state, {}).tone;
  const ambientClass = toneToAmbientClass(tone);

  if (isLoading) {
    return (
      <Surface variant="gradient" elevation={3} className="overflow-hidden p-6">
        <div className="space-y-3">
          <Skeleton className="h-8 w-72" />
          <Skeleton className="h-3 w-96" />
          <div className="grid grid-cols-1 gap-3 pt-2 sm:grid-cols-4">
            <Skeleton className="h-16" />
            <Skeleton className="h-16" />
            <Skeleton className="h-16" />
            <Skeleton className="h-16" />
          </div>
          <Skeleton className="h-7 w-full" />
        </div>
      </Surface>
    );
  }

  return (
    <Surface
      variant="gradient"
      elevation={3}
      className="motion-glide relative overflow-hidden p-6"
    >
      {/* Ambient glow keyed to headline tone — purely decorative. */}
      <div
        aria-hidden="true"
        className={cn(
          'pointer-events-none absolute -right-24 -top-24 h-72 w-72 rounded-full blur-3xl opacity-40',
          ambientClass,
        )}
      />

      <div className="relative space-y-5">
        <div className="space-y-2">
          <AdaptiveHeadline
            state={state}
            data={{
              total_sboms: posture?.total_sboms,
              total_findings: posture?.total_findings,
              critical: posture?.severity?.critical,
              high: posture?.severity?.high,
              kev_count: posture?.kev_count,
            }}
          />
          <LatestRunIndicator isoTimestamp={posture?.last_successful_run_at} />
        </div>

        {/* Key signals — the decision-relevant few, exploitability first. */}
        <KeySignalsRow
          kevCount={posture?.kev_count ?? 0}
          highEpssCount={posture?.high_epss_count}
          criticalCount={posture?.severity?.critical ?? 0}
          fixCount={posture?.fix_available_count ?? 0}
          onKevClick={onKevClick}
          onEpssClick={onEpssClick}
          onCriticalClick={onCriticalClick}
          onFixClick={onFixClick}
        />

        {/* Supporting: severity proportions, demoted below the signals. */}
        <div className="space-y-1.5">
          <p className="text-[11px] font-semibold uppercase tracking-wider text-hcl-muted">
            Severity distribution
          </p>
          <SeverityDistributionBar
            severity={posture?.severity}
            onSegmentClick={onSegmentClick}
            interactiveSeverities={interactiveSeverities}
          />
        </div>
      </div>
    </Surface>
  );
}

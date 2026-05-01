'use client';

import { Surface } from '@/components/ui/Surface';
import { Skeleton } from '@/components/ui/Spinner';
import { cn } from '@/lib/utils';
import {
  computeHeadlineCopy,
  toneToAmbientClass,
} from '@/lib/headlineCopy';
import type { DashboardPosture, DashboardTrend, HeadlineState } from '@/types';
import { AdaptiveHeadline } from './AdaptiveHeadline';
import { SeverityDistributionBar } from './SeverityDistributionBar';
import { HeroMetricRow } from './HeroMetricRow';
import { LatestRunIndicator } from './LatestRunIndicator';

interface HeroPostureCardProps {
  posture: DashboardPosture | undefined;
  trend: DashboardTrend | undefined;
  isLoading: boolean;
}

/**
 * The v2 hero — calm by default, loud only when it should be.
 *
 * Composition (top to bottom): adaptive headline → sub-line → latest-run
 * inline indicator → severity distribution bar (h-7) → 4-tile metric row.
 *
 * The headline tone drives the ambient glow color (decorative only),
 * which is the only visual signal that escalates with severity. No
 * red-dot live pill; no "Urgent attention required"; no `degraded` band.
 * If you find yourself wanting to add one of those back, reread
 * `docs/dashboard-redesign.md` §2 and §13 before reaching for the keyboard.
 */
export function HeroPostureCard({
  posture,
  trend,
  isLoading,
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
          <Skeleton className="h-7 w-full" />
          <div className="grid grid-cols-1 gap-3 pt-2 sm:grid-cols-4">
            <Skeleton className="h-16" />
            <Skeleton className="h-16" />
            <Skeleton className="h-16" />
            <Skeleton className="h-16" />
          </div>
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
      {/* Ambient glow keyed to headline tone — purely decorative.
          Same family as the headline color, low opacity, off-screen.
          Critical state is never the loudest pixel; it's the only colored one. */}
      <div
        aria-hidden="true"
        className={cn(
          'pointer-events-none absolute -right-24 -top-24 h-72 w-72 rounded-full blur-3xl opacity-40',
          ambientClass,
        )}
      />

      <div className="relative space-y-5">
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

        <SeverityDistributionBar severity={posture?.severity} />

        <HeroMetricRow posture={posture} trend={trend} />
      </div>
    </Surface>
  );
}

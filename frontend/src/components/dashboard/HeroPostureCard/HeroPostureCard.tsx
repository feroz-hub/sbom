'use client';

import { ShieldQuestion } from 'lucide-react';
import { Surface } from '@/components/ui/Surface';
import { Skeleton } from '@/components/ui/Spinner';
import { cn } from '@/lib/utils';
import {
  COVERAGE_INCOMPLETE_NOTE,
  COVERAGE_UNKNOWN_NOTE,
  coverageGapLabel,
} from '@/lib/dashboardPosture';
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
  // Coverage is part of the headline decision, so the tone (and the ambient
  // glow it drives) has to be computed with it — otherwise an unassessed
  // scope still glows green.
  const headlineData = {
    total_sboms: posture?.total_sboms,
    total_findings: posture?.total_findings,
    critical: posture?.severity?.critical,
    high: posture?.severity?.high,
    kev_count: posture?.kev_count,
    coverage_status: posture?.coverage_status,
    coverage_gap_sources: posture?.coverage_gap_sources,
  };
  const tone = computeHeadlineCopy(state, headlineData).tone;
  const ambientClass = toneToAmbientClass(tone);
  const coverageStatus = posture?.coverage_status ?? 'complete';
  const coverageShortfall = coverageStatus !== 'complete';
  const hasFindings = (posture?.total_findings ?? 0) > 0;
  // With findings present the vulnerability posture stays the headline; the
  // coverage caveat rides alongside so the count reads as a floor, not a total.
  const coverageNote = coverageShortfall
    ? [
        coverageStatus === 'incomplete' ? COVERAGE_INCOMPLETE_NOTE : COVERAGE_UNKNOWN_NOTE,
        coverageGapLabel(posture?.coverage_gap_sources),
      ]
        .filter(Boolean)
        .join(' ')
    : null;

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
          <AdaptiveHeadline state={state} data={headlineData} />
          <LatestRunIndicator isoTimestamp={posture?.last_successful_run_at} />
          {/* Findings present + coverage short: keep both facts visible. */}
          {coverageNote && hasFindings && (
            <p
              data-testid="hero-coverage-warning"
              className="flex max-w-2xl items-start gap-1.5 rounded-lg bg-amber-50 px-3 py-2 text-xs leading-relaxed text-amber-800 ring-1 ring-amber-200/70 dark:bg-amber-950/40 dark:text-amber-200 dark:ring-amber-900/60"
            >
              <ShieldQuestion className="mt-0.5 h-3.5 w-3.5 shrink-0" aria-hidden />
              <span>{coverageNote}</span>
            </p>
          )}
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
            coverageShortfall={coverageShortfall}
          />
        </div>
      </div>
    </Surface>
  );
}

'use client';

import { useCallback, useMemo } from 'react';
import { useQuery } from '@tanstack/react-query';
import { useRouter } from 'next/navigation';
import { ClipboardCheck } from 'lucide-react';
import { TopBar } from '@/components/layout/TopBar';
import { Motion } from '@/components/ui/Motion';
import { HeroPostureCard } from '@/components/dashboard/HeroPostureCard/HeroPostureCard';
import { WhatsNewStrip } from '@/components/dashboard/WhatsNewStrip';
import { CounterTiles } from '@/components/dashboard/CounterTiles';
import { SeverityChart } from '@/components/dashboard/SeverityChart';
import { VulnerabilityAgePie } from '@/components/dashboard/VulnerabilityAgePie';
import { TrendExplorer } from '@/components/dashboard/TrendExplorer';
import { QuickActionsV2 } from '@/components/dashboard/QuickActionsV2/QuickActionsV2';
import { FindingsTrendChart } from '@/components/dashboard/FindingsTrendChart/FindingsTrendChart';
import { LifetimeStats } from '@/components/dashboard/LifetimeStats/LifetimeStats';
import { TopVulnerableSboms } from '@/components/dashboard/TopVulnerableSboms';
import { ActivityFeed } from '@/components/dashboard/ActivityFeed';
import { AiConfigBanner } from '@/components/dashboard/AiConfigBanner';
import {
  getDashboardLifetime,
  getDashboardPosture,
  getDashboardTrend,
  getRuns,
} from '@/lib/api';
import {
  aggregateRuns,
  topRunForSeverity,
  type SeverityKey,
} from '@/lib/topVulnerableRuns';
import { severityKeyToParam } from '@/lib/severityParam';
import { HIGH_EPSS_PERCENTILE } from '@/lib/findingFilters';

const DRILLABLE_SEVERITIES: readonly SeverityKey[] = [
  'critical',
  'high',
  'medium',
  'low',
];

/**
 * v3 dashboard — exploitability-led, decision-first.
 *
 * Hierarchy (top to bottom):
 *  1. HeroPostureCard — "what do I act on right now?" headline + the
 *     decision-relevant few signals (KEV · likely-exploited EPSS · Critical ·
 *     Fix) + severity distribution as supporting context.
 *  2. WhatsNewStrip — the delta since last week (drives action > static totals).
 *  3. QuickActionsV2 — the primary action.
 *  4. TopVulnerableSboms — where to look first.
 *  5. Supporting detail — trend, then lifetime + activity (most demoted).
 *
 * Every finding count is one click to those findings via the shared drill-down
 * (`useFindingsFilterFromUrl`): severity counts resolve the run with the most
 * of that tier; KEV/EPSS/Fix land on the most-vulnerable run with the matching
 * filter pre-applied. The portfolio count comes from `posture`; the target run
 * from `['top-vulnerable-runs']` (shared cache — no extra request).
 *
 * The likely-exploited (EPSS) tile and needs-review chip are feature-gated on
 * optional posture fields the endpoint doesn't expose yet — they appear when
 * the Phase 2 aggregates land.
 */
export default function DashboardPage() {
  const router = useRouter();

  const postureQuery = useQuery({
    queryKey: ['dashboard-posture'],
    queryFn: ({ signal }) => getDashboardPosture(signal),
  });

  const trendQuery = useQuery({
    queryKey: ['dashboard-trend', 30],
    queryFn: ({ signal }) => getDashboardTrend(30, signal),
  });

  const lifetimeQuery = useQuery({
    queryKey: ['dashboard-lifetime'],
    queryFn: ({ signal }) => getDashboardLifetime(signal),
  });

  // Same key + fetch as TopVulnerableSboms → shared cache, one network call.
  // Resolves which run a hero drill-down should land on.
  const topRunsQuery = useQuery({
    queryKey: ['top-vulnerable-runs'],
    queryFn: ({ signal }) =>
      getRuns({ run_status: 'FINDINGS', page: 1, page_size: 100 }, signal),
  });

  const posture = postureQuery.data;
  const buckets = useMemo(
    () => aggregateRuns(topRunsQuery.data ?? []),
    [topRunsQuery.data],
  );

  // A severity is clickable only when the portfolio has findings at that tier
  // AND a run resolves to drill into — otherwise it stays a static label.
  const interactiveSeverities = useMemo(() => {
    const set = new Set<SeverityKey>();
    for (const key of DRILLABLE_SEVERITIES) {
      if ((posture?.severity?.[key] ?? 0) > 0 && topRunForSeverity(buckets, key)) {
        set.add(key);
      }
    }
    return set;
  }, [buckets, posture]);

  const handleSegmentClick = useCallback(
    (key: SeverityKey) => {
      const bucket = topRunForSeverity(buckets, key);
      if (!bucket) return;
      const globalCount = posture?.severity?.[key] ?? bucket[key];
      router.push(
        `/analysis/${bucket.latestRunId}?severity=${severityKeyToParam(key)}&globalCount=${globalCount}`,
      );
    },
    [buckets, posture, router],
  );

  // KEV / EPSS / Fix have no per-run column to rank by, so they land on the
  // most-vulnerable run (highest weighted severity) with the matching filter
  // pre-applied; the reconciliation banner frames portfolio-vs-run. Wired
  // whenever a target run exists — the tiles self-gate on count > 0.
  const topBucket = buckets[0];
  const handleKevClick = useCallback(() => {
    if (!topBucket) return;
    router.push(
      `/analysis/${topBucket.latestRunId}?kev=1&globalCount=${posture?.kev_count ?? 0}`,
    );
  }, [topBucket, posture, router]);
  const handleFixClick = useCallback(() => {
    if (!topBucket) return;
    router.push(
      `/analysis/${topBucket.latestRunId}?fix=1&globalCount=${posture?.fix_available_count ?? 0}`,
    );
  }, [topBucket, posture, router]);
  const handleEpssClick = useCallback(() => {
    if (!topBucket) return;
    router.push(
      `/analysis/${topBucket.latestRunId}?epss=${HIGH_EPSS_PERCENTILE}&globalCount=${posture?.high_epss_count ?? 0}`,
    );
  }, [topBucket, posture, router]);
  const handleReviewClick = useCallback(() => {
    if (!topBucket) return;
    router.push(
      `/analysis/${topBucket.latestRunId}?review=1&globalCount=${posture?.needs_review_count ?? 0}`,
    );
  }, [topBucket, posture, router]);

  const needsReview = posture?.needs_review_count;

  return (
    <div className="flex flex-1 flex-col">
      <TopBar
        title="Dashboard"
        subtitle="Real-time security posture across your SBOM portfolio"
      />
      <div className="space-y-6 p-6">
        <AiConfigBanner />

        {/* Counter tiles — stored / scanned / analysed */}
        <Motion preset="rise">
          <CounterTiles />
        </Motion>

        {/* "Your Analyzer, So Far" — lifetime growth, kept near the top */}
        <Motion preset="rise" delay={20}>
          <LifetimeStats data={lifetimeQuery.data} isLoading={lifetimeQuery.isLoading} />
        </Motion>

        {/* 1 — the decision */}
        <Motion preset="rise" delay={40}>
          <HeroPostureCard
            posture={postureQuery.data}
            isLoading={postureQuery.isLoading}
            onSegmentClick={handleSegmentClick}
            interactiveSeverities={interactiveSeverities}
            onKevClick={topBucket ? handleKevClick : undefined}
            onEpssClick={topBucket ? handleEpssClick : undefined}
            onCriticalClick={
              interactiveSeverities.has('critical')
                ? () => handleSegmentClick('critical')
                : undefined
            }
            onFixClick={topBucket ? handleFixClick : undefined}
          />
        </Motion>

        {/* 2 — what's changed (delta drives action more than totals) */}
        <Motion preset="rise" delay={60}>
          <WhatsNewStrip posture={postureQuery.data} />
        </Motion>

        {/* 3 — the primary action */}
        <Motion preset="rise" delay={120}>
          <QuickActionsV2 primaryAction={postureQuery.data?.primary_action} />
        </Motion>

        {/* Distribution pies — vulnerability by threat level + by age. Placed
            ABOVE the vulnerable-SBOM list so the overview reads before the list. */}
        <div className="grid grid-cols-1 gap-6 lg:grid-cols-2">
          <Motion preset="rise" delay={180}>
            <SeverityChart
              data={postureQuery.data?.severity}
              isLoading={postureQuery.isLoading}
            />
          </Motion>
          <Motion preset="rise" delay={220}>
            <VulnerabilityAgePie />
          </Motion>
        </div>

        {/* Where to look first */}
        <Motion preset="rise" delay={260}>
          <TopVulnerableSboms />
        </Motion>

        {/* Needs-review — quiet, feature-gated until the Phase 2 aggregate. */}
        {needsReview != null && needsReview > 0 && (
          <Motion preset="rise" delay={210}>
            <button
              type="button"
              onClick={topBucket ? handleReviewClick : undefined}
              disabled={!topBucket}
              className="inline-flex items-center gap-2 rounded-lg border border-amber-200 bg-amber-50/70 px-3 py-1.5 text-xs font-medium text-amber-800 transition-colors hover:bg-amber-100 focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-amber-400 disabled:cursor-default disabled:opacity-70 dark:border-amber-900 dark:bg-amber-950/30 dark:text-amber-200"
            >
              <ClipboardCheck className="h-3.5 w-3.5" aria-hidden />
              <strong className="font-metric tabular-nums">{needsReview.toLocaleString()}</strong>
              low-confidence findings need review
            </button>
          </Motion>
        )}

        {/* 5 — supporting detail */}
        <Motion preset="rise" delay={240}>
          <FindingsTrendChart data={trendQuery.data} isLoading={trendQuery.isLoading} />
        </Motion>

        {/* Trend explorer — granularity + application filter + fix/resolved */}
        <Motion preset="rise" delay={260}>
          <TrendExplorer />
        </Motion>

        {/* Recent activity — supporting detail at the foot of the dashboard. */}
        <Motion preset="rise" delay={300}>
          <ActivityFeed />
        </Motion>
      </div>
    </div>
  );
}

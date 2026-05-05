'use client';

import { useQuery } from '@tanstack/react-query';
import { TopBar } from '@/components/layout/TopBar';
import { Motion } from '@/components/ui/Motion';
import { HeroPostureCard } from '@/components/dashboard/HeroPostureCard/HeroPostureCard';
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
} from '@/lib/api';

/**
 * v2 dashboard — calm posture, real trend, value delivered.
 *
 * Layout (top to bottom):
 *  1. HeroPostureCard — adaptive headline + severity bar + 4-tile metric row
 *  2. QuickActionsV2 — primary CTA swaps based on posture state
 *  3. FindingsTrendChart — zero-filled stacked area + annotations + ref line
 *  4. LifetimeStats — cumulative growth metrics ("Your Analyzer, So Far")
 *  5. TopVulnerableSboms + ActivityFeed — preserved unchanged
 *
 * Removed in v2: SECURITY POSTURE LIVE pill, three counter cards
 * (Active Projects / Total SBOMs / Distinct Vulnerabilities), the two
 * donuts (Vulnerability Severity / SBOM Activity), and the "Degraded · NVD
 * mirror disabled" sidebar leak. Spec: ``docs/dashboard-redesign.md``.
 */
export default function DashboardPage() {
  // Single posture round-trip — ADR-0001 carried KEV/Fix/severity, v2 adds
  // total_findings, distinct_vulns, net_7day_*, headline_state, primary_action.
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

  const heroLoading = postureQuery.isLoading || trendQuery.isLoading;

  return (
    <div className="flex flex-1 flex-col">
      <TopBar
        title="Dashboard"
        subtitle="Real-time security posture across your SBOM portfolio"
      />
      <div className="space-y-6 p-6">
        <AiConfigBanner />

        <Motion preset="rise">
          <HeroPostureCard
            posture={postureQuery.data}
            trend={trendQuery.data}
            isLoading={heroLoading}
          />
        </Motion>

        <Motion preset="rise" delay={80}>
          <QuickActionsV2 primaryAction={postureQuery.data?.primary_action} />
        </Motion>

        <Motion preset="rise" delay={160}>
          <FindingsTrendChart data={trendQuery.data} isLoading={trendQuery.isLoading} />
        </Motion>

        <Motion preset="rise" delay={240}>
          <LifetimeStats data={lifetimeQuery.data} isLoading={lifetimeQuery.isLoading} />
        </Motion>

        <div className="grid grid-cols-1 gap-6 lg:grid-cols-2">
          <Motion preset="rise" delay={320}>
            <TopVulnerableSboms />
          </Motion>
          <Motion preset="rise" delay={400}>
            <ActivityFeed />
          </Motion>
        </div>
      </div>
    </div>
  );
}

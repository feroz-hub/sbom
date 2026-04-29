'use client';

import { useQuery } from '@tanstack/react-query';
import { TopBar } from '@/components/layout/TopBar';
import { Motion } from '@/components/ui/Motion';
import { HeroRiskPulse } from '@/components/dashboard/HeroRiskPulse';
import { StatsGrid } from '@/components/dashboard/StatsGrid';
import { SeverityChart } from '@/components/dashboard/SeverityChart';
import { ActivityChart } from '@/components/dashboard/ActivityChart';
import { TrendChart } from '@/components/dashboard/TrendChart';
import { TopVulnerableSboms } from '@/components/dashboard/TopVulnerableSboms';
import { ActivityFeed } from '@/components/dashboard/ActivityFeed';
import { DashboardQuickActions } from '@/components/dashboard/DashboardQuickActions';
import {
  getDashboardActivity,
  getDashboardPosture,
  getDashboardStats,
  getDashboardTrend,
  getHealth,
} from '@/lib/api';

export default function DashboardPage() {
  const statsQuery = useQuery({
    queryKey: ['dashboard-stats'],
    queryFn: ({ signal }) => getDashboardStats(signal),
  });

  const activityQuery = useQuery({
    queryKey: ['dashboard-activity'],
    queryFn: ({ signal }) => getDashboardActivity(signal),
  });

  // Posture — single source of truth for hero band, KEV count, fix-available
  // count, and last-successful-run timestamp. ADR-0001.
  const postureQuery = useQuery({
    queryKey: ['dashboard-posture'],
    queryFn: ({ signal }) => getDashboardPosture(signal),
  });

  const trendQuery = useQuery({
    queryKey: ['dashboard-trend', 30],
    queryFn: ({ signal }) => getDashboardTrend(30, signal),
  });

  // Health — drives the hero "LIVE / Degraded" pill and the posture state
  // machine's degraded gate. Polled to keep the pill honest.
  const healthQuery = useQuery({
    queryKey: ['dashboard-health'],
    queryFn: ({ signal }) => getHealth(signal),
    refetchInterval: 30_000,
    staleTime: 5_000,
    retry: 1,
  });

  const isAnySyncing =
    statsQuery.isFetching ||
    postureQuery.isFetching ||
    activityQuery.isFetching ||
    trendQuery.isFetching;

  const heroLoading =
    statsQuery.isLoading || postureQuery.isLoading || trendQuery.isLoading;

  return (
    <div className="flex flex-1 flex-col">
      <TopBar
        title="Dashboard"
        subtitle="Real-time security posture across your SBOM portfolio"
      />
      <div className="space-y-6 p-6">
        <Motion preset="rise">
          <HeroRiskPulse
            stats={statsQuery.data}
            posture={postureQuery.data}
            trend={trendQuery.data}
            health={healthQuery.data}
            isLoading={heroLoading}
            isSyncing={isAnySyncing && !heroLoading}
          />
        </Motion>

        <Motion preset="rise" delay={80}>
          <DashboardQuickActions />
        </Motion>

        <Motion preset="rise" delay={140}>
          <StatsGrid
            stats={statsQuery.data}
            trend={trendQuery.data}
            isLoading={statsQuery.isLoading}
            error={statsQuery.error}
          />
        </Motion>

        <div className="grid grid-cols-1 gap-6 lg:grid-cols-2">
          <Motion preset="rise" delay={200}>
            <SeverityChart
              data={postureQuery.data?.severity}
              isLoading={postureQuery.isLoading}
            />
          </Motion>
          <Motion preset="rise" delay={260}>
            <ActivityChart
              data={activityQuery.data}
              isLoading={activityQuery.isLoading}
            />
          </Motion>
        </div>

        <Motion preset="rise" delay={320}>
          <TrendChart data={trendQuery.data} isLoading={trendQuery.isLoading} />
        </Motion>

        <div className="grid grid-cols-1 gap-6 lg:grid-cols-2">
          <Motion preset="rise" delay={380}>
            <TopVulnerableSboms />
          </Motion>
          <Motion preset="rise" delay={440}>
            <ActivityFeed />
          </Motion>
        </div>
      </div>
    </div>
  );
}

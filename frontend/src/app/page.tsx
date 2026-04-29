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
  getDashboardSeverity,
  getDashboardStats,
  getDashboardTrend,
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

  const severityQuery = useQuery({
    queryKey: ['dashboard-severity'],
    queryFn: ({ signal }) => getDashboardSeverity(signal),
  });

  const trendQuery = useQuery({
    queryKey: ['dashboard-trend', 30],
    queryFn: ({ signal }) => getDashboardTrend(30, signal),
  });

  const isAnySyncing =
    statsQuery.isFetching ||
    severityQuery.isFetching ||
    activityQuery.isFetching ||
    trendQuery.isFetching;

  const heroLoading =
    statsQuery.isLoading || severityQuery.isLoading || trendQuery.isLoading;

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
            severity={severityQuery.data}
            trend={trendQuery.data}
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
              data={severityQuery.data}
              isLoading={severityQuery.isLoading}
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

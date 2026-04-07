'use client';

import { useQuery } from '@tanstack/react-query';
import { TopBar } from '@/components/layout/TopBar';
import { StatsGrid } from '@/components/dashboard/StatsGrid';
import { SeverityChart } from '@/components/dashboard/SeverityChart';
import { ActivityChart } from '@/components/dashboard/ActivityChart';
import { TrendChart } from '@/components/dashboard/TrendChart';
import { RecentSboms } from '@/components/dashboard/RecentSboms';
import {
  getDashboardStats,
  getRecentSboms,
  getDashboardActivity,
  getDashboardSeverity,
  getDashboardTrend,
} from '@/lib/api';

export default function DashboardPage() {
  const statsQuery = useQuery({
    queryKey: ['dashboard-stats'],
    queryFn: ({ signal }) => getDashboardStats(signal),
  });

  const recentQuery = useQuery({
    queryKey: ['recent-sboms'],
    queryFn: ({ signal }) => getRecentSboms(5, signal),
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

  return (
    <div className="flex flex-col flex-1">
      <TopBar title="Dashboard" />
      <div className="p-6 space-y-6">
        <StatsGrid
          stats={statsQuery.data}
          isLoading={statsQuery.isLoading}
          error={statsQuery.error}
        />

        <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
          <SeverityChart
            data={severityQuery.data}
            isLoading={severityQuery.isLoading}
          />
          <ActivityChart
            data={activityQuery.data}
            isLoading={activityQuery.isLoading}
          />
        </div>

        <TrendChart
          data={trendQuery.data}
          isLoading={trendQuery.isLoading}
        />

        <RecentSboms
          sboms={recentQuery.data}
          isLoading={recentQuery.isLoading}
        />
      </div>
    </div>
  );
}

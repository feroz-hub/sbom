'use client';

import {
  LineChart,
  Line,
  XAxis,
  YAxis,
  CartesianGrid,
  Tooltip,
  Legend,
  ResponsiveContainer,
} from 'recharts';
import { Card, CardHeader, CardTitle, CardContent } from '@/components/ui/Card';
import { Spinner } from '@/components/ui/Spinner';
import { useTheme } from '@/components/theme/ThemeProvider';
import type { DashboardTrend } from '@/types';

interface TrendChartProps {
  data: DashboardTrend | undefined;
  isLoading: boolean;
}

const SERIES = [
  { key: 'critical', label: 'Critical', color: '#dc2626' },
  { key: 'high', label: 'High', color: '#ea580c' },
  { key: 'medium', label: 'Medium', color: '#d97706' },
  { key: 'low', label: 'Low', color: '#0067B1' },
] as const;

export function TrendChart({ data, isLoading }: TrendChartProps) {
  const { resolvedTheme } = useTheme();
  const isDark = resolvedTheme === 'dark';
  const gridStroke = isDark ? '#334155' : '#e2e8f0';
  const axisStroke = isDark ? '#94a3b8' : '#64748b';
  const tooltipStyle = {
    borderRadius: 8,
    fontSize: 12,
    backgroundColor: isDark ? '#1e293b' : '#ffffff',
    border: isDark ? '1px solid #475569' : '1px solid #e2e8f0',
    color: isDark ? '#f1f5f9' : '#0f172a',
  };

  const series = data?.series ?? [];
  return (
    <Card>
      <CardHeader>
        <CardTitle>
          Findings Trend
          {data?.days ? (
            <span className="text-sm font-normal text-hcl-muted"> · last {data.days} days</span>
          ) : null}
        </CardTitle>
      </CardHeader>
      <CardContent>
        {isLoading ? (
          <div className="flex h-56 items-center justify-center">
            <Spinner />
          </div>
        ) : series.length === 0 ? (
          <div className="flex h-56 items-center justify-center text-sm text-hcl-muted">
            No analysis runs in this window
          </div>
        ) : (
          <ResponsiveContainer width="100%" height={240}>
            <LineChart data={series} margin={{ top: 8, right: 12, left: -16, bottom: 0 }}>
              <CartesianGrid strokeDasharray="3 3" stroke={gridStroke} />
              <XAxis dataKey="date" tick={{ fontSize: 11, fill: axisStroke }} stroke={axisStroke} />
              <YAxis
                tick={{ fontSize: 11, fill: axisStroke }}
                stroke={axisStroke}
                allowDecimals={false}
              />
              <Tooltip
                contentStyle={tooltipStyle}
                formatter={(value: number, name: string) => [value.toLocaleString(), name]}
              />
              <Legend wrapperStyle={{ fontSize: '12px', color: isDark ? '#e2e8f0' : '#334155' }} />
              {SERIES.map((s) => (
                <Line
                  key={s.key}
                  type="monotone"
                  dataKey={s.key}
                  name={s.label}
                  stroke={s.color}
                  strokeWidth={2}
                  dot={false}
                />
              ))}
            </LineChart>
          </ResponsiveContainer>
        )}
      </CardContent>
    </Card>
  );
}

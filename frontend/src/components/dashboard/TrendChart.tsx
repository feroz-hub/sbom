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
  const series = data?.series ?? [];
  return (
    <Card>
      <CardHeader>
        <CardTitle>
          Findings Trend{data?.days ? <span className="text-hcl-muted text-sm font-normal"> · last {data.days} days</span> : null}
        </CardTitle>
      </CardHeader>
      <CardContent>
        {isLoading ? (
          <div className="flex items-center justify-center h-56">
            <Spinner />
          </div>
        ) : series.length === 0 ? (
          <div className="flex items-center justify-center h-56 text-gray-400 text-sm">
            No analysis runs in this window
          </div>
        ) : (
          <ResponsiveContainer width="100%" height={240}>
            <LineChart data={series} margin={{ top: 8, right: 12, left: -16, bottom: 0 }}>
              <CartesianGrid strokeDasharray="3 3" stroke="#e2e8f0" />
              <XAxis dataKey="date" tick={{ fontSize: 11 }} stroke="#64748b" />
              <YAxis tick={{ fontSize: 11 }} stroke="#64748b" allowDecimals={false} />
              <Tooltip
                contentStyle={{ borderRadius: '8px', fontSize: '12px' }}
                formatter={(value: number, name: string) => [value.toLocaleString(), name]}
              />
              <Legend wrapperStyle={{ fontSize: '12px' }} />
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

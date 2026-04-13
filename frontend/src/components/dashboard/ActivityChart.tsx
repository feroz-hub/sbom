'use client';

import { PieChart, Pie, Cell, Tooltip, Legend, ResponsiveContainer } from 'recharts';
import { Card, CardHeader, CardTitle, CardContent } from '@/components/ui/Card';
import { Spinner } from '@/components/ui/Spinner';
import { useTheme } from '@/components/theme/ThemeProvider';
import type { ActivityData } from '@/types';

interface ActivityChartProps {
  data: ActivityData | undefined;
  isLoading: boolean;
}

const COLORS = ['#0067B1', '#00B2E2'];

export function ActivityChart({ data, isLoading }: ActivityChartProps) {
  const { resolvedTheme } = useTheme();
  const tooltipStyle = {
    borderRadius: 8,
    fontSize: 12,
    backgroundColor: resolvedTheme === 'dark' ? '#1e293b' : '#ffffff',
    border: resolvedTheme === 'dark' ? '1px solid #475569' : '1px solid #e2e8f0',
    color: resolvedTheme === 'dark' ? '#f1f5f9' : '#0f172a',
  };

  const chartData = data
    ? [
        { name: 'Active (≤30d)', value: data.active_30d },
        { name: 'Stale', value: data.stale },
      ]
    : [];

  const total = chartData.reduce((s, d) => s + d.value, 0);

  return (
    <Card>
      <CardHeader>
        <CardTitle>SBOM Activity</CardTitle>
      </CardHeader>
      <CardContent>
        {isLoading ? (
          <div className="flex h-48 items-center justify-center">
            <Spinner />
          </div>
        ) : total === 0 ? (
          <div className="flex h-48 items-center justify-center text-sm text-hcl-muted">
            No activity data available
          </div>
        ) : (
          <>
            <ResponsiveContainer width="100%" height={220}>
              <PieChart>
                <Pie
                  data={chartData}
                  cx="50%"
                  cy="50%"
                  innerRadius={60}
                  outerRadius={90}
                  paddingAngle={3}
                  dataKey="value"
                >
                  {chartData.map((_, i) => (
                    <Cell key={i} fill={COLORS[i % COLORS.length]} />
                  ))}
                </Pie>
                <Tooltip
                  formatter={(value: number) => [value.toLocaleString(), 'SBOMs']}
                  contentStyle={tooltipStyle}
                />
                <Legend
                  formatter={(value) => (
                    <span className="text-xs text-foreground">{value}</span>
                  )}
                />
              </PieChart>
            </ResponsiveContainer>
            <div className="mt-2 flex justify-center gap-6">
              {chartData.map((d, i) => (
                <div key={d.name} className="flex items-center gap-2">
                  <span className="h-2.5 w-2.5 rounded-full" style={{ backgroundColor: COLORS[i] }} />
                  <span className="text-xs text-hcl-muted">
                    {d.name}: <strong className="text-hcl-navy">{d.value}</strong>
                  </span>
                </div>
              ))}
            </div>
          </>
        )}
      </CardContent>
    </Card>
  );
}

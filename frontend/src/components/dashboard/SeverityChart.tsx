'use client';

import { PieChart, Pie, Cell, Tooltip, Legend, ResponsiveContainer } from 'recharts';
import { Card, CardHeader, CardTitle, CardContent } from '@/components/ui/Card';
import { Spinner } from '@/components/ui/Spinner';
import { useTheme } from '@/components/theme/ThemeProvider';
import type { SeverityData } from '@/types';

interface SeverityChartProps {
  data: SeverityData | undefined;
  isLoading: boolean;
}

const COLORS: Record<string, string> = {
  Critical: '#C0392B',
  High: '#D4680A',
  Medium: '#B8860B',
  Low: '#0067B1',
  Unknown: '#5B7083',
};

export function SeverityChart({ data, isLoading }: SeverityChartProps) {
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
        { name: 'Critical', value: data.critical },
        { name: 'High', value: data.high },
        { name: 'Medium', value: data.medium },
        { name: 'Low', value: data.low },
        { name: 'Unknown', value: data.unknown },
      ].filter((d) => d.value > 0)
    : [];

  const total = chartData.reduce((s, d) => s + d.value, 0);

  return (
    <Card>
      <CardHeader>
        <CardTitle>Vulnerability Severity</CardTitle>
      </CardHeader>
      <CardContent>
        {isLoading ? (
          <div className="flex h-48 items-center justify-center">
            <Spinner />
          </div>
        ) : total === 0 ? (
          <div className="flex h-48 items-center justify-center text-sm text-hcl-muted">
            No vulnerability data available
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
                  {chartData.map((entry) => (
                    <Cell key={entry.name} fill={COLORS[entry.name]} />
                  ))}
                </Pie>
                <Tooltip formatter={(value: number) => [value.toLocaleString(), 'Count']} contentStyle={tooltipStyle} />
                <Legend
                  formatter={(value) => (
                    <span className="text-xs text-foreground">{value}</span>
                  )}
                />
              </PieChart>
            </ResponsiveContainer>
            <div className="mt-2 grid grid-cols-2 gap-2">
              {chartData.map((d) => (
                <div key={d.name} className="flex items-center gap-2">
                  <span
                    className="h-2.5 w-2.5 flex-shrink-0 rounded-full"
                    style={{ backgroundColor: COLORS[d.name] }}
                  />
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

'use client';

import { PieChart, Pie, Cell, Tooltip, Legend, ResponsiveContainer } from 'recharts';
import { Card, CardHeader, CardTitle, CardContent } from '@/components/ui/Card';
import { Spinner } from '@/components/ui/Spinner';
import type { SeverityData } from '@/types';

interface SeverityChartProps {
  data: SeverityData | undefined;
  isLoading: boolean;
}

const COLORS: Record<string, string> = {
  Critical: '#dc2626',
  High: '#ea580c',
  Medium: '#ca8a04',
  Low: '#2563eb',
  Unknown: '#6b7280',
};

export function SeverityChart({ data, isLoading }: SeverityChartProps) {
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
          <div className="flex items-center justify-center h-48">
            <Spinner />
          </div>
        ) : total === 0 ? (
          <div className="flex items-center justify-center h-48 text-gray-400 text-sm">
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
                <Tooltip
                  formatter={(value: number) => [value.toLocaleString(), 'Count']}
                  contentStyle={{ borderRadius: '8px', fontSize: '12px' }}
                />
                <Legend
                  formatter={(value) => (
                    <span className="text-xs text-gray-700">{value}</span>
                  )}
                />
              </PieChart>
            </ResponsiveContainer>
            <div className="mt-2 grid grid-cols-2 gap-2">
              {chartData.map((d) => (
                <div key={d.name} className="flex items-center gap-2">
                  <span
                    className="w-2.5 h-2.5 rounded-full flex-shrink-0"
                    style={{ backgroundColor: COLORS[d.name] }}
                  />
                  <span className="text-xs text-gray-600">
                    {d.name}: <strong>{d.value}</strong>
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

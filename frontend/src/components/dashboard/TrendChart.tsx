'use client';

import { useId, useMemo, useState } from 'react';
import {
  Area,
  AreaChart,
  CartesianGrid,
  Legend,
  ResponsiveContainer,
  Tooltip,
  XAxis,
  YAxis,
  type TooltipProps,
} from 'recharts';
import { Surface, SurfaceContent, SurfaceHeader } from '@/components/ui/Surface';
import { Spinner } from '@/components/ui/Spinner';
import { EmptyState } from '@/components/ui/EmptyState';
import { useTheme } from '@/components/theme/ThemeProvider';
import { cn } from '@/lib/utils';
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

type SeriesKey = (typeof SERIES)[number]['key'];

function CustomTooltip({ active, payload, label }: TooltipProps<number, string>) {
  if (!active || !payload?.length) return null;
  const total = payload.reduce((s, p) => s + (typeof p.value === 'number' ? p.value : 0), 0);
  return (
    <div className="min-w-[160px] rounded-lg border border-border-subtle bg-surface px-3 py-2 text-xs shadow-elev-3">
      <div className="font-metric text-[11px] font-semibold uppercase tracking-wider text-hcl-muted">
        {label}
      </div>
      <ul className="mt-1.5 space-y-1">
        {payload.map((entry) => (
          <li key={String(entry.dataKey)} className="flex items-center justify-between gap-3">
            <span className="flex items-center gap-1.5">
              <span className="h-2 w-2 rounded-full" style={{ backgroundColor: entry.color }} aria-hidden />
              <span className="text-hcl-navy">{entry.name}</span>
            </span>
            <span className="font-metric font-semibold text-hcl-navy">
              {typeof entry.value === 'number' ? entry.value.toLocaleString() : '—'}
            </span>
          </li>
        ))}
        <li className="mt-1 flex items-center justify-between gap-3 border-t border-border-subtle pt-1">
          <span className="text-[10px] font-semibold uppercase tracking-wider text-hcl-muted">
            Total
          </span>
          <span className="font-metric text-xs font-bold text-hcl-navy">
            {total.toLocaleString()}
          </span>
        </li>
      </ul>
    </div>
  );
}

export function TrendChart({ data, isLoading }: TrendChartProps) {
  const { resolvedTheme } = useTheme();
  const isDark = resolvedTheme === 'dark';
  const gradientPrefix = useId().replace(/[:.]/g, '-');

  const [hidden, setHidden] = useState<Record<SeriesKey, boolean>>({
    critical: false,
    high: false,
    medium: false,
    low: false,
  });

  const series = data?.series ?? [];

  const gridStroke = isDark ? '#243047' : '#dce8f2';
  const axisStroke = isDark ? '#8fa4bd' : '#5c6d7e';

  const formattedSeries = useMemo(
    () =>
      series.map((p) => ({
        ...p,
        // Display: "Apr 12" — keep date string for tooltip's `label`
        date: p.date,
      })),
    [series],
  );

  const toggleSeries = (key: SeriesKey) => {
    setHidden((prev) => ({ ...prev, [key]: !prev[key] }));
  };

  const totals: Record<SeriesKey, number> = useMemo(() => {
    const acc: Record<SeriesKey, number> = { critical: 0, high: 0, medium: 0, low: 0 };
    for (const p of series) {
      acc.critical += p.critical;
      acc.high += p.high;
      acc.medium += p.medium;
      acc.low += p.low;
    }
    return acc;
  }, [series]);

  return (
    <Surface variant="elevated">
      <SurfaceHeader>
        <div>
          <h3 className="text-base font-semibold text-hcl-navy">
            Findings trend
            {data?.days ? (
              <span className="ml-2 text-xs font-normal text-hcl-muted">
                · last {data.days} days
              </span>
            ) : null}
          </h3>
          <p className="mt-0.5 text-xs text-hcl-muted">
            Daily severity counts across all analysis runs.
          </p>
        </div>
        <div className="hidden items-center gap-1.5 sm:flex">
          {SERIES.map((s) => (
            <button
              key={s.key}
              type="button"
              onClick={() => toggleSeries(s.key)}
              aria-pressed={!hidden[s.key]}
              className={cn(
                'inline-flex items-center gap-1.5 rounded-full border px-2.5 py-1 text-[11px] font-medium transition-all duration-base ease-spring',
                'focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-hcl-blue/40',
                hidden[s.key]
                  ? 'border-border-subtle bg-surface-muted text-hcl-muted opacity-60'
                  : 'border-border bg-surface text-hcl-navy hover:-translate-y-px',
              )}
            >
              <span
                className="h-2 w-2 rounded-full"
                style={{ backgroundColor: hidden[s.key] ? 'currentColor' : s.color }}
                aria-hidden
              />
              {s.label}
              <span className="font-metric text-[10px] tabular-nums text-hcl-muted">
                {totals[s.key].toLocaleString()}
              </span>
            </button>
          ))}
        </div>
      </SurfaceHeader>
      <SurfaceContent>
        {isLoading ? (
          <div className="flex h-64 items-center justify-center">
            <Spinner />
          </div>
        ) : series.length === 0 ? (
          <EmptyState
            illustration="no-runs"
            title="No analysis runs yet"
            description="Run an analysis to populate the trend over time."
            compact
          />
        ) : (
          <ResponsiveContainer width="100%" height={260}>
            <AreaChart
              data={formattedSeries}
              margin={{ top: 8, right: 12, left: -16, bottom: 0 }}
            >
              <defs>
                {SERIES.map((s) => (
                  <linearGradient
                    key={s.key}
                    id={`${gradientPrefix}-${s.key}`}
                    x1="0"
                    y1="0"
                    x2="0"
                    y2="1"
                  >
                    <stop offset="0%" stopColor={s.color} stopOpacity={0.32} />
                    <stop offset="100%" stopColor={s.color} stopOpacity={0} />
                  </linearGradient>
                ))}
              </defs>
              <CartesianGrid
                strokeDasharray="3 3"
                stroke={gridStroke}
                vertical={false}
              />
              <XAxis
                dataKey="date"
                tick={{ fontSize: 11, fill: axisStroke }}
                stroke={axisStroke}
                tickLine={false}
                axisLine={{ stroke: gridStroke }}
                minTickGap={24}
              />
              <YAxis
                tick={{ fontSize: 11, fill: axisStroke }}
                stroke={axisStroke}
                allowDecimals={false}
                tickLine={false}
                axisLine={{ stroke: gridStroke }}
                width={42}
              />
              <Tooltip
                content={<CustomTooltip />}
                cursor={{ stroke: axisStroke, strokeDasharray: '3 3', strokeOpacity: 0.6 }}
              />
              <Legend
                wrapperStyle={{ display: 'none' }}
              />
              {SERIES.map((s) =>
                hidden[s.key] ? null : (
                  <Area
                    key={s.key}
                    type="monotone"
                    dataKey={s.key}
                    name={s.label}
                    stroke={s.color}
                    fill={`url(#${gradientPrefix}-${s.key})`}
                    strokeWidth={2}
                    dot={false}
                    activeDot={{ r: 4, strokeWidth: 2, stroke: 'var(--color-surface)' }}
                    isAnimationActive
                    animationDuration={650}
                    animationEasing="ease-out"
                  />
                ),
              )}
            </AreaChart>
          </ResponsiveContainer>
        )}
      </SurfaceContent>
    </Surface>
  );
}

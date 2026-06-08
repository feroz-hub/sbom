'use client';

import { useState } from 'react';
import { useQuery } from '@tanstack/react-query';
import {
  Area,
  CartesianGrid,
  ComposedChart,
  Legend,
  Line,
  ResponsiveContainer,
  Tooltip,
  XAxis,
  YAxis,
  type TooltipProps,
} from 'recharts';
import { ChevronDown } from 'lucide-react';
import { Surface, SurfaceContent, SurfaceHeader } from '@/components/ui/Surface';
import { Spinner } from '@/components/ui/Spinner';
import { useTheme } from '@/components/theme/ThemeProvider';
import { getDashboardTrendFiltered, getProjects } from '@/lib/api';
import { cn } from '@/lib/utils';
import type { TrendGranularity } from '@/types';

const SEVERITY_SERIES = [
  { key: 'critical', label: 'Critical', color: '#C0392B' },
  { key: 'high', label: 'High', color: '#D4680A' },
  { key: 'medium', label: 'Medium', color: '#B8860B' },
  { key: 'low', label: 'Low', color: '#0067B1' },
] as const;

const GRANULARITIES: TrendGranularity[] = ['day', 'week', 'month', 'year'];

function formatAxis(input: string, granularity: TrendGranularity): string {
  const dt = new Date(input);
  if (Number.isNaN(dt.getTime())) return input;
  if (granularity === 'year') return String(dt.getUTCFullYear());
  if (granularity === 'month') {
    return dt.toLocaleString('en-US', { month: 'short', year: '2-digit', timeZone: 'UTC' });
  }
  return dt.toLocaleString('en-US', { month: 'short', day: 'numeric', timeZone: 'UTC' });
}

function TrendTooltip({ active, payload, label }: TooltipProps<number, string>) {
  if (!active || !payload?.length) return null;
  return (
    <div className="min-w-[180px] rounded-lg border border-border-subtle bg-surface px-3 py-2 text-xs shadow-elev-3">
      <div className="font-metric text-[11px] font-semibold uppercase tracking-wider text-hcl-muted">
        {typeof label === 'string' ? label : ''}
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
      </ul>
    </div>
  );
}

/**
 * Manager trend explorer: severity (stacked areas) over time at a chosen
 * granularity, optionally filtered to a set of applications (projects), with
 * the two fix overlays — ``fix_available`` and ``resolved`` — as lines.
 * Separate from the calm v2 ``FindingsTrendChart`` so that stays untouched.
 */
export function TrendExplorer() {
  const { resolvedTheme } = useTheme();
  const isDark = resolvedTheme === 'dark';
  const [granularity, setGranularity] = useState<TrendGranularity>('week');
  const [selectedApps, setSelectedApps] = useState<number[]>([]);

  const projectsQuery = useQuery({
    queryKey: ['projects'],
    queryFn: ({ signal }) => getProjects(signal),
  });
  const projects = projectsQuery.data ?? [];

  const { data, isLoading } = useQuery({
    queryKey: ['trend-explorer', granularity, [...selectedApps].sort((a, b) => a - b)],
    queryFn: ({ signal }) =>
      getDashboardTrendFiltered(
        { granularity, applicationIds: selectedApps.length ? selectedApps : undefined },
        signal,
      ),
  });
  const points = data?.points ?? [];

  const gridStroke = isDark ? '#243047' : '#dce8f2';
  const axisStroke = isDark ? '#8fa4bd' : '#5c6d7e';

  const toggleApp = (id: number) =>
    setSelectedApps((prev) =>
      prev.includes(id) ? prev.filter((x) => x !== id) : [...prev, id],
    );

  return (
    <Surface variant="elevated">
      <SurfaceHeader>
        <div>
          <h3 className="text-base font-semibold text-hcl-navy">Trend explorer</h3>
          <p className="mt-0.5 text-xs text-hcl-muted">
            Severity over time with fixes-available and resolved overlays.
          </p>
        </div>
        <div className="flex flex-wrap items-center gap-2">
          {/* Granularity toggle */}
          <div className="inline-flex rounded-lg border border-border bg-surface p-0.5">
            {GRANULARITIES.map((g) => (
              <button
                key={g}
                type="button"
                onClick={() => setGranularity(g)}
                aria-pressed={granularity === g}
                className={cn(
                  'rounded-md px-2.5 py-1 text-[11px] font-medium capitalize transition-colors focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-hcl-blue/40',
                  granularity === g
                    ? 'bg-hcl-blue text-white'
                    : 'text-hcl-muted hover:text-hcl-navy',
                )}
              >
                {g}
              </button>
            ))}
          </div>
          {/* Application filter */}
          <details className="relative">
            <summary className="inline-flex cursor-pointer list-none items-center gap-1 rounded-lg border border-border bg-surface px-2.5 py-1 text-[11px] font-medium text-hcl-navy">
              {selectedApps.length ? `${selectedApps.length} application${selectedApps.length > 1 ? 's' : ''}` : 'All applications'}
              <ChevronDown className="h-3 w-3" aria-hidden />
            </summary>
            <div className="absolute right-0 z-10 mt-1 max-h-64 w-56 overflow-auto rounded-lg border border-border bg-surface p-2 shadow-elev-3">
              {projects.length === 0 ? (
                <p className="px-1 py-2 text-xs text-hcl-muted">No applications.</p>
              ) : (
                <ul className="space-y-0.5">
                  {projects.map((p) => (
                    <li key={p.id}>
                      <label className="flex cursor-pointer items-center gap-2 rounded px-1.5 py-1 text-xs text-hcl-navy hover:bg-surface-muted">
                        <input
                          type="checkbox"
                          checked={selectedApps.includes(p.id)}
                          onChange={() => toggleApp(p.id)}
                          className="accent-hcl-blue"
                        />
                        <span className="truncate">{p.project_name}</span>
                      </label>
                    </li>
                  ))}
                </ul>
              )}
              {selectedApps.length > 0 && (
                <button
                  type="button"
                  onClick={() => setSelectedApps([])}
                  className="mt-1 w-full rounded px-1.5 py-1 text-left text-[11px] font-medium text-hcl-blue hover:bg-surface-muted"
                >
                  Clear selection
                </button>
              )}
            </div>
          </details>
        </div>
      </SurfaceHeader>
      <SurfaceContent>
        {isLoading ? (
          <div className="flex h-80 items-center justify-center">
            <Spinner />
          </div>
        ) : (
          <ResponsiveContainer width="100%" height={320}>
            <ComposedChart data={points} margin={{ top: 12, right: 16, left: -16, bottom: 0 }}>
              <CartesianGrid strokeDasharray="3 3" stroke={gridStroke} vertical={false} />
              <XAxis
                dataKey="date"
                tick={{ fontSize: 11, fill: axisStroke }}
                stroke={axisStroke}
                tickLine={false}
                axisLine={{ stroke: gridStroke }}
                minTickGap={20}
                tickFormatter={(v) => formatAxis(v, granularity)}
              />
              <YAxis
                tick={{ fontSize: 11, fill: axisStroke }}
                stroke={axisStroke}
                allowDecimals={false}
                tickLine={false}
                axisLine={{ stroke: gridStroke }}
                width={42}
              />
              <Tooltip content={<TrendTooltip />} />
              <Legend wrapperStyle={{ fontSize: 11 }} />
              {SEVERITY_SERIES.map((s) => (
                <Area
                  key={s.key}
                  type="monotone"
                  dataKey={s.key}
                  stackId="severity"
                  name={s.label}
                  stroke={s.color}
                  fill={s.color}
                  fillOpacity={0.18}
                  strokeWidth={1.5}
                  dot={false}
                  isAnimationActive
                  animationDuration={500}
                />
              ))}
              <Line
                type="monotone"
                dataKey="fix_available"
                name="Fix available"
                stroke="#16A34A"
                strokeWidth={2}
                dot={false}
                isAnimationActive
                animationDuration={500}
              />
              <Line
                type="monotone"
                dataKey="resolved"
                name="Resolved"
                stroke="#7C3AED"
                strokeWidth={2}
                strokeDasharray="5 4"
                dot={false}
                isAnimationActive
                animationDuration={500}
              />
            </ComposedChart>
          </ResponsiveContainer>
        )}
      </SurfaceContent>
    </Surface>
  );
}

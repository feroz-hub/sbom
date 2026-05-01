'use client';

import { useId, useMemo, useState } from 'react';
import {
  Area,
  AreaChart,
  CartesianGrid,
  Legend,
  ReferenceDot,
  ReferenceLine,
  ResponsiveContainer,
  Tooltip,
  XAxis,
  YAxis,
  type TooltipProps,
} from 'recharts';
import { Surface, SurfaceContent, SurfaceHeader } from '@/components/ui/Surface';
import { Spinner } from '@/components/ui/Spinner';
import { useTheme } from '@/components/theme/ThemeProvider';
import { cn } from '@/lib/utils';
import type {
  DashboardTrend,
  TrendAnnotation,
  TrendAnnotationKind,
} from '@/types';
import { EmptyTrendState } from './EmptyTrendState';

interface FindingsTrendChartProps {
  data: DashboardTrend | undefined;
  isLoading: boolean;
}

const SERIES = [
  { key: 'critical', label: 'Critical', color: '#C0392B' },
  { key: 'high', label: 'High', color: '#D4680A' },
  { key: 'medium', label: 'Medium', color: '#B8860B' },
  { key: 'low', label: 'Low', color: '#0067B1' },
  { key: 'unknown', label: 'Unknown', color: '#6B7A8D' },
] as const;

type SeriesKey = (typeof SERIES)[number]['key'];

const ANNOTATION_VISUAL: Record<TrendAnnotationKind, { color: string; label: string }> = {
  sbom_uploaded: { color: '#0067B1', label: 'SBOM uploaded' },
  remediation: { color: '#16A34A', label: 'Findings resolved' },
  kev_first_seen: { color: '#C0392B', label: 'New KEV-listed CVE' },
};

function CustomTooltip({ active, payload, label }: TooltipProps<number, string>) {
  if (!active || !payload?.length) return null;
  const total = payload.reduce(
    (s, p) => s + (typeof p.value === 'number' ? p.value : 0),
    0,
  );
  return (
    <div className="min-w-[180px] rounded-lg border border-border-subtle bg-surface px-3 py-2 text-xs shadow-elev-3">
      <div className="font-metric text-[11px] font-semibold uppercase tracking-wider text-hcl-muted">
        {formatTooltipDate(label)}
      </div>
      <ul className="mt-1.5 space-y-1">
        {payload.map((entry) => (
          <li key={String(entry.dataKey)} className="flex items-center justify-between gap-3">
            <span className="flex items-center gap-1.5">
              <span
                className="h-2 w-2 rounded-full"
                style={{ backgroundColor: entry.color }}
                aria-hidden
              />
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

function formatTooltipDate(input: unknown): string {
  if (typeof input !== 'string') return '';
  const dt = new Date(input);
  if (Number.isNaN(dt.getTime())) return input;
  return dt
    .toLocaleString('en-US', { month: 'short', day: 'numeric' })
    .toUpperCase();
}

function formatXAxisDate(input: string): string {
  const dt = new Date(input);
  if (Number.isNaN(dt.getTime())) return input;
  return dt.toLocaleString('en-US', { month: 'short', day: 'numeric' });
}

/**
 * v2 Findings Trend chart.
 *
 * Replaces the v1 chart that broke when only one day of data existed.
 * Backend now zero-fills, includes ``unknown``, ships annotations, and
 * provides ``avg_total`` for the dashed reference line. Frontend changes
 * vs v1: adds reference line, renders annotation markers, switches to
 * ``points`` (with ``series`` fallback for the deprecation window), and
 * adds the empty state for the first 7 days.
 *
 * Spec: ``docs/dashboard-redesign.md`` §5.
 */
export function FindingsTrendChart({ data, isLoading }: FindingsTrendChartProps) {
  const { resolvedTheme } = useTheme();
  const isDark = resolvedTheme === 'dark';
  const gradientPrefix = useId().replace(/[:.]/g, '-');

  const [hidden, setHidden] = useState<Record<SeriesKey, boolean>>({
    critical: false,
    high: false,
    medium: false,
    low: false,
    // Unknown hidden by default — it's a data-quality signal, not a tier.
    // The toggle is right there in the legend if the user wants it on.
    unknown: true,
  });

  // v2 reads `points`; falls back to legacy `series` for the deprecation window.
  const points = data?.points ?? data?.series ?? [];
  const annotations = data?.annotations ?? [];
  const avgTotal = data?.avg_total ?? 0;

  // Empty-state condition uses the server-supplied
  // `runs_distinct_dates` (canonical: count of distinct calendar dates with
  // ≥1 successful run). Falls back to the FE-derived `populatedDays` heuristic
  // only if the server hasn't shipped the new field yet (back-compat window).
  // The empty-state copy uses `runs_total` so same-day runs report honestly.
  // See `docs/dashboard-metrics-spec.md` §3.6 — Bug 2 + Bug 6 lock.
  const populatedDays = useMemo(
    () => points.filter((p) => (p.total ?? 0) > 0).length,
    [points],
  );
  const distinctDates = data?.runs_distinct_dates ?? populatedDays;
  const runsTotal = data?.runs_total ?? populatedDays;
  const showEmptyState = distinctDates > 0 && distinctDates < 7;

  const totals: Record<SeriesKey, number> = useMemo(() => {
    const acc: Record<SeriesKey, number> = {
      critical: 0,
      high: 0,
      medium: 0,
      low: 0,
      unknown: 0,
    };
    for (const p of points) {
      acc.critical += p.critical;
      acc.high += p.high;
      acc.medium += p.medium;
      acc.low += p.low;
      acc.unknown += p.unknown ?? 0;
    }
    return acc;
  }, [points]);

  const gridStroke = isDark ? '#243047' : '#dce8f2';
  const axisStroke = isDark ? '#8fa4bd' : '#5c6d7e';

  const toggleSeries = (key: SeriesKey) => {
    setHidden((prev) => ({ ...prev, [key]: !prev[key] }));
  };

  const annotationsByDate = useMemo(() => {
    const map = new Map<string, TrendAnnotation[]>();
    for (const a of annotations) {
      const list = map.get(a.date) ?? [];
      list.push(a);
      map.set(a.date, list);
    }
    return map;
  }, [annotations]);

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
            {avgTotal > 0 && (
              <>
                {' '}
                <span className="font-metric tabular-nums">
                  {avgTotal.toLocaleString(undefined, { maximumFractionDigits: 1 })}
                </span>{' '}
                /day average.
              </>
            )}
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
          <div className="flex h-80 items-center justify-center">
            <Spinner />
          </div>
        ) : showEmptyState ? (
          <EmptyTrendState runsSoFar={runsTotal} />
        ) : (
          <ResponsiveContainer width="100%" height={320}>
            <AreaChart
              data={points}
              margin={{ top: 12, right: 16, left: -16, bottom: 0 }}
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
                tickFormatter={formatXAxisDate}
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
                cursor={{
                  stroke: axisStroke,
                  strokeDasharray: '3 3',
                  strokeOpacity: 0.6,
                }}
              />
              <Legend wrapperStyle={{ display: 'none' }} />

              {/* 30-day average reference line — context for any single day's value. */}
              {avgTotal > 0 && (
                <ReferenceLine
                  y={avgTotal}
                  stroke={isDark ? '#3D9FDA' : '#0067B1'}
                  strokeDasharray="4 4"
                  strokeOpacity={0.55}
                  label={{
                    value: `Avg ${avgTotal.toLocaleString(undefined, { maximumFractionDigits: 0 })}`,
                    position: 'right',
                    fontSize: 10,
                    fill: axisStroke,
                  }}
                />
              )}

              {/* Stacked areas — Critical at the bottom for visual weight. */}
              {SERIES.map((s) =>
                hidden[s.key] ? null : (
                  <Area
                    key={s.key}
                    type="monotone"
                    dataKey={s.key}
                    stackId="severity"
                    name={s.label}
                    stroke={s.color}
                    fill={`url(#${gradientPrefix}-${s.key})`}
                    strokeWidth={2}
                    dot={false}
                    activeDot={{
                      r: 4,
                      strokeWidth: 2,
                      stroke: 'var(--color-surface)',
                    }}
                    isAnimationActive
                    animationDuration={650}
                    animationEasing="ease-out"
                  />
                ),
              )}

              {/* Annotation markers — one per day, colored by kind. The
                  tooltip absorbs the per-event labels via title text. */}
              {[...annotationsByDate.entries()].map(([date, list]) => {
                const dominant = list[0];
                if (!dominant) return null;
                const visual = ANNOTATION_VISUAL[dominant.kind];
                const labels = list.map((a) => a.label).join(' · ');
                return (
                  <ReferenceDot
                    key={date}
                    x={date}
                    y={0}
                    r={5}
                    fill={visual.color}
                    stroke={isDark ? '#15202F' : '#FFFFFF'}
                    strokeWidth={1.5}
                    isFront
                    label={{
                      value: '▼',
                      fill: visual.color,
                      fontSize: 11,
                      position: 'top',
                    }}
                    aria-label={`${visual.label} on ${date}: ${labels}`}
                  />
                );
              })}
            </AreaChart>
          </ResponsiveContainer>
        )}
      </SurfaceContent>
    </Surface>
  );
}

'use client';

import { useQuery } from '@tanstack/react-query';
import {
  Area,
  ComposedChart,
  Line,
  ResponsiveContainer,
  Tooltip,
  XAxis,
  YAxis,
  type TooltipContentProps,
} from 'recharts';
import { AlertTriangle, TrendingDown, TrendingUp } from 'lucide-react';
import { Surface, SurfaceContent, SurfaceHeader } from '@/components/ui/Surface';
import { Spinner } from '@/components/ui/Spinner';
import { EmptyState } from '@/components/ui/EmptyState';
import { getDashboardForecast } from '@/lib/api';
import { cn } from '@/lib/utils';

/**
 * Predictive risk engine — projected distinct-active findings trajectory.
 *
 * Solid line = observed daily distinct-active total (the locked trend
 * series). Dashed line = OLS projection over the next horizon, with a
 * ±1.96σ residual band. The card never overstates: the server flags
 * `insufficient_history` (<7 days of data) and we render an empty state
 * instead of a two-point regression; R² is shown so a noisy fit reads as
 * noisy. The anomaly strip fires when yesterday's velocity broke the
 * 30-day baseline (|z| ≥ 2).
 */

interface ChartRow {
  date: string;
  actual?: number;
  projected?: number;
  bandLo?: number;
  bandSpan?: number;
}

function shortDate(d: string): string {
  return d.length >= 10 ? d.slice(5) : d;
}

function isChartRow(value: unknown): value is ChartRow {
  if (!value || typeof value !== 'object') return false;
  const candidate = value as Record<string, unknown>;
  return (
    typeof candidate.date === 'string'
    && (candidate.actual == null || typeof candidate.actual === 'number')
    && (candidate.projected == null || typeof candidate.projected === 'number')
    && (candidate.bandLo == null || typeof candidate.bandLo === 'number')
    && (candidate.bandSpan == null || typeof candidate.bandSpan === 'number')
  );
}

function ForecastTooltip({ active, payload, label }: TooltipContentProps) {
  if (!active || !payload?.length) return null;
  const row = payload.map((entry) => entry.payload).find(isChartRow);
  if (!row) return null;
  return (
    <div className="rounded-lg border border-border-subtle bg-surface px-3 py-2 text-xs shadow-elev-3">
      <div className="font-semibold text-hcl-navy">{String(label)}</div>
      {row.actual != null && (
        <div className="mt-1 text-hcl-navy">
          Observed: <span className="font-metric font-bold">{row.actual.toLocaleString()}</span>
        </div>
      )}
      {row.projected != null && row.actual == null && (
        <div className="mt-1 text-hcl-navy">
          Projected:{' '}
          <span className="font-metric font-bold">{Math.round(row.projected).toLocaleString()}</span>
          {row.bandLo != null && row.bandSpan != null && (
            <span className="text-hcl-muted">
              {' '}
              ({Math.round(row.bandLo)}–{Math.round(row.bandLo + row.bandSpan)})
            </span>
          )}
        </div>
      )}
    </div>
  );
}

export interface ForecastCardProps {
  forecast?: any;
  isLoading?: boolean;
}

export function ForecastCard({ forecast, isLoading: propsIsLoading }: ForecastCardProps = {}) {
  const hasProps = forecast !== undefined;

  const queryResult = useQuery({
    queryKey: ['dashboard-forecast'],
    queryFn: ({ signal }) => getDashboardForecast(signal),
    enabled: !hasProps,
  });

  const data = hasProps ? forecast : queryResult.data;
  const isLoading = hasProps ? !!propsIsLoading : queryResult.isLoading;

  const rows: ChartRow[] = [];
  if (data && !data.insufficient_history) {
    for (const p of data.history) rows.push({ date: shortDate(p.date), actual: p.total });
    const last = data.history[data.history.length - 1];
    if (last && data.projection.length > 0) {
      // Anchor the dashed line + band to the last observed point.
      rows[rows.length - 1] = {
        ...rows[rows.length - 1],
        projected: last.total,
        bandLo: last.total,
        bandSpan: 0,
      };
    }
    for (const p of data.projection) {
      rows.push({
        date: shortDate(p.date),
        projected: p.projected,
        bandLo: p.lo,
        bandSpan: Math.max(0, p.hi - p.lo),
      });
    }
  }

  const slope = data?.slope_per_day ?? 0;
  const improving = slope < -0.005;
  const worsening = slope > 0.005;
  const anomaly = data?.anomaly;

  return (
    <Surface variant="elevated">
      <SurfaceHeader>
        <div>
          <h3 className="text-base font-semibold text-hcl-navy">Findings forecast</h3>
          <p className="mt-0.5 text-xs text-hcl-muted">
            Observed distinct-active findings + {data?.horizon_days ?? 14}-day projection
          </p>
        </div>
        {data && !data.insufficient_history && (
          <span
            className={cn(
              'inline-flex items-center gap-1.5 rounded-full px-2.5 py-1 text-xs font-semibold',
              improving && 'bg-emerald-50 text-emerald-700 dark:bg-emerald-950/40 dark:text-emerald-300',
              worsening && 'bg-red-50 text-red-700 dark:bg-red-950/40 dark:text-red-300',
              !improving && !worsening && 'bg-surface-muted text-hcl-muted',
            )}
          >
            {improving ? (
              <TrendingDown className="h-3.5 w-3.5" aria-hidden />
            ) : worsening ? (
              <TrendingUp className="h-3.5 w-3.5" aria-hidden />
            ) : null}
            {slope > 0 ? '+' : ''}
            {slope.toFixed(2)}/day
          </span>
        )}
      </SurfaceHeader>
      <SurfaceContent>
        {isLoading ? (
          <div className="flex h-56 items-center justify-center">
            <Spinner />
          </div>
        ) : !data || data.insufficient_history ? (
          <EmptyState
            illustration="generic"
            title="Not enough history yet"
            description="The forecast unlocks after 7 days of analysis snapshots — keep scanning."
            compact
          />
        ) : (
          <>
            {anomaly?.detected && (
              <div className="mb-3 flex items-center gap-2 rounded-lg border border-amber-200 bg-amber-50/70 px-3 py-2 text-xs text-amber-800 dark:border-amber-900 dark:bg-amber-950/30 dark:text-amber-200">
                <AlertTriangle className="h-3.5 w-3.5 shrink-0" aria-hidden />
                <span>
                  Velocity anomaly: <strong className="font-metric">{anomaly.delta > 0 ? '+' : ''}{anomaly.delta}</strong>{' '}
                  findings in a day vs a {anomaly.baseline_mean >= 0 ? '+' : ''}
                  {anomaly.baseline_mean}/day baseline
                  {anomaly.zscore != null && <> (z = {anomaly.zscore})</>}
                </span>
              </div>
            )}
            <ResponsiveContainer width="100%" height={220}>
              <ComposedChart data={rows} margin={{ top: 4, right: 8, bottom: 0, left: -16 }}>
                <XAxis
                  dataKey="date"
                  tick={{ fontSize: 10 }}
                  tickLine={false}
                  axisLine={false}
                  interval="preserveStartEnd"
                  minTickGap={28}
                />
                <YAxis tick={{ fontSize: 10 }} tickLine={false} axisLine={false} allowDecimals={false} />
                {/* Confidence band: transparent base + tinted span, stacked. */}
                <Area dataKey="bandLo" stackId="band" stroke="none" fill="transparent" isAnimationActive={false} />
                <Area
                  dataKey="bandSpan"
                  stackId="band"
                  stroke="none"
                  fill="#0067B1"
                  fillOpacity={0.1}
                  isAnimationActive={false}
                />
                <Line
                  dataKey="actual"
                  stroke="#0067B1"
                  strokeWidth={2}
                  dot={false}
                  isAnimationActive={false}
                />
                <Line
                  dataKey="projected"
                  stroke="#0067B1"
                  strokeWidth={2}
                  strokeDasharray="5 4"
                  dot={false}
                  isAnimationActive={false}
                />
                <Tooltip content={ForecastTooltip} />
              </ComposedChart>
            </ResponsiveContainer>
            <dl className="mt-3 grid grid-cols-3 gap-3 border-t border-border-subtle pt-3 text-center">
              <div>
                <dt className="text-[10px] font-medium uppercase tracking-wider text-hcl-muted">Now</dt>
                <dd className="font-metric text-lg font-bold text-hcl-navy">
                  {data.current_total.toLocaleString()}
                </dd>
              </div>
              <div>
                <dt className="text-[10px] font-medium uppercase tracking-wider text-hcl-muted">
                  In {data.horizon_days}d
                </dt>
                <dd className="font-metric text-lg font-bold text-hcl-navy">
                  {data.projected_total != null ? Math.round(data.projected_total).toLocaleString() : '—'}
                </dd>
              </div>
              <div>
                <dt className="text-[10px] font-medium uppercase tracking-wider text-hcl-muted">
                  {data.days_to_zero != null ? 'Zero in' : 'Fit R²'}
                </dt>
                <dd className="font-metric text-lg font-bold text-hcl-navy">
                  {data.days_to_zero != null ? `${data.days_to_zero}d` : data.r_squared.toFixed(2)}
                </dd>
              </div>
            </dl>
          </>
        )}
      </SurfaceContent>
    </Surface>
  );
}

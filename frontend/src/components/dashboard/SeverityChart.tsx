'use client';

import { useRouter } from 'next/navigation';
import { useState } from 'react';
import { PieChart, Pie, Cell, Tooltip, ResponsiveContainer, type TooltipContentProps } from 'recharts';
import { Surface, SurfaceContent, SurfaceHeader } from '@/components/ui/Surface';
import { Spinner } from '@/components/ui/Spinner';
import { EmptyState } from '@/components/ui/EmptyState';
import { useTheme } from '@/components/theme/ThemeProvider';
import { cn } from '@/lib/utils';
import type { SeverityKey } from '@/lib/severityParam';
import type { SeverityData } from '@/types';

interface SeverityChartProps {
  data: SeverityData | undefined;
  isLoading: boolean;
  /** Card heading. Defaults to "Vulnerability severity". */
  title?: string;
  /** When provided, slices drill via this handler — reuses the hero severity
   *  drill-down (→ useFindingsFilterFromUrl). Without it, the built-in
   *  runs-list navigation is used. */
  onSliceClick?: (key: SeverityKey) => void;
  /** Scored severities that resolve to a run to drill into. A slice is
   *  clickable only when in this set (with onSliceClick); others — including
   *  the unscored bucket — render static (no dead buttons). */
  interactiveSeverities?: ReadonlySet<SeverityKey>;
}

interface ChartDatum {
  name: string;
  key: keyof SeverityData;
  value: number;
  color: string;
}

const SEVERITY_ORDER: Array<Pick<ChartDatum, 'name' | 'key' | 'color'>> = [
  { name: 'Critical', key: 'critical', color: '#C0392B' },
  { name: 'High', key: 'high', color: '#D4680A' },
  { name: 'Medium', key: 'medium', color: '#B8860B' },
  { name: 'Low', key: 'low', color: '#0067B1' },
  { name: 'Unknown', key: 'unknown', color: '#5B7083' },
];

function isChartDatum(value: unknown): value is ChartDatum {
  if (!value || typeof value !== 'object') return false;
  const candidate = value as Record<string, unknown>;
  return (
    typeof candidate.name === 'string'
    && typeof candidate.value === 'number'
    && typeof candidate.color === 'string'
  );
}

function CustomTooltip({ active, payload }: TooltipContentProps) {
  if (!active || !payload?.length) return null;
  const datum = payload.map((entry) => entry.payload).find(isChartDatum);
  if (!datum) return null;
  return (
    <div className="rounded-lg border border-border-subtle bg-surface px-3 py-2 text-xs shadow-elev-3">
      <div className="flex items-center gap-2">
        <span className="h-2.5 w-2.5 rounded-full" style={{ backgroundColor: datum.color }} aria-hidden />
        <span className="font-semibold text-hcl-navy">{datum.name}</span>
      </div>
      <div className="mt-1 font-metric text-base font-bold text-hcl-navy">
        {datum.value.toLocaleString()}
      </div>
      <div className="text-[10px] uppercase tracking-wider text-hcl-muted">
        Click slice to drill down
      </div>
    </div>
  );
}

export function SeverityChart({
  data,
  isLoading,
  title = 'Vulnerability severity',
  onSliceClick,
  interactiveSeverities,
}: SeverityChartProps) {
  const router = useRouter();
  const { resolvedTheme: _theme } = useTheme();
  const [hovered, setHovered] = useState<string | null>(null);

  const chartData: ChartDatum[] = data
    ? SEVERITY_ORDER.map((s) => ({ ...s, value: data[s.key] })).filter((d) => d.value > 0)
    : [];
  const total = chartData.reduce((s, d) => s + d.value, 0);

  // With onSliceClick (hero drill pattern) only scored severities that resolve
  // to a run are clickable — the unscored bucket is shown for the total but has
  // no severity run to land on. Without onSliceClick, the runs-list fallback
  // handles every rendered slice.
  const isDrillable = (d: ChartDatum): boolean =>
    onSliceClick
      ? d.key !== 'unknown' && (interactiveSeverities?.has(d.key) ?? false)
      : true;

  const handleSliceClick = (d: ChartDatum) => {
    if (!isDrillable(d)) return;
    if (onSliceClick) {
      if (d.key !== 'unknown') onSliceClick(d.key);
      return;
    }
    // Fallback: runs view filtered to runs that produced findings.
    // ADR-0001: status=FINDINGS replaces the old overloaded FAIL.
    router.push(`/analysis?tab=runs&status=FINDINGS&severity=${d.key.toUpperCase()}`);
  };

  return (
    <Surface variant="elevated">
      <SurfaceHeader>
        <div>
          <h3 className="text-base font-semibold text-hcl-navy">{title}</h3>
          {total > 0 && (
            <p className="mt-0.5 text-xs text-hcl-muted">
              <span className="font-metric font-semibold text-hcl-navy">{total.toLocaleString()}</span> total findings · click to filter
            </p>
          )}
        </div>
      </SurfaceHeader>
      <SurfaceContent>
        {isLoading ? (
          <div className="flex h-56 items-center justify-center">
            <Spinner />
          </div>
        ) : total === 0 ? (
          <EmptyState
            illustration="all-clear"
            title="No vulnerabilities"
            description="Run an analysis to see severity distribution."
            compact
          />
        ) : (
          <div className="grid grid-cols-1 gap-4 lg:grid-cols-[1fr_auto] lg:items-center">
            <div className="relative">
              <ResponsiveContainer width="100%" height={220}>
                <PieChart>
                  <Pie
                    data={chartData}
                    cx="50%"
                    cy="50%"
                    innerRadius={62}
                    outerRadius={92}
                    paddingAngle={3}
                    dataKey="value"
                    nameKey="name"
                    onClick={(_, index) => {
                      const d = chartData[index];
                      if (d) handleSliceClick(d);
                    }}
                    onMouseEnter={(_, index) => setHovered(chartData[index]?.name ?? null)}
                    onMouseLeave={() => setHovered(null)}
                    isAnimationActive
                    animationDuration={600}
                    animationEasing="ease-out"
                  >
                    {chartData.map((entry) => (
                      <Cell
                        key={entry.name}
                        fill={entry.color}
                        stroke={hovered === entry.name ? entry.color : 'transparent'}
                        strokeWidth={hovered === entry.name ? 2 : 0}
                        style={{
                          transition: 'opacity 200ms',
                          opacity: hovered && hovered !== entry.name ? 0.55 : 1,
                          cursor: isDrillable(entry) ? 'pointer' : 'default',
                        }}
                      />
                    ))}
                  </Pie>
                  <Tooltip content={CustomTooltip} />
                </PieChart>
              </ResponsiveContainer>
              {/* Center label inside donut */}
              <div className="pointer-events-none absolute inset-0 flex flex-col items-center justify-center text-center">
                <span className="font-metric text-2xl font-bold leading-none text-hcl-navy">
                  {total.toLocaleString()}
                </span>
                <span className="mt-0.5 text-[10px] font-medium uppercase tracking-wider text-hcl-muted">
                  Findings
                </span>
              </div>
            </div>
            <ul className="grid gap-1.5 self-center lg:min-w-[180px]">
              {chartData.map((d) => {
                const pct = total > 0 ? (d.value / total) * 100 : 0;
                const drillable = isDrillable(d);
                const rowClass =
                  'flex w-full items-center justify-between gap-3 rounded-lg px-2 py-1.5';
                const body = (
                  <>
                    <span className="flex min-w-0 items-center gap-2">
                      <span
                        className="h-2.5 w-2.5 shrink-0 rounded-full"
                        style={{ backgroundColor: d.color }}
                        aria-hidden
                      />
                      <span className="text-xs font-medium text-hcl-navy">{d.name}</span>
                    </span>
                    <span className="flex items-center gap-2">
                      <span className="text-[10px] tabular-nums text-hcl-muted">{pct.toFixed(0)}%</span>
                      <span className="font-metric text-xs font-semibold text-hcl-navy">
                        {d.value.toLocaleString()}
                      </span>
                    </span>
                  </>
                );
                return (
                  <li key={d.name}>
                    {drillable ? (
                      <button
                        type="button"
                        onClick={() => handleSliceClick(d)}
                        onMouseEnter={() => setHovered(d.name)}
                        onMouseLeave={() => setHovered(null)}
                        aria-label={`View ${d.name} findings (${d.value.toLocaleString()})`}
                        className={cn(
                          rowClass,
                          'border border-transparent text-left transition-all duration-base ease-spring',
                          'hover:border-border-subtle hover:bg-surface-muted hover:-translate-y-px',
                          'focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-hcl-blue/40',
                        )}
                      >
                        {body}
                      </button>
                    ) : (
                      <div
                        className={rowClass}
                        onMouseEnter={() => setHovered(d.name)}
                        onMouseLeave={() => setHovered(null)}
                      >
                        {body}
                      </div>
                    )}
                  </li>
                );
              })}
            </ul>
          </div>
        )}
      </SurfaceContent>
    </Surface>
  );
}

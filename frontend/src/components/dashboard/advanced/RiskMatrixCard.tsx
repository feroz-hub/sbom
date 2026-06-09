'use client';

import { useQuery } from '@tanstack/react-query';
import {
  CartesianGrid,
  Cell,
  ReferenceLine,
  ResponsiveContainer,
  Scatter,
  ScatterChart,
  Tooltip,
  XAxis,
  YAxis,
  ZAxis,
  type TooltipProps,
} from 'recharts';
import { Surface, SurfaceContent, SurfaceHeader } from '@/components/ui/Surface';
import { Spinner } from '@/components/ui/Spinner';
import { EmptyState } from '@/components/ui/EmptyState';
import { getDashboardRiskMatrix } from '@/lib/api';
import type { RiskMatrixPoint } from '@/types';

/**
 * Risk matrix — every distinct finding plotted impact × exploitability.
 *
 * Y = CVSS (how bad if it happens), X = EPSS (how likely it happens,
 * 30-day). The top-right quadrant (CVSS ≥ 7, EPSS ≥ 0.5) is the
 * patch-first zone; KEV findings render as larger red-ringed points
 * regardless of quadrant because observed exploitation outranks any
 * model. Severity colours match the rest of the dashboard.
 */

const SEVERITY_COLOR: Record<string, string> = {
  critical: '#C0392B',
  high: '#D4680A',
  medium: '#B8860B',
  low: '#0067B1',
  unknown: '#5B7083',
};

const QUADRANT_X = 0.5;
const QUADRANT_Y = 7;

function MatrixTooltip({ active, payload }: TooltipProps<number, string>) {
  if (!active || !payload?.length) return null;
  const p = payload[0]?.payload as RiskMatrixPoint | undefined;
  if (!p) return null;
  return (
    <div className="max-w-[240px] rounded-lg border border-border-subtle bg-surface px-3 py-2 text-xs shadow-elev-3">
      <div className="flex items-center gap-2">
        <span
          className="h-2.5 w-2.5 shrink-0 rounded-full"
          style={{ backgroundColor: SEVERITY_COLOR[p.severity] ?? SEVERITY_COLOR.unknown }}
          aria-hidden
        />
        <span className="truncate font-metric font-semibold text-hcl-navy">{p.vuln_id}</span>
        {p.kev && (
          <span className="rounded bg-red-50 px-1.5 py-0.5 text-[10px] font-semibold text-red-700 dark:bg-red-950/40 dark:text-red-300">
            KEV
          </span>
        )}
      </div>
      <div className="mt-1 truncate text-hcl-muted">{p.component}</div>
      <div className="mt-1 flex gap-3 font-metric tabular-nums text-hcl-navy">
        <span>CVSS {p.cvss.toFixed(1)}</span>
        <span>EPSS {(p.epss * 100).toFixed(1)}%</span>
      </div>
      <div className="mt-0.5 text-[10px] text-hcl-muted">
        {p.has_fix ? 'Fix available' : 'No fix recorded'}
      </div>
    </div>
  );
}

export function RiskMatrixCard() {
  const query = useQuery({
    queryKey: ['dashboard-risk-matrix'],
    queryFn: ({ signal }) => getDashboardRiskMatrix(300, signal),
  });
  const data = query.data;
  const points = data?.points ?? [];
  const kevPoints = points.filter((p) => p.kev);
  const otherPoints = points.filter((p) => !p.kev);
  const patchFirst = points.filter((p) => p.cvss >= QUADRANT_Y && p.epss >= QUADRANT_X).length;

  return (
    <Surface variant="elevated">
      <SurfaceHeader>
        <div>
          <h3 className="text-base font-semibold text-hcl-navy">Risk matrix</h3>
          <p className="mt-0.5 text-xs text-hcl-muted">
            Impact (CVSS) × exploitability (EPSS) — top-right is the patch-first zone
          </p>
        </div>
        {points.length > 0 && (
          <span className="rounded-full bg-surface-muted px-2.5 py-1 text-xs font-semibold text-hcl-navy">
            <span className="font-metric">{patchFirst}</span> in patch-first zone
          </span>
        )}
      </SurfaceHeader>
      <SurfaceContent>
        {query.isLoading ? (
          <div className="flex h-64 items-center justify-center">
            <Spinner />
          </div>
        ) : points.length === 0 ? (
          <EmptyState
            illustration="all-clear"
            title="Nothing to plot"
            description="No CVSS-scored findings in the latest runs."
            compact
          />
        ) : (
          <>
            <ResponsiveContainer width="100%" height={280}>
              <ScatterChart margin={{ top: 8, right: 12, bottom: 4, left: -16 }}>
                <CartesianGrid strokeDasharray="3 3" className="stroke-border-subtle" strokeOpacity={0.5} />
                <XAxis
                  type="number"
                  dataKey="epss"
                  domain={[0, 1]}
                  tickFormatter={(v: number) => `${Math.round(v * 100)}%`}
                  tick={{ fontSize: 10 }}
                  tickLine={false}
                  axisLine={false}
                  name="EPSS"
                />
                <YAxis
                  type="number"
                  dataKey="cvss"
                  domain={[0, 10]}
                  tick={{ fontSize: 10 }}
                  tickLine={false}
                  axisLine={false}
                  name="CVSS"
                />
                <ZAxis range={[28, 28]} />
                <ReferenceLine x={QUADRANT_X} stroke="#5B7083" strokeDasharray="4 4" strokeOpacity={0.6} />
                <ReferenceLine
                  y={QUADRANT_Y}
                  stroke="#5B7083"
                  strokeDasharray="4 4"
                  strokeOpacity={0.6}
                  label={{
                    value: 'patch first →',
                    position: 'insideTopRight',
                    fontSize: 10,
                    fill: '#C0392B',
                  }}
                />
                <Tooltip content={<MatrixTooltip />} cursor={{ strokeDasharray: '3 3' }} />
                <Scatter data={otherPoints} isAnimationActive={false} fillOpacity={0.75}>
                  {otherPoints.map((p, i) => (
                    <Cell
                      key={`${p.vuln_id}-${i}`}
                      fill={SEVERITY_COLOR[p.severity] ?? SEVERITY_COLOR.unknown}
                    />
                  ))}
                </Scatter>
                <Scatter
                  data={kevPoints}
                  isAnimationActive={false}
                  shape="diamond"
                  fill="#C0392B"
                  stroke="#7B241C"
                  strokeWidth={1.5}
                />
              </ScatterChart>
            </ResponsiveContainer>
            <div className="mt-2 flex flex-wrap items-center gap-x-4 gap-y-1 border-t border-border-subtle pt-2 text-[10px] text-hcl-muted">
              {Object.entries(SEVERITY_COLOR).map(([sev, color]) => (
                <span key={sev} className="inline-flex items-center gap-1.5 capitalize">
                  <span className="h-2 w-2 rounded-full" style={{ backgroundColor: color }} aria-hidden />
                  {sev}
                </span>
              ))}
              <span className="inline-flex items-center gap-1.5">
                <span className="inline-block h-2 w-2 rotate-45 bg-[#C0392B]" aria-hidden />
                KEV (observed exploitation)
              </span>
              {data && data.total_distinct > points.length && (
                <span className="ml-auto">
                  showing {points.length} of {data.total_distinct.toLocaleString()} (KEV/EPSS-first)
                  {data.unplotted_no_cvss > 0 && ` · ${data.unplotted_no_cvss} lack CVSS`}
                </span>
              )}
            </div>
          </>
        )}
      </SurfaceContent>
    </Surface>
  );
}

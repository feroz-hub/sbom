'use client';

import { useMemo } from 'react';
import { useQuery } from '@tanstack/react-query';
import { getRuns } from '@/lib/api';
import { cn } from '@/lib/utils';

interface Props {
  /** SBOM whose run history feeds the sparkline. Null = render nothing. */
  sbomId: number | null;
  /** Run id of the rightmost point — visually highlighted. */
  currentRunId?: number;
  /** Title attribute / sr-only description suffix (e.g. SBOM name). */
  contextLabel?: string;
  /** Optional CSS class on the wrapper. */
  className?: string;
  /** Width in px. Default 240. */
  width?: number;
  /** Height in px. Default 24. */
  height?: number;
}

const COMPARABLE_STATUSES = new Set(['OK', 'FINDINGS', 'PARTIAL']);

/**
 * Total-findings sparkline over the last 30 runs of a given SBOM.
 *
 * Hide rules (returns null):
 *   - sbomId is null (e.g. cross-SBOM compare)
 *   - <2 historical runs available
 *   - network failure on the secondary fetch
 *
 * Data source: existing GET /api/runs?sbom_id=X&page_size=30. No new
 * backend. The query is lazy — only fires when the component renders, so
 * the surrounding hero doesn't pay any LCP cost.
 *
 * Rendering: raw SVG path. `stroke-dasharray` draw-on animation skipped
 * on `prefers-reduced-motion`.
 */
export function Sparkline({
  sbomId,
  currentRunId,
  contextLabel,
  className,
  width = 240,
  height = 24,
}: Props) {
  const { data, isError } = useQuery({
    queryKey: ['compare', 'sparkline', sbomId],
    queryFn: ({ signal }) =>
      getRuns({ sbom_id: sbomId as number, page_size: 30 }, signal),
    enabled: sbomId != null,
    staleTime: 5 * 60 * 1000,
  });

  const series = useMemo(() => {
    if (!data) return [];
    const sortable = data.filter(
      (r) => r.run_status != null && COMPARABLE_STATUSES.has(r.run_status),
    );
    sortable.sort((a, b) => a.id - b.id);
    return sortable.map((r) => ({
      id: r.id,
      total: typeof r.total_findings === 'number' ? r.total_findings : 0,
    }));
  }, [data]);

  if (sbomId == null || isError) return null;
  if (series.length < 2) return null;

  const path = buildSvgPath(series.map((p) => p.total), width, height);
  const last = series[series.length - 1];
  const trend = describeTrend(series.map((p) => p.total));
  const sbomFragment = contextLabel ? ` of ${contextLabel}` : '';
  const titleText = `Total findings, last ${series.length} runs${sbomFragment}: trending ${trend}, current value ${last.total}.`;

  return (
    <div
      className={cn(
        'inline-flex items-baseline gap-3 text-[11px] text-hcl-muted',
        className,
      )}
    >
      <span className="font-semibold uppercase tracking-wider">
        Total findings, last {series.length} runs
      </span>
      <svg
        role="img"
        width={width}
        height={height}
        viewBox={`0 0 ${width} ${height}`}
        preserveAspectRatio="none"
        aria-label={titleText}
        className="overflow-visible"
      >
        <title>{titleText}</title>
        <path
          d={path}
          fill="none"
          strokeWidth={1.5}
          strokeLinecap="round"
          strokeLinejoin="round"
          className="stroke-hcl-blue/80 dark:stroke-hcl-blue motion-reduce:[animation:none]"
          style={{
            // Draw-on animation: dasharray of full length, dashoffset
            // starting at full length, animating to 0.
            strokeDasharray: 1000,
            strokeDashoffset: 0,
            animation: 'compare-sparkline-draw 600ms var(--ease-out) both',
          }}
        />
        {/* Current-run marker — rightmost data point */}
        <circle
          cx={width}
          cy={pointY(last.total, series.map((p) => p.total), height)}
          r={3}
          className="fill-hcl-blue"
        />
      </svg>
      <span className="font-mono tabular-nums text-hcl-navy">
        {last.total.toLocaleString()}
        {currentRunId != null && last.id === currentRunId && (
          <span className="ml-1 text-hcl-muted/80">(current)</span>
        )}
      </span>
    </div>
  );
}

// ─── Pure helpers (exported for direct unit testing) ────────────────────────

export function buildSvgPath(values: number[], width: number, height: number): string {
  if (values.length === 0) return '';
  const max = Math.max(...values, 1);
  const min = Math.min(...values, 0);
  const range = max - min || 1;
  const stepX = values.length > 1 ? width / (values.length - 1) : 0;
  return values
    .map((v, i) => {
      const x = i * stepX;
      // Invert Y: SVG 0 is at the top. Add 2px padding so points don't kiss the edges.
      const y = height - 2 - ((v - min) / range) * (height - 4);
      return `${i === 0 ? 'M' : 'L'} ${x.toFixed(1)} ${y.toFixed(1)}`;
    })
    .join(' ');
}

export function pointY(v: number, values: number[], height: number): number {
  const max = Math.max(...values, 1);
  const min = Math.min(...values, 0);
  const range = max - min || 1;
  return height - 2 - ((v - min) / range) * (height - 4);
}

export function describeTrend(values: number[]): 'flat' | 'up' | 'down' {
  if (values.length < 2) return 'flat';
  const first = values[0];
  const last = values[values.length - 1];
  const delta = last - first;
  const pct = Math.abs(delta) / Math.max(first, 1);
  if (pct < 0.05) return 'flat';
  return delta > 0 ? 'up' : 'down';
}

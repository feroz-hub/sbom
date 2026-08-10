import { cn } from '@/lib/utils';
import { useId, useMemo } from 'react';

interface SparklineProps {
  data: number[];
  width?: number;
  height?: number;
  /** Stroke + fill base color. Accepts any CSS color (var() or hex). */
  color?: string;
  /** Render a faint area fill under the line. */
  area?: boolean;
  /** Plot a dot at the last point. */
  showLast?: boolean;
  className?: string;
  /** Accessible description, e.g. "30-day trend, increasing". */
  ariaLabel?: string;
}

/**
 * Lightweight inline SVG sparkline — used inside KPI cards.
 *
 * Zero dependencies; renders 0 or 1 datapoint as a flat line.
 */
export function Sparkline({
  data,
  width = 120,
  height = 32,
  color = 'var(--color-hcl-blue)',
  area = true,
  showLast = true,
  className,
  ariaLabel,
}: SparklineProps) {
  const gradientId = useId();
  const { linePath, areaPath, lastX, lastY } = useMemo(() => {
    if (data.length === 0) {
      return { linePath: '', areaPath: '', lastX: 0, lastY: 0 };
    }
    const min = Math.min(...data);
    const max = Math.max(...data);
    const range = max - min || 1;
    const stepX = data.length > 1 ? width / (data.length - 1) : 0;

    const points = data.map((v, i) => {
      const x = i * stepX;
      // Pad 10% top/bottom so the line never hits the edge.
      const normalized = (v - min) / range;
      const y = height - 4 - normalized * (height - 8);
      return [x, y] as const;
    });

    const linePath = points
      .map(([x, y], i) => `${i === 0 ? 'M' : 'L'}${x.toFixed(2)},${y.toFixed(2)}`)
      .join(' ');

    const areaPath = `${linePath} L${(points[points.length - 1]?.[0] ?? 0).toFixed(2)},${height} L0,${height} Z`;
    const last = points[points.length - 1] ?? [0, 0];
    return { linePath, areaPath, lastX: last[0], lastY: last[1] };
  }, [data, width, height]);

  if (data.length === 0) {
    return (
      <svg
        width={width}
        height={height}
        viewBox={`0 0 ${width} ${height}`}
        className={cn('overflow-visible', className)}
        aria-hidden="true"
      >
        <line
          x1={0}
          y1={height / 2}
          x2={width}
          y2={height / 2}
          stroke="var(--color-border)"
          strokeWidth={1}
          strokeDasharray="2 3"
        />
      </svg>
    );
  }

  const a11y = ariaLabel
    ? ({ role: 'img', 'aria-label': ariaLabel } as const)
    : ({ 'aria-hidden': true } as const);

  return (
    <svg
      {...a11y}
      width={width}
      height={height}
      viewBox={`0 0 ${width} ${height}`}
      className={cn('overflow-visible', className)}
    >
      <defs>
        <linearGradient id={gradientId} x1="0" y1="0" x2="0" y2="1">
          <stop offset="0%" stopColor={color} stopOpacity="0.35" />
          <stop offset="100%" stopColor={color} stopOpacity="0" />
        </linearGradient>
      </defs>
      {area && <path d={areaPath} fill={`url(#${gradientId})`} />}
      <path
        d={linePath}
        fill="none"
        stroke={color}
        strokeWidth={1.6}
        strokeLinecap="round"
        strokeLinejoin="round"
      />
      {showLast && (
        <circle
          cx={lastX}
          cy={lastY}
          r={2.4}
          fill={color}
          stroke="var(--color-surface)"
          strokeWidth={1.5}
        />
      )}
    </svg>
  );
}

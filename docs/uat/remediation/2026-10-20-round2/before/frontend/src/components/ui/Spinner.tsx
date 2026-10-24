import { cn } from '@/lib/utils';

interface SpinnerProps {
  size?: 'sm' | 'md' | 'lg';
  className?: string;
  label?: string;
}

const sizeClasses: Record<string, string> = {
  sm: 'h-4 w-4',
  md: 'h-6 w-6',
  lg: 'h-10 w-10',
};

export function Spinner({ size = 'md', className, label }: SpinnerProps) {
  const a11yProps = label
    ? ({ role: 'status', 'aria-label': label } as const)
    : ({ 'aria-hidden': true } as const);
  return (
    <svg
      {...a11yProps}
      className={cn(
        'animate-spin motion-reduce:animate-none text-primary',
        sizeClasses[size],
        className,
      )}
      fill="none"
      viewBox="0 0 24 24"
    >
      <circle className="opacity-25" cx="12" cy="12" r="10" stroke="currentColor" strokeWidth="4" />
      <path className="opacity-75" fill="currentColor" d="M4 12a8 8 0 018-8v8H4z" />
    </svg>
  );
}

export function PageSpinner({ label = 'Loading' }: { label?: string }) {
  return (
    <div
      role="status"
      aria-live="polite"
      className="flex h-64 flex-col items-center justify-center gap-3"
    >
      <Spinner size="lg" />
      <span className="sr-only">{label}</span>
    </div>
  );
}

interface SkeletonProps {
  className?: string;
}

/** Single block — use as a building block for custom skeleton compositions. */
export function Skeleton({ className }: SkeletonProps) {
  return <div aria-hidden="true" className={cn('rounded shimmer', className)} />;
}

export function SkeletonRow({ cols }: { cols: number }) {
  return (
    <tr aria-hidden="true">
      {Array.from({ length: cols }).map((_, i) => (
        <td key={i} className="px-4 py-3">
          <div
            className="h-4 rounded shimmer"
            style={{ width: `${60 + ((i * 13) % 40)}%` }}
          />
        </td>
      ))}
    </tr>
  );
}

export function SkeletonCard({ className }: SkeletonProps = {}) {
  return (
    <div
      aria-hidden="true"
      className={cn(
        'space-y-3 rounded-xl border border-border bg-surface p-6 shadow-card',
        className,
      )}
    >
      <div className="h-4 w-1/3 rounded shimmer" />
      <div className="h-8 w-1/2 rounded shimmer" />
      <div className="h-3 w-2/3 rounded shimmer" />
    </div>
  );
}

interface SkeletonTextProps {
  lines?: number;
  className?: string;
}

/** Multi-line text placeholder — last line is shorter for natural feel. */
export function SkeletonText({ lines = 3, className }: SkeletonTextProps) {
  return (
    <div aria-hidden="true" className={cn('space-y-2', className)}>
      {Array.from({ length: lines }).map((_, i) => {
        const isLast = i === lines - 1;
        const width = isLast ? '70%' : `${85 + ((i * 7) % 15)}%`;
        return (
          <div
            key={i}
            className="h-3 rounded shimmer"
            style={{ width }}
          />
        );
      })}
    </div>
  );
}

interface SkeletonChartProps {
  height?: number;
  variant?: 'line' | 'bar' | 'donut';
  className?: string;
}

/** Chart placeholder matching Recharts proportions. */
export function SkeletonChart({ height = 240, variant = 'line', className }: SkeletonChartProps) {
  if (variant === 'donut') {
    return (
      <div
        aria-hidden="true"
        className={cn('flex items-center justify-center', className)}
        style={{ height }}
      >
        <div
          className="rounded-full shimmer"
          style={{
            width: Math.min(height, 200),
            height: Math.min(height, 200),
            mask: 'radial-gradient(circle, transparent 40%, black 41%)',
            WebkitMask: 'radial-gradient(circle, transparent 40%, black 41%)',
          }}
        />
      </div>
    );
  }
  if (variant === 'bar') {
    return (
      <div
        aria-hidden="true"
        className={cn('flex items-end gap-2', className)}
        style={{ height }}
      >
        {[60, 80, 45, 95, 70, 85, 55, 75].map((pct, i) => (
          <div
            key={i}
            className="flex-1 rounded-t shimmer"
            style={{ height: `${pct}%` }}
          />
        ))}
      </div>
    );
  }
  return (
    <div
      aria-hidden="true"
      className={cn('rounded-lg shimmer', className)}
      style={{ height }}
    />
  );
}

interface SkeletonTableProps {
  rows?: number;
  cols?: number;
  showHeader?: boolean;
  className?: string;
}

/** Standalone table-shaped skeleton (for whole-page loading, not inside a real <table>). */
export function SkeletonTable({ rows = 5, cols = 6, showHeader = true, className }: SkeletonTableProps) {
  return (
    <div
      aria-hidden="true"
      className={cn('overflow-hidden rounded-xl border border-border bg-surface', className)}
    >
      {showHeader && (
        <div className="flex gap-4 border-b border-border bg-surface-muted px-4 py-3">
          {Array.from({ length: cols }).map((_, i) => (
            <div key={i} className="h-3 flex-1 rounded shimmer" />
          ))}
        </div>
      )}
      <div className="divide-y divide-border-subtle">
        {Array.from({ length: rows }).map((_, r) => (
          <div key={r} className="flex gap-4 px-4 py-3">
            {Array.from({ length: cols }).map((_, c) => (
              <div
                key={c}
                className="h-4 flex-1 rounded shimmer"
                style={{ maxWidth: `${60 + ((r * 13 + c * 7) % 40)}%` }}
              />
            ))}
          </div>
        ))}
      </div>
    </div>
  );
}

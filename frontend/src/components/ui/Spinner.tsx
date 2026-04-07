import { cn } from '@/lib/utils';

interface SpinnerProps {
  size?: 'sm' | 'md' | 'lg';
  className?: string;
  /**
   * Accessible label. When omitted, the spinner is treated as decorative
   * (aria-hidden) — use this when the surrounding context already communicates
   * the loading state (e.g. a button with aria-busy).
   */
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
        'animate-spin motion-reduce:animate-none text-hcl-blue',
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
      className="flex flex-col items-center justify-center h-64 gap-3"
    >
      <Spinner size="lg" />
      <span className="sr-only">{label}</span>
    </div>
  );
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

export function SkeletonCard() {
  return (
    <div
      aria-hidden="true"
      className="bg-white rounded-xl border border-hcl-border shadow-card p-6 space-y-3"
    >
      <div className="h-4 rounded shimmer w-1/3" />
      <div className="h-8 rounded shimmer w-1/2" />
      <div className="h-3 rounded shimmer w-2/3" />
    </div>
  );
}

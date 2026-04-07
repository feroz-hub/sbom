import { cn } from '@/lib/utils';
import type { ReactNode } from 'react';

interface BadgeProps {
  children: ReactNode;
  variant?: 'default' | 'success' | 'error' | 'warning' | 'info' | 'gray';
  className?: string;
}

const variantClasses: Record<string, string> = {
  default: 'bg-hcl-light text-hcl-navy border-hcl-border',
  success: 'bg-green-50 text-green-700 border-green-200',
  error: 'bg-red-50 text-red-700 border-red-200',
  warning: 'bg-amber-50 text-amber-700 border-amber-200',
  info: 'bg-hcl-light text-hcl-blue border-hcl-border',
  gray: 'bg-slate-100 text-slate-600 border-slate-200',
};

const BASE =
  'inline-flex items-center px-2.5 py-0.5 rounded-full text-xs font-medium border whitespace-nowrap';

export function Badge({ children, variant = 'default', className }: BadgeProps) {
  return <span className={cn(BASE, variantClasses[variant], className)}>{children}</span>;
}

// ── Severity styling map ─────────────────────────────────────────────────────
// Two cues per level: colour + a leading dot. Colour-only would fail WCAG 1.4.1
// (Use of Color) for users with low-contrast vision or colour blindness.
const severityMap: Record<string, { cls: string; dot: string; label: string }> = {
  CRITICAL: {
    cls: 'bg-red-50 text-red-800 border-red-300 font-semibold',
    dot: 'bg-red-600',
    label: 'Critical severity',
  },
  HIGH: {
    cls: 'bg-orange-50 text-orange-800 border-orange-300 font-semibold',
    dot: 'bg-orange-500',
    label: 'High severity',
  },
  MEDIUM: {
    cls: 'bg-amber-50 text-amber-800 border-amber-300',
    dot: 'bg-amber-500',
    label: 'Medium severity',
  },
  LOW: {
    cls: 'bg-hcl-light text-hcl-blue border-hcl-border',
    dot: 'bg-hcl-blue',
    label: 'Low severity',
  },
  UNKNOWN: {
    cls: 'bg-slate-100 text-slate-600 border-slate-200',
    dot: 'bg-slate-400',
    label: 'Unknown severity',
  },
};

export function SeverityBadge({ severity }: { severity: string }) {
  const key = severity?.toUpperCase() ?? 'UNKNOWN';
  const entry = severityMap[key] ?? severityMap.UNKNOWN;
  return (
    <span className={cn(BASE, 'gap-1.5', entry.cls)} aria-label={entry.label}>
      <span className={cn('h-1.5 w-1.5 rounded-full', entry.dot)} aria-hidden="true" />
      {severity}
    </span>
  );
}

// ── Status styling map ───────────────────────────────────────────────────────
const statusMap: Record<string, { cls: string; dot: string; label: string }> = {
  PASS:    { cls: 'bg-green-50 text-green-800 border-green-200',   dot: 'bg-green-500', label: 'Passed' },
  FAIL:    { cls: 'bg-red-50 text-red-800 border-red-200',         dot: 'bg-red-500',   label: 'Failed' },
  PARTIAL: { cls: 'bg-amber-50 text-amber-800 border-amber-200',   dot: 'bg-amber-500', label: 'Partial' },
  ERROR:   { cls: 'bg-red-50 text-red-800 border-red-200',         dot: 'bg-red-500',   label: 'Error' },
  RUNNING: { cls: 'bg-hcl-light text-hcl-blue border-hcl-border',  dot: 'bg-hcl-blue animate-pulse motion-reduce:animate-none', label: 'Running' },
  PENDING: { cls: 'bg-slate-100 text-slate-600 border-slate-200',  dot: 'bg-slate-400', label: 'Pending' },
};

export function StatusBadge({ status }: { status: string }) {
  const key = status?.toUpperCase() ?? 'PENDING';
  const entry = statusMap[key] ?? statusMap.PENDING;
  return (
    <span className={cn(BASE, 'gap-1.5', entry.cls)} aria-label={entry.label}>
      <span className={cn('h-1.5 w-1.5 rounded-full', entry.dot)} aria-hidden="true" />
      {status}
    </span>
  );
}

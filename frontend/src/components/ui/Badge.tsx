import { runStatusDescription, runStatusShortLabel } from '@/lib/analysisRunStatusLabels';
import { cn } from '@/lib/utils';
import type { ReactNode } from 'react';

interface BadgeProps {
  children: ReactNode;
  variant?: 'default' | 'success' | 'error' | 'warning' | 'info' | 'gray';
  className?: string;
}

const variantClasses: Record<string, string> = {
  default: 'bg-hcl-light text-hcl-navy border-hcl-border',
  success:
    'bg-green-50 text-green-800 border-green-200 dark:bg-emerald-950/50 dark:text-emerald-200 dark:border-emerald-800',
  error: 'bg-red-50 text-red-800 border-red-200 dark:bg-red-950/50 dark:text-red-200 dark:border-red-800',
  warning:
    'bg-amber-50 text-amber-800 border-amber-200 dark:bg-amber-950/50 dark:text-amber-200 dark:border-amber-800',
  info: 'bg-hcl-light text-hcl-blue border-hcl-border',
  gray: 'bg-slate-100 text-slate-700 border-slate-200 dark:bg-slate-800 dark:text-slate-200 dark:border-slate-600',
};

const BASE =
  'inline-flex items-center px-2.5 py-0.5 rounded-full text-xs font-medium border whitespace-nowrap';

export function Badge({ children, variant = 'default', className }: BadgeProps) {
  return <span className={cn(BASE, variantClasses[variant], className)}>{children}</span>;
}

const severityMap: Record<string, { cls: string; dot: string; label: string }> = {
  CRITICAL: {
    cls: 'bg-red-50 text-red-900 border-red-300 dark:bg-red-950/60 dark:text-red-100 dark:border-red-700 font-semibold',
    dot: 'bg-red-600 dark:bg-red-400',
    label: 'Critical severity',
  },
  HIGH: {
    cls: 'bg-orange-50 text-orange-900 border-orange-300 dark:bg-orange-950/50 dark:text-orange-100 dark:border-orange-700 font-semibold',
    dot: 'bg-orange-500 dark:bg-orange-400',
    label: 'High severity',
  },
  MEDIUM: {
    cls: 'bg-amber-50 text-amber-900 border-amber-300 dark:bg-amber-950/50 dark:text-amber-100 dark:border-amber-700',
    dot: 'bg-amber-500 dark:bg-amber-400',
    label: 'Medium severity',
  },
  LOW: {
    cls: 'bg-hcl-light text-hcl-blue border-hcl-border',
    dot: 'bg-hcl-blue',
    label: 'Low severity',
  },
  UNKNOWN: {
    cls: 'bg-slate-100 text-slate-700 border-slate-200 dark:bg-slate-800 dark:text-slate-200 dark:border-slate-600',
    dot: 'bg-slate-400 dark:bg-slate-500',
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

const statusMap: Record<string, { cls: string; dot: string }> = {
  PASS: {
    cls: 'bg-green-50 text-green-800 border-green-200 dark:bg-emerald-950/50 dark:text-emerald-200 dark:border-emerald-800',
    dot: 'bg-green-500',
  },
  FAIL: {
    cls: 'bg-red-50 text-red-800 border-red-200 dark:bg-red-950/50 dark:text-red-200 dark:border-red-800',
    dot: 'bg-red-500',
  },
  PARTIAL: {
    cls: 'bg-amber-50 text-amber-800 border-amber-200 dark:bg-amber-950/50 dark:text-amber-200 dark:border-amber-800',
    dot: 'bg-amber-500',
  },
  ERROR: {
    cls: 'bg-red-50 text-red-800 border-red-200 dark:bg-red-950/50 dark:text-red-200 dark:border-red-800',
    dot: 'bg-red-500',
  },
  RUNNING: {
    cls: 'bg-hcl-light text-hcl-blue border-hcl-border',
    dot: 'bg-hcl-blue animate-pulse motion-reduce:animate-none',
  },
  PENDING: {
    cls: 'bg-slate-100 text-slate-600 border-slate-200 dark:bg-slate-800 dark:text-slate-300 dark:border-slate-600',
    dot: 'bg-slate-400 dark:bg-slate-500',
  },
  NO_DATA: {
    cls: 'bg-slate-100 text-slate-700 border-slate-200 dark:bg-slate-800 dark:text-slate-300 dark:border-slate-600',
    dot: 'bg-slate-400 dark:bg-slate-500',
  },
};

export function StatusBadge({ status }: { status: string }) {
  const key = status?.toUpperCase() ?? 'PENDING';
  const entry = statusMap[key] ?? statusMap.PENDING;
  const short = runStatusShortLabel(status);
  const help = runStatusDescription(status);
  return (
    <span
      className={cn(BASE, 'max-w-full cursor-help gap-1.5', entry.cls)}
      title={help}
      aria-label={help}
    >
      <span className={cn('h-1.5 w-1.5 shrink-0 rounded-full', entry.dot)} aria-hidden="true" />
      <span className="min-w-0 truncate">{short}</span>
    </span>
  );
}

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
  gray: 'bg-slate-100 text-slate-500 border-slate-200',
};

export function Badge({ children, variant = 'default', className }: BadgeProps) {
  return (
    <span
      className={cn(
        'inline-flex items-center px-2.5 py-0.5 rounded-full text-xs font-medium border',
        variantClasses[variant],
        className
      )}
    >
      {children}
    </span>
  );
}

export function SeverityBadge({ severity }: { severity: string }) {
  const map: Record<string, string> = {
    CRITICAL: 'bg-red-50 text-red-700 border-red-200 font-semibold',
    HIGH: 'bg-orange-50 text-orange-700 border-orange-200',
    MEDIUM: 'bg-amber-50 text-amber-700 border-amber-200',
    LOW: 'bg-hcl-light text-hcl-blue border-hcl-border',
    UNKNOWN: 'bg-slate-100 text-slate-500 border-slate-200',
  };
  const cls = map[severity?.toUpperCase()] ?? map.UNKNOWN;
  return (
    <span className={cn('inline-flex items-center px-2.5 py-0.5 rounded-full text-xs font-medium border', cls)}>
      {severity}
    </span>
  );
}

export function StatusBadge({ status }: { status: string }) {
  const map: Record<string, string> = {
    PASS: 'bg-green-50 text-green-700 border-green-200',
    FAIL: 'bg-red-50 text-red-700 border-red-200',
    PARTIAL: 'bg-amber-50 text-amber-700 border-amber-200',
    ERROR: 'bg-red-50 text-red-700 border-red-200',
    RUNNING: 'bg-hcl-light text-hcl-blue border-hcl-border',
    PENDING: 'bg-slate-100 text-slate-500 border-slate-200',
  };
  const cls = map[status?.toUpperCase()] ?? map.PENDING;
  return (
    <span className={cn('inline-flex items-center px-2.5 py-0.5 rounded-full text-xs font-medium border', cls)}>
      {status}
    </span>
  );
}

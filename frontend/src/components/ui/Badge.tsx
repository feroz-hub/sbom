import { cn } from '@/lib/utils';
import type { ReactNode } from 'react';

interface BadgeProps {
  children: ReactNode;
  variant?: 'default' | 'success' | 'error' | 'warning' | 'info' | 'gray';
  className?: string;
}

const variantClasses: Record<string, string> = {
  default: 'bg-gray-100 text-gray-700 border-gray-200',
  success: 'bg-green-100 text-green-700 border-green-200',
  error: 'bg-red-100 text-red-700 border-red-200',
  warning: 'bg-yellow-100 text-yellow-700 border-yellow-200',
  info: 'bg-blue-100 text-blue-700 border-blue-200',
  gray: 'bg-gray-100 text-gray-500 border-gray-200',
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
    CRITICAL: 'bg-red-100 text-red-700 border-red-200',
    HIGH: 'bg-orange-100 text-orange-700 border-orange-200',
    MEDIUM: 'bg-yellow-100 text-yellow-700 border-yellow-200',
    LOW: 'bg-blue-100 text-blue-700 border-blue-200',
    UNKNOWN: 'bg-gray-100 text-gray-600 border-gray-200',
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
    PASS: 'bg-green-100 text-green-700 border-green-200',
    FAIL: 'bg-red-100 text-red-700 border-red-200',
    PARTIAL: 'bg-yellow-100 text-yellow-700 border-yellow-200',
    ERROR: 'bg-red-100 text-red-700 border-red-200',
    RUNNING: 'bg-blue-100 text-blue-700 border-blue-200',
    PENDING: 'bg-gray-100 text-gray-600 border-gray-200',
  };
  const cls = map[status?.toUpperCase()] ?? map.PENDING;
  return (
    <span className={cn('inline-flex items-center px-2.5 py-0.5 rounded-full text-xs font-medium border', cls)}>
      {status}
    </span>
  );
}

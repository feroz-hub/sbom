import { AlertCircle, AlertTriangle, CheckCircle, Info } from 'lucide-react';
import type { ReactNode } from 'react';
import { cn } from '@/lib/utils';

export type AlertVariant = 'error' | 'success' | 'warning' | 'info';

const variantStyles: Record<AlertVariant, string> = {
  error:
    'border-red-200 bg-red-50 text-red-800 dark:border-red-900 dark:bg-red-950/45 dark:text-red-200',
  success:
    'border-emerald-200 bg-emerald-50 text-emerald-900 dark:border-emerald-800 dark:bg-emerald-950/40 dark:text-emerald-100',
  warning:
    'border-amber-200 bg-amber-50 text-amber-900 dark:border-amber-800 dark:bg-amber-950/40 dark:text-amber-100',
  info: 'border-primary/25 bg-hcl-light text-hcl-navy dark:border-primary/40 dark:bg-surface-muted dark:text-foreground',
};

const icons: Record<AlertVariant, typeof AlertCircle> = {
  error: AlertCircle,
  success: CheckCircle,
  warning: AlertTriangle,
  info: Info,
};

interface AlertProps {
  variant: AlertVariant;
  children: ReactNode;
  className?: string;
  /** Visually emphasized heading (optional). */
  title?: string;
  /** When false, the leading icon is omitted. Default: true. */
  showIcon?: boolean;
}

export function Alert({ variant, children, className, title, showIcon = true }: AlertProps) {
  const Icon = icons[variant];
  return (
    <div
      role={variant === 'error' ? 'alert' : 'status'}
      className={cn('rounded-lg border px-4 py-3 text-sm', variantStyles[variant], className)}
    >
      <div className={cn('flex gap-3', !showIcon && 'gap-0')}>
        {showIcon && <Icon className="mt-0.5 h-5 w-5 shrink-0 opacity-90" aria-hidden />}
        <div className="min-w-0 flex-1">
          {title ? <p className="mb-1 font-semibold leading-tight">{title}</p> : null}
          <div className="leading-relaxed">{children}</div>
        </div>
      </div>
    </div>
  );
}

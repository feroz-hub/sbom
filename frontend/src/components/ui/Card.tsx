import { cn } from '@/lib/utils';
import type { ReactNode } from 'react';

type CardVariant = 'elevated' | 'inset';

interface CardProps {
  children: ReactNode;
  className?: string;
  interactive?: boolean;
  /** `inset` uses a flatter, panel-like surface for nested groups. */
  variant?: CardVariant;
}

const variantClasses: Record<CardVariant, string> = {
  elevated: 'bg-surface border border-border shadow-card',
  inset: 'bg-surface-muted border border-border-subtle shadow-none',
};

export function Card({ children, className, interactive = false, variant = 'elevated' }: CardProps) {
  return (
    <div
      className={cn(
        'rounded-xl transition-[box-shadow,transform] duration-200 motion-reduce:transition-none',
        variantClasses[variant],
        interactive &&
          'cursor-pointer hover:-translate-y-0.5 hover:shadow-card-hover motion-reduce:hover:translate-y-0',
        className,
      )}
    >
      {children}
    </div>
  );
}

export function CardHeader({ children, className }: CardProps) {
  return (
    <div className={cn('border-b border-border px-6 py-4', className)}>
      {children}
    </div>
  );
}

export function CardTitle({ children, className }: CardProps) {
  return (
    <h3 className={cn('text-base font-semibold text-hcl-navy', className)}>
      {children}
    </h3>
  );
}

export function CardContent({ children, className }: CardProps) {
  return <div className={cn('px-6 py-4', className)}>{children}</div>;
}
